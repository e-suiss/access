//! OpenID Federation over the identity plane's adapters (OP-155 m.3 (j), §10.7.1 item 8): every
//! federation document is fetched through the guarded outbound client, the environment's settings and
//! pinned trust anchors are read in its own scope.

use access_identity_oidf::chain::TrustAnchor;
use access_identity_oidf::ports::{Fetch, Unreachable};
use access_identity_oidf::statement::{MAX_STATEMENT, parse_jwks};
use access_kernel::json;
use access_store::Pool;
use access_store::identity::{EnvironmentId, TenantTx};
use access_store::oidf::{FederationSettingsRow, TrustAnchorRow};

use crate::ports::oauth::ClientDocuments;
use crate::ports::{EnvironmentEntry, Unavailable};

/// The environment's federation settings, read in its scope; `None` without an `access_app` pool.
///
/// # Errors
/// [`Unavailable`].
pub async fn settings(
    app: Option<&Pool>,
    environment: &EnvironmentEntry,
) -> Result<Option<FederationSettingsRow>, Unavailable> {
    let Some(app) = app else {
        return Ok(None);
    };
    let mut t = TenantTx::begin(app, environment.tenant, environment.environment)
        .await
        .map_err(|_| Unavailable)?;
    let s = t.federation_settings().await.map_err(|_| Unavailable)?;
    t.commit().await.map_err(|_| Unavailable)?;
    Ok(Some(s))
}

/// The live trust anchors with their pinned keys; an anchor whose stored keys no longer parse
/// is left out (fail-closed).
#[must_use]
pub fn anchors(rows: &[TrustAnchorRow]) -> Vec<TrustAnchor> {
    rows.iter()
        .filter(|a| a.live)
        .filter_map(|a| {
            let doc = json::parse(&a.jwks, MAX_STATEMENT).ok()?;
            Some(TrustAnchor {
                entity_id: a.entity_id.clone(),
                jwks: parse_jwks(&doc).ok()?,
            })
        })
        .collect()
}

/// What one refresh of a domain's tracked issuers found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Refreshed {
    /// Chains that resolved.
    pub resolved: u32,
    /// Chains that did not resolve, or whose environment is no federation leaf.
    pub unresolved: u32,
    /// Chains whose metadata policies conflict.
    pub conflict: u32,
}

/// Re-resolves the chain of every tracked issuer of `domain` at `now_ms` through the guarded
/// outbound client and records each outcome (IDI-12, OP-155 m.3 (j)): a resolved chain lets the
/// issuer's Claims in for one hour and until its `exp`; anything else cuts them. The Acceptance
/// is never read or written.
///
/// # Errors
/// [`Unavailable`].
pub async fn refresh_issuers(
    app: &Pool,
    documents: &(dyn ClientDocuments + Sync),
    domain: &access_store::scope::DomainId,
    now_ms: u64,
) -> Result<Refreshed, Unavailable> {
    use access_identity_oidf::chain::ChainError;
    use access_store::identity::TenantId;
    use access_store::oidf::{ChainState, set_issuer_state, tracked_issuers};
    let mut out = Refreshed::default();
    let rows = tracked_issuers(app, domain)
        .await
        .map_err(|_| Unavailable)?;
    for row in rows {
        let (tenant, environment) = (
            TenantId::from_bytes(row.environment.0),
            EnvironmentId::from_bytes(row.environment.1),
        );
        let mut t = TenantTx::begin(app, tenant, environment)
            .await
            .map_err(|_| Unavailable)?;
        let fed = t.federation_settings().await.map_err(|_| Unavailable)?;
        let rows = t.trust_anchors().await.map_err(|_| Unavailable)?;
        t.commit().await.map_err(|_| Unavailable)?;
        let outcome = if fed.enabled {
            let fetch = GuardedFetch {
                documents,
                environment,
            };
            access_identity_oidf::app::resolve(&fetch, &row.entity_id, anchors(&rows), now_ms).await
        } else {
            Err(ChainError::Unresolved)
        };
        let (state, anchor, exp) = match &outcome {
            Ok(c) if c.leaf.sub == row.entity_id => {
                out.resolved = out.resolved.saturating_add(1);
                (ChainState::Resolved, Some(c.anchor.as_str()), c.exp_ms)
            }
            Err(ChainError::Policy(_)) => {
                out.conflict = out.conflict.saturating_add(1);
                (ChainState::Conflict, None, 0)
            }
            _ => {
                out.unresolved = out.unresolved.saturating_add(1);
                (ChainState::Unresolved, None, 0)
            }
        };
        set_issuer_state(app, domain, &row.entity_id, state, anchor, now_ms, exp)
            .await
            .map_err(|_| Unavailable)?;
    }
    Ok(out)
}

/// Federation fetches for `environment` through the guarded outbound client: each URL is vetted
/// first, the body is read up to [`MAX_STATEMENT`].
pub struct GuardedFetch<'a> {
    /// The outbound client.
    pub documents: &'a (dyn ClientDocuments + Sync),
    /// The environment fetching.
    pub environment: EnvironmentId,
}

impl Fetch for GuardedFetch<'_> {
    async fn fetch(&self, url: &str, accept: &str) -> Result<(u16, Vec<u8>), Unreachable> {
        self.documents.vet(url).await.map_err(|_| Unreachable)?;
        let f = self
            .documents
            .fetch(self.environment, url, accept, MAX_STATEMENT)
            .await
            .map_err(|_| Unreachable)?;
        Ok((f.status, f.body))
    }
}
