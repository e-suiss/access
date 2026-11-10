//! OpenID Federation over the identity plane's adapters (OP-155 m.3 (j), §10.7.1 item 8): every
//! federation document is fetched through the guarded outbound client, the realm's settings and
//! pinned trust anchors are read in its own scope.

use access_identity_oidf::chain::TrustAnchor;
use access_identity_oidf::ports::{Fetch, Unreachable};
use access_identity_oidf::statement::{MAX_STATEMENT, parse_jwks};
use access_kernel::json;
use access_store::Pool;
use access_store::identity::{RealmId, TenantTx};
use access_store::oidf::{FederationSettingsRow, TrustAnchorRow};

use crate::ports::oauth::ClientDocuments;
use crate::ports::{RealmEntry, Unavailable};

/// The realm's federation settings, read in its scope; `None` without an `access_app` pool.
///
/// # Errors
/// [`Unavailable`].
pub async fn settings(
    app: Option<&Pool>,
    realm: &RealmEntry,
) -> Result<Option<FederationSettingsRow>, Unavailable> {
    let Some(app) = app else {
        return Ok(None);
    };
    let mut t = TenantTx::begin(app, realm.tenant, realm.realm)
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

/// Federation fetches for `realm` through the guarded outbound client: each URL is vetted
/// first, the body is read up to [`MAX_STATEMENT`].
pub struct GuardedFetch<'a> {
    /// The outbound client.
    pub documents: &'a (dyn ClientDocuments + Sync),
    /// The realm fetching.
    pub realm: RealmId,
}

impl Fetch for GuardedFetch<'_> {
    async fn fetch(&self, url: &str, accept: &str) -> Result<(u16, Vec<u8>), Unreachable> {
        self.documents.vet(url).await.map_err(|_| Unreachable)?;
        let f = self
            .documents
            .fetch(self.realm, url, accept, MAX_STATEMENT)
            .await
            .map_err(|_| Unreachable)?;
        Ok((f.status, f.body))
    }
}
