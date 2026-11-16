//! The management environment's issuer as the tenant's administration source (OP-159 m.47 (d), (f),
//! TN-139): for each administrator and each domain it administers, a line of short-lived
//! `tenant_administration` Claims about its Party there. A live administrator's line is renewed
//! before it lapses; a removed or suspended one's is ended at once, and an end that never
//! arrives lapses within [`ADMINISTRATION_TTL_MS`]. A cross-domain first acceptance holds nothing
//! until its cooling ends (TN-109).

use std::future::Future;

use access_internal_api::claims::{Carrier, ClaimIngest, ClaimSubmission, ClaimVerdict};
use access_internal_api::idp::{TENANT_ADMINISTRATION, Unavailable};
use access_kernel::claim::{self, Statement};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::model::{EqValue, Id, Window};
use access_store::Pool;
use access_store::identity::{EnvironmentId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenant_admin::{self as store, AdminLine, TenantAdmin};

use super::claims::{ClaimSigner, NotSigned};
use crate::ports::Clock;

/// How long a `tenant_administration` Claim holds before it is renewed (OP-159 m.47 (f), PD):
/// one hour.
pub const ADMINISTRATION_TTL_MS: u64 = 3_600_000;

/// How early before it lapses a live line is renewed (PD).
pub const RESTATE_LEAD_MS: u64 = 15 * 60_000;

/// What one restate step did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Restated {
    /// Lines renewed.
    pub renewed: u32,
    /// Lines ended.
    pub ended: u32,
    /// Lines whose Claim the domain did not admit or the signer refused.
    pub failed: u32,
}

/// The management environment's administration courier.
pub struct Administration<S, I, C> {
    /// `access_app`.
    pub app: Pool,
    /// The Claim issuer keys.
    pub signer: S,
    /// Claim Ingest of the authority plane.
    pub ingest: I,
    /// Time.
    pub clock: C,
}

fn down(e: impl std::fmt::Display) -> Unavailable {
    Unavailable(format!("administration: {e}"))
}

/// Whether `admin` administers: added, not removed, with an account that can sign in (OP-159
/// m.47 (f), TN-49); its cooling only moves the Claim's start (TN-109).
fn live(admin: Option<&TenantAdmin>, status: Option<&str>) -> bool {
    admin.is_some_and(|a| a.ended_ms.is_none())
        && status.is_some_and(|s| {
            crate::domain::status::AccountStatus::parse(s)
                .is_some_and(crate::domain::status::AccountStatus::can_authenticate)
        })
}

impl<S: ClaimSigner, I: ClaimIngest, C: Clock> Administration<S, I, C> {
    /// Signs and submits the next Claim of `line`: `true` from `from` for an hour, or `false`
    /// at once; records it once admitted. `None` when the domain did not admit it.
    async fn state(
        &self,
        (tenant, management): (TenantId, EnvironmentId),
        line: &AdminLine,
        value: Option<u64>,
    ) -> Result<Option<[u8; 16]>, Unavailable> {
        let now = self.clock.now_ms();
        let mut t = TenantTx::begin(&self.app, tenant, management)
            .await
            .map_err(down)?;
        let issuer = access_store::issuer::environment_issuer(&mut t)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        let Some(issuer) = issuer else {
            return Ok(None);
        };
        let (holds, validity) = match value {
            Some(from) => (
                true,
                Window {
                    from: from.max(now),
                    until: from.max(now).saturating_add(ADMINISTRATION_TTL_MS),
                },
            ),
            None => (
                false,
                Window {
                    from: now,
                    until: now,
                },
            ),
        };
        let statement = Statement {
            domain: Digest(*line.domain.as_bytes()),
            issuer: Id(issuer),
            subject: Id(line.party),
            class: String::from(TENANT_ADMINISTRATION),
            value: Some(EqValue::Bool(holds)),
            issued_at: now,
            validity,
            assurance: std::collections::BTreeMap::new(),
            bound_intent: None,
            bound_instance: None,
            bound_resource: None,
            supersedes: line.claim.map(Id),
        };
        let Ok(payload) = statement.to_bytes() else {
            return Ok(None);
        };
        let sign1 = match self.signer.sign(management, payload, now).await {
            Ok(s) => s,
            Err(NotSigned::Refused(code)) => {
                tracing::warn!(
                    event = "administration.claim.refused",
                    reason = code,
                    "tenant administration claim refused by the signer"
                );
                return Ok(None);
            }
            Err(NotSigned::Down(e)) => return Err(e),
        };
        let id = claim::claim_id(&sign1);
        let verdict = self
            .ingest
            .ingest(ClaimSubmission {
                domain: statement.domain,
                carrier: Carrier::Cose,
                claim: sign1,
                body: None,
                evidence: None,
            })
            .await?;
        if !matches!(verdict, ClaimVerdict::Admitted { .. }) {
            tracing::warn!(
                event = "administration.claim.not_admitted",
                ?verdict,
                "tenant administration claim not admitted"
            );
            return Ok(None);
        }
        let mut t = TenantTx::begin(&self.app, tenant, management)
            .await
            .map_err(down)?;
        if holds {
            store::stated(
                &mut t,
                (&line.subject, &line.domain),
                &id.0,
                (now, validity.until),
            )
            .await
            .map_err(down)?;
        } else {
            store::end_line(&mut t, (&line.subject, &line.domain), now, Some(&id.0))
                .await
                .map_err(down)?;
        }
        t.commit().await.map_err(down)?;
        Ok(Some(id.0))
    }

    async fn facts(
        &self,
        (tenant, management): (TenantId, EnvironmentId),
        subject: &[u8; 16],
    ) -> Result<(Option<TenantAdmin>, Option<String>), Unavailable> {
        let mut t = TenantTx::begin(&self.app, tenant, management)
            .await
            .map_err(down)?;
        let admin = store::admin(&mut t, subject).await.map_err(down)?;
        let status = access_store::idp::environment::account(&mut t, *subject)
            .await
            .map_err(down)?
            .map(|a| a.status);
        t.commit().await.map_err(down)?;
        Ok((admin, status))
    }

    /// Opens the line of `subject` with its Party `party` in `domain` and states it, when the
    /// administrator is live (OP-159 m.47 (d)): what the console does when an administrator first
    /// reads an environment. Returns the Claim stated.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn admit(
        &self,
        (tenant, management): (TenantId, EnvironmentId),
        subject: &[u8; 16],
        (domain, party): (&DomainId, &[u8; 16]),
    ) -> Result<Option<[u8; 16]>, Unavailable> {
        let now = self.clock.now_ms();
        let (admin, status) = self.facts((tenant, management), subject).await?;
        if !live(admin.as_ref(), status.as_deref()) {
            return Ok(None);
        }
        let mut t = TenantTx::begin(&self.app, tenant, management)
            .await
            .map_err(down)?;
        store::open_line(&mut t, subject, domain, party)
            .await
            .map_err(down)?;
        let line = store::lines(&mut t, Some(subject))
            .await
            .map_err(down)?
            .into_iter()
            .find(|l| l.domain == *domain);
        t.commit().await.map_err(down)?;
        let Some(line) = line.filter(|l| l.ended_ms.is_none()) else {
            return Ok(None);
        };
        if line
            .valid_until_ms
            .is_some_and(|u| u > now.saturating_add(RESTATE_LEAD_MS))
        {
            return Ok(line.claim);
        }
        let from = admin.and_then(|a| a.cooling_until_ms).unwrap_or(now);
        self.state((tenant, management), &line, Some(from)).await
    }

    /// Ends every line of `subject` at once (OP-159 m.47 (f)): its removal or its account's
    /// suspension closes the episode in every domain it administered.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn end(
        &self,
        (tenant, management): (TenantId, EnvironmentId),
        subject: &[u8; 16],
    ) -> Result<u32, Unavailable> {
        let mut t = TenantTx::begin(&self.app, tenant, management)
            .await
            .map_err(down)?;
        let lines = store::lines(&mut t, Some(subject)).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        let mut ended = 0_u32;
        for line in lines.iter().filter(|l| l.ended_claim.is_none()) {
            if line.claim.is_some() {
                if self
                    .state((tenant, management), line, None)
                    .await?
                    .is_some()
                {
                    ended = ended.saturating_add(1);
                }
            } else {
                let mut t = TenantTx::begin(&self.app, tenant, management)
                    .await
                    .map_err(down)?;
                store::end_line(
                    &mut t,
                    (&line.subject, &line.domain),
                    self.clock.now_ms(),
                    None,
                )
                .await
                .map_err(down)?;
                t.commit().await.map_err(down)?;
            }
        }
        Ok(ended)
    }

    /// Renews the live lines that lapse within [`RESTATE_LEAD_MS`] and ends the lines whose
    /// administrator no longer administers (OP-159 m.47 (f)).
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn step(&self) -> Result<Restated, Unavailable> {
        let now = self.clock.now_ms();
        let mut out = Restated::default();
        for tenant in store::due_tenants(&self.app, now.saturating_add(RESTATE_LEAD_MS))
            .await
            .map_err(down)?
        {
            let mut t = TenantTx::begin_tenant(&self.app, tenant)
                .await
                .map_err(down)?;
            let management = store::management_environment(&mut t).await.map_err(down)?;
            t.commit().await.map_err(down)?;
            let Some((management, _)) = management else {
                continue;
            };
            let mut t = TenantTx::begin(&self.app, tenant, management)
                .await
                .map_err(down)?;
            let lines = store::lines(&mut t, None).await.map_err(down)?;
            t.commit().await.map_err(down)?;
            for line in lines {
                if line.ended_claim.is_some() {
                    continue;
                }
                let (admin, status) = self.facts((tenant, management), &line.subject).await?;
                let alive = live(admin.as_ref(), status.as_deref()) && line.ended_ms.is_none();
                let due = line
                    .valid_until_ms
                    .is_none_or(|u| u <= now.saturating_add(RESTATE_LEAD_MS));
                let stated = if alive && due {
                    let from = admin.and_then(|a| a.cooling_until_ms).unwrap_or(now);
                    let r = self.state((tenant, management), &line, Some(from)).await?;
                    out.renewed = out.renewed.saturating_add(u32::from(r.is_some()));
                    r
                } else if !alive && line.claim.is_some() {
                    let r = self.state((tenant, management), &line, None).await?;
                    out.ended = out.ended.saturating_add(u32::from(r.is_some()));
                    r
                } else {
                    continue;
                };
                if stated.is_none() {
                    out.failed = out.failed.saturating_add(1);
                }
            }
        }
        Ok(out)
    }

    /// Steps every `every` until `stop` turns true.
    pub fn run(
        &self,
        every: std::time::Duration,
        stop: &tokio::sync::watch::Receiver<bool>,
    ) -> impl Future<Output = ()> + Send + '_
    where
        S: Sync,
        I: Sync,
        C: Sync,
    {
        let mut stop = stop.clone();
        async move {
            loop {
                if let Err(error) = self.step().await {
                    tracing::warn!(error = %error.0, "administration restate step failed");
                }
                let _ = tokio::time::timeout(every, stop.changed()).await;
                if *stop.borrow() {
                    return;
                }
            }
        }
    }
}
