//! Domain verification and its watch (TN-90, OP-153 m.3 (o)): a claimed domain is verified by
//! its published challenge (DNS TXT or HTTPS) or by an upstream identity provider's assertion,
//! and then holds as the realm issuer's time-limited `domain_verification` Claim. The watch
//! re-verifies every 90 days, reads MX and the registrar daily, lapses a verification 72 hours
//! after an unconfirmed change and retracts its Claim, and raises the contested alarm when a
//! second organization claims the same domain; a contested domain carries no autojoin and no
//! home realm discovery.

use std::collections::BTreeSet;

use access_identity_account::domain::claim_classes::{
    DomainVerification, IdentityClass, VerificationMethod,
};
use access_identity_account::domain::claims::{ClaimOrder, line};
use access_kernel::model::Id;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::org_authority::DomainClaim;

use crate::AdminError;
use crate::domain::org::{
    CHANGE_GRACE_S, Method, REVERIFY_S, Watch, answers, mx_digest, rdap_digest, txt_name, watch,
    well_known,
};
use crate::ports::DomainProbe;

/// Contested-domain alarms raised (TN-90); no realm label (OP-47).
pub static CONTESTED: access_telemetry::metrics::Counter<0> =
    access_telemetry::metrics::Counter::new(
        "access_org_domain_contested_total",
        "Domains a second organization claimed (TN-90)",
        [],
    );

/// What one watch pass over a realm did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WatchPass {
    /// Claims verified or re-verified.
    pub verified: u32,
    /// MX or registrar changes seen.
    pub changed: u32,
    /// Verifications that lapsed, their Claims retracted.
    pub lapsed: u32,
    /// Claims newly alarmed as contested.
    pub contested: u32,
    /// Probes that could not answer; nothing changed for them.
    pub unavailable: u32,
}

/// The realm issuer's `domain_verification` order for `c`, or its retraction.
#[must_use]
pub fn verification_order(c: &DomainClaim, at: u64, retract: bool) -> ClaimOrder {
    let method = match Method::parse(&c.method) {
        Some(Method::Https) => VerificationMethod::Https,
        Some(Method::Idp) => VerificationMethod::Idp,
        _ => VerificationMethod::DnsTxt,
    };
    let body = DomainVerification {
        organization: Id(c.party),
        domain: c.domain.clone(),
        method,
        verified_at: at,
    }
    .to_value();
    let ttl = u64::try_from(REVERIFY_S).unwrap_or(0).saturating_mul(1000);
    let mut order = ClaimOrder::registry(
        c.org,
        IdentityClass::DomainVerification,
        body,
        Some(c.party),
        (at, ttl),
        line(&[b"domain_verification", c.domain.as_bytes(), &c.org]),
    );
    order.retract = retract;
    order
}

/// Queues `order` for the realm issuer's courier in `t` (OP-10).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn queue(t: &mut TenantTx, order: &ClaimOrder) -> Result<(), AdminError> {
    let bytes = order.to_bytes().map_err(|_| AdminError::Encode)?;
    let trace = access_telemetry::trace::current_header();
    t.outbox_traced(&order.kind(), &bytes, trace.as_deref())
        .await?;
    Ok(())
}

/// The watch over one realm's domain claims.
pub struct DomainWatch<'a, P> {
    /// The `access_app` pool.
    pub app: &'a Pool,
    /// The outside world.
    pub probe: &'a P,
}

impl<P: DomainProbe> DomainWatch<'_, P> {
    /// Whether the claim's challenge is published now; `None` when the probe cannot answer.
    async fn proved(&self, c: &DomainClaim) -> Option<bool> {
        match Method::parse(&c.method)? {
            Method::DnsTxt => self
                .probe
                .txt(&txt_name(&c.domain))
                .await
                .ok()
                .map(|records| records.iter().any(|r| answers(r, &c.challenge_hash))),
            Method::Https => self
                .probe
                .https(&well_known(&c.domain))
                .await
                .ok()
                .map(|body| body.is_some_and(|b| answers(&b, &c.challenge_hash))),
            Method::Idp => self.probe.idp_asserts(c.party, &c.domain).await.ok(),
        }
    }

    /// The MX and registrar digests of the claim's domain; `None` when a probe cannot answer.
    async fn seen(&self, c: &DomainClaim) -> Option<([u8; 32], [u8; 32])> {
        let mx = self.probe.mx(&c.domain).await.ok()?;
        let registrar = self.probe.registrar(&c.domain).await.ok()?;
        Some((mx_digest(&mx), rdap_digest(registrar.as_deref())))
    }

    async fn verified(
        &self,
        at: (TenantId, RealmId),
        c: &DomainClaim,
        seen: ([u8; 32], [u8; 32]),
    ) -> Result<(), AdminError> {
        let mut t = TenantTx::begin(self.app, at.0, at.1).await?;
        let now = t.server_time().await?;
        t.verify_domain(c.id, REVERIFY_S, &seen.0, &seen.1).await?;
        t.domain_checked(c.id).await?;
        t.domain_claim_issued(c.id, true).await?;
        queue(&mut t, &verification_order(c, now, false)).await?;
        t.commit().await?;
        Ok(())
    }

    /// One pass over the open claims of `(tenant, realm)` (TN-90).
    ///
    /// # Errors
    /// [`AdminError`] when the store cannot answer; probes that cannot answer only count.
    pub async fn realm(&self, at: (TenantId, RealmId)) -> Result<WatchPass, AdminError> {
        let mut out = WatchPass::default();
        let mut t = TenantTx::begin(self.app, at.0, at.1).await?;
        let now = i64::try_from(t.server_time().await?).unwrap_or(i64::MAX);
        let claims = t.open_domain_claims(None).await?;
        let domains: BTreeSet<&str> = claims.iter().map(|c| c.domain.as_str()).collect();
        for d in domains {
            let alarmed = t.contest_domain(d).await?;
            if !alarmed.is_empty() {
                CONTESTED.add(1, []);
                out.contested = out
                    .contested
                    .saturating_add(u32::try_from(alarmed.len()).unwrap_or(u32::MAX));
                tracing::warn!(
                    event = "org.domain.contested",
                    "a second organization claimed a domain; no autojoin for any of them (TN-90)"
                );
            }
        }
        t.commit().await?;
        for c in &claims {
            let step = watch(
                c.verified_ms,
                c.reverify_ms,
                c.checked_ms,
                c.changed_ms,
                now,
            );
            match step {
                Watch::Rest => {}
                Watch::Verify => match self.proved(c).await {
                    Some(true) => {
                        let Some(seen) = self.seen(c).await else {
                            out.unavailable = out.unavailable.saturating_add(1);
                            continue;
                        };
                        self.verified(at, c, seen).await?;
                        out.verified = out.verified.saturating_add(1);
                    }
                    Some(false) => {}
                    None => out.unavailable = out.unavailable.saturating_add(1),
                },
                Watch::Check { reverify } => {
                    let Some(seen) = self.seen(c).await else {
                        out.unavailable = out.unavailable.saturating_add(1);
                        continue;
                    };
                    let mut t = TenantTx::begin(self.app, at.0, at.1).await?;
                    if t.watch_domain(c.id, &seen.0, &seen.1).await? {
                        out.changed = out.changed.saturating_add(1);
                        tracing::warn!(
                            event = "org.domain.changed",
                            "a verified domain's MX or registrar changed; re-verify within 72 hours (TN-90)"
                        );
                    }
                    t.domain_checked(c.id).await?;
                    t.commit().await?;
                    if reverify && self.proved(c).await == Some(true) {
                        self.verified(at, c, seen).await?;
                        out.verified = out.verified.saturating_add(1);
                    }
                }
            }
        }
        out.lapsed = self.lapse(at).await?;
        Ok(out)
    }

    /// Withdraws verifications past their re-verification time or 72 hours past an unconfirmed
    /// change, and retracts their Claims (TN-90).
    async fn lapse(&self, at: (TenantId, RealmId)) -> Result<u32, AdminError> {
        let mut t = TenantTx::begin(self.app, at.0, at.1).await?;
        let now = t.server_time().await?;
        let before = t.open_domain_claims(None).await?;
        let lapsed = t.lapse_domains(CHANGE_GRACE_S).await?;
        let mut n = 0u32;
        for id in &lapsed {
            let Some(c) = before.iter().find(|c| c.id == *id) else {
                continue;
            };
            t.domain_claim_issued(c.id, false).await?;
            queue(&mut t, &verification_order(c, now, true)).await?;
            n = n.saturating_add(1);
        }
        t.commit().await?;
        Ok(n)
    }
}
