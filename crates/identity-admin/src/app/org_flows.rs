//! What committed organization Exercises write besides their decision (TN-90, TN-120,
//! OP-153 m.3 (o), (p)): a domain claim and its one-time challenge, a release that retracts the
//! domain's Claim, and an enterprise connection draft.

use access_store::identity::TenantTx;

use super::ClientSecret;
use super::orgs::live_org;
use crate::AdminError;
use crate::domain::org::{DomainClaim, SsoDraft};
use crate::domain::{Change, Invalid};

/// Records a committed `idp.org.domain_claim` and answers its challenge once: 256 random bits
/// as base64url, kept only as SHA-256 (TN-90, OP-153 m.3 (o)). A second organization's claim of
/// the same domain raises the contested alarm on the watch's next pass and at once here.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn claim_domain(
    t: &mut TenantTx,
    d: &DomainClaim,
    exercise: &[u8; 32],
) -> Result<ClientSecret, AdminError> {
    let org = live_org(t, d.org).await?;
    let token = access_kernel::json::b64url_encode(
        &access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?,
    );
    let hash = suiss_crypto::digest::sha256(token.as_bytes());
    t.claim_domain(org.id, (&d.domain, d.method.word()), &hash, exercise)
        .await?;
    if !t.contest_domain(&d.domain).await?.is_empty() {
        super::domains::CONTESTED.add(1, []);
        tracing::warn!(
            event = "org.domain.contested",
            "a second organization claimed a domain; no autojoin for any of them (TN-90)"
        );
    }
    Ok(ClientSecret(token))
}

/// Releases a claim; a live `domain_verification` Claim of it is retracted (TN-90).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn release_domain(
    t: &mut TenantTx,
    org: [u8; 16],
    claim: [u8; 16],
) -> Result<bool, AdminError> {
    let org = live_org(t, org).await?;
    let c = t
        .open_domain_claims(Some(org.id))
        .await?
        .into_iter()
        .find(|c| c.id == claim)
        .ok_or(Invalid::NoDomain)?;
    let done = t.release_domain(claim).await?;
    if done && c.claimed {
        let now = t.server_time().await?;
        t.domain_claim_issued(claim, false).await?;
        super::domains::queue(t, &super::domains::verification_order(&c, now, true)).await?;
    }
    Ok(done)
}

/// Records a committed `idp.org.sso_draft` by the Party of `subject` (TN-120): a draft only.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn sso_draft(
    t: &mut TenantTx,
    d: &SsoDraft,
    subject: Option<[u8; 16]>,
    exercise: &[u8; 32],
) -> Result<(), AdminError> {
    let org = live_org(t, d.org).await?;
    let by = match subject {
        Some(s) => access_store::idp::subject_party(t, &s)
            .await?
            .unwrap_or([0; 16]),
        None => [0; 16],
    };
    t.insert_sso_draft(org.id, (&d.issuer, &d.client_id), by, exercise)
        .await?;
    Ok(())
}

/// What a committed organization change writes besides its row, with the one-time secret it
/// answers, if any.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn committed(
    t: &mut TenantTx,
    change: &Change,
    subject: Option<[u8; 16]>,
    exercise: &[u8; 32],
) -> Result<Option<ClientSecret>, AdminError> {
    match change {
        Change::OrgDomainClaim(d) => Ok(Some(claim_domain(t, d, exercise).await?)),
        Change::OrgSsoDraft(d) => {
            sso_draft(t, d, subject, exercise).await?;
            Ok(None)
        }
        _ => Ok(None),
    }
}
