//! Trust marks (OpenID Federation 1.0 §7, §10.7.1 item 6): the mark itself, who may issue it,
//! its status query and how long a status is kept (OP-155 m.3 (j)). A trust mark is never an
//! Acceptance and never satisfies consent (IDP-20).

use access_kernel::json::Json;

use crate::jws::{self, time_ms};
use crate::statement::{
    EntityStatement, Jwk, MAX_STATEMENT, OidfError, SKEW_MS, TRUST_MARK_TYP, entity_id_ok,
};

/// `typ` of a trust mark status response.
pub const STATUS_TYP: &str = "trust-mark-status-response+jwt";
/// Longest time a trust mark status is kept: min(`exp`, 1 h) (OP-155 m.3 (j)).
pub const STATUS_CACHE_MAX_MS: u64 = 3_600_000;
/// Media type of a trust mark status response.
pub const STATUS_CONTENT_TYPE: &str = "application/trust-mark-status-response+jwt";

/// A verified trust mark.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustMark {
    /// `trust_mark_type`.
    pub trust_mark_type: String,
    /// The issuer's entity identifier.
    pub iss: String,
    /// The entity it is about.
    pub sub: String,
    /// `iat`, Unix milliseconds.
    pub iat_ms: u64,
    /// `exp`, Unix milliseconds; none for a mark without expiry.
    pub exp_ms: Option<u64>,
    /// The compact JWS.
    pub raw: String,
}

/// Verifies a trust mark about `subject` with its issuer's keys: `typ` `trust-mark+jwt`,
/// `trust_mark_type` (never the draft `id`), `iat`, an unexpired `exp` when present, and no
/// `delegation`, which is not accepted.
///
/// # Errors
/// [`OidfError`].
pub fn verify_trust_mark(
    jwt: &str,
    issuer_keys: &[Jwk],
    subject: &str,
    now_ms: u64,
) -> Result<TrustMark, OidfError> {
    let parts = jws::split(jwt, MAX_STATEMENT)?;
    let (alg, kid) = jws::check_header(&parts.header, Some(&[TRUST_MARK_TYP]), &[])?;
    jws::verify(&parts, alg, &kid, issuer_keys)?;
    let c = &parts.payload;
    if c.get("id").is_some() || c.get("delegation").is_some() {
        return Err(if c.get("delegation").is_some() {
            OidfError::Delegation
        } else {
            OidfError::TrustMark
        });
    }
    let claim = |n: &str| c.get(n).and_then(Json::as_str).map(String::from);
    let trust_mark_type = claim("trust_mark_type")
        .filter(|t| !t.is_empty())
        .ok_or(OidfError::TrustMark)?;
    let iss = claim("iss").ok_or(OidfError::Claims)?;
    let sub = claim("sub").ok_or(OidfError::Claims)?;
    if !entity_id_ok(&iss) {
        return Err(OidfError::EntityId);
    }
    if sub != subject {
        return Err(OidfError::TrustMark);
    }
    let iat_ms = time_ms(c, "iat")?.ok_or(OidfError::Time)?;
    let exp_ms = time_ms(c, "exp")?;
    if iat_ms > now_ms.saturating_add(SKEW_MS)
        || exp_ms.is_some_and(|e| e.saturating_add(SKEW_MS) <= now_ms)
    {
        return Err(OidfError::Time);
    }
    Ok(TrustMark {
        trust_mark_type,
        iss,
        sub,
        iat_ms,
        exp_ms,
        raw: String::from(jwt),
    })
}

/// Whether the trust anchor `anchor` lets `issuer` issue marks of `trust_mark_type`: listed for
/// the type in its `trust_mark_issuers`, and the type not owned in `trust_mark_owners`, since
/// a delegation is not accepted.
#[must_use]
pub fn issuer_allowed(anchor: &EntityStatement, trust_mark_type: &str, issuer: &str) -> bool {
    if anchor
        .trust_mark_owners
        .as_ref()
        .is_some_and(|o| o.get(trust_mark_type).is_some())
    {
        return false;
    }
    match anchor
        .trust_mark_issuers
        .as_ref()
        .and_then(|i| i.get(trust_mark_type))
    {
        Some(Json::Array(list)) => list.iter().any(|i| i.as_str() == Some(issuer)),
        _ => false,
    }
}

/// How long a status answer about a mark expiring at `exp_ms` is kept: min(`exp`, 1 h).
#[must_use]
pub fn status_cache_ms(exp_ms: Option<u64>, now_ms: u64) -> u64 {
    exp_ms.map_or(STATUS_CACHE_MAX_MS, |e| {
        e.saturating_sub(now_ms).min(STATUS_CACHE_MAX_MS)
    })
}

/// The form body of a trust mark status request: `trust_mark=<jwt>`.
#[must_use]
pub fn status_request_body(trust_mark: &str) -> String {
    let mut out = String::from("trust_mark=");
    for b in trust_mark.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(hex(b >> 4));
            out.push(hex(b & 0xf));
        }
    }
    out
}

fn hex(n: u8) -> char {
    char::from(
        b"0123456789ABCDEF"
            .get(usize::from(n))
            .copied()
            .unwrap_or(b'0'),
    )
}

/// A verified trust mark status answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// `status`, such as `active`, `expired`, `revoked` or `invalid`.
    pub status: String,
    /// `iat`, Unix milliseconds.
    pub iat_ms: u64,
}

impl Status {
    /// Whether the mark is active.
    #[must_use]
    pub fn active(&self) -> bool {
        self.status == "active"
    }
}

/// Verifies a status answer from `issuer` about `trust_mark`, signed with the issuer's keys.
///
/// # Errors
/// [`OidfError`].
pub fn parse_status_response(
    jwt: &str,
    issuer: &str,
    issuer_keys: &[Jwk],
    trust_mark: &str,
    now_ms: u64,
) -> Result<Status, OidfError> {
    let parts = jws::split(jwt, MAX_STATEMENT)?;
    let (alg, kid) = jws::check_header(&parts.header, Some(&[STATUS_TYP]), &[])?;
    jws::verify(&parts, alg, &kid, issuer_keys)?;
    let c = &parts.payload;
    let claim = |n: &str| c.get(n).and_then(Json::as_str);
    if claim("iss") != Some(issuer) || claim("trust_mark") != Some(trust_mark) {
        return Err(OidfError::Claims);
    }
    let status = claim("status")
        .filter(|s| !s.is_empty())
        .ok_or(OidfError::Claims)?;
    let iat_ms = time_ms(c, "iat")?.ok_or(OidfError::Time)?;
    if iat_ms > now_ms.saturating_add(SKEW_MS) {
        return Err(OidfError::Time);
    }
    Ok(Status {
        status: String::from(status),
        iat_ms,
    })
}

#[cfg(test)]
mod tests;
