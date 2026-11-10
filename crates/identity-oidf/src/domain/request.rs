//! Registration checks (OpenID Federation 1.0 §12, §10.7.1 item 7): the request object of
//! automatic registration with its `jti` and `exp` for the replay table, and the entity
//! configuration an RP posts for explicit registration. Both are off per realm by default.

use access_kernel::json::Json;

use crate::chain::{ChainError, from_array};
use crate::jws::{self, time_ms};
use crate::statement::{
    self, EntityStatement, Jwk, MAX_STATEMENT, OidfError, SKEW_MS, verify_with,
};

/// Longest `jti` accepted.
pub const MAX_JTI: usize = 256;
/// Longest lifetime of a request object, from now to `exp`.
pub const MAX_REQUEST_LIFETIME_MS: u64 = 3_600_000;
/// `typ` values a request object may carry (RFC 9101 §10.8).
pub const REQUEST_TYPS: [&str; 2] = ["oauth-authz-req+jwt", "JWT"];

/// The `trust_chain` JWS header parameter, read without verifying anything; `None` when absent
/// or malformed.
#[must_use]
pub fn trust_chain_header(jwt: &str) -> Option<Vec<String>> {
    let parts = jws::split(jwt, MAX_STATEMENT).ok()?;
    trust_chain_of(&parts.header).ok().flatten()
}

fn trust_chain_of(header: &Json) -> Result<Option<Vec<String>>, ChainError> {
    header.get("trust_chain").map(from_array).transpose()
}

/// A verified request object of automatic registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestObject {
    /// `jti`, for the replay table.
    pub jti: String,
    /// `exp`, Unix milliseconds; the replay entry lives until then.
    pub exp_ms: u64,
    /// Every claim.
    pub claims: Json,
}

/// Verifies a request object with the RP's keys from its resolved chain: ES256 or RS256, a
/// `kid`, `typ` absent or a request object type, `iss` (and `client_id` when present) the
/// client, `aud` naming `audience`, a `jti` of at most [`MAX_JTI`] characters, and an `exp`
/// at most [`MAX_REQUEST_LIFETIME_MS`] ahead and not past.
///
/// # Errors
/// [`OidfError`].
pub fn verify_request_object(
    jwt: &str,
    rp_keys: &[Jwk],
    client_id: &str,
    audience: &str,
    now_ms: u64,
) -> Result<RequestObject, OidfError> {
    let parts = jws::split(jwt, MAX_STATEMENT)?;
    if parts.header.get("typ").is_some() {
        jws::check_header(&parts.header, Some(&REQUEST_TYPS), &["trust_chain"])?;
    }
    let (alg, kid) = jws::check_header(&parts.header, None, &["trust_chain"])?;
    trust_chain_of(&parts.header).map_err(|_| OidfError::Header)?;
    jws::verify(&parts, alg, &kid, rp_keys)?;
    let c = &parts.payload;
    let claim = |n: &str| c.get(n).and_then(Json::as_str);
    if claim("iss") != Some(client_id)
        || c.get("client_id")
            .is_some_and(|v| v.as_str() != Some(client_id))
    {
        return Err(OidfError::Claims);
    }
    let aud_ok = match c.get("aud") {
        Some(Json::Str(a)) => a == audience,
        Some(Json::Array(a)) => a.iter().any(|v| v.as_str() == Some(audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(OidfError::Audience);
    }
    let jti = claim("jti")
        .filter(|j| !j.is_empty() && j.len() <= MAX_JTI)
        .ok_or(OidfError::Claims)?;
    let exp_ms = time_ms(c, "exp")?.ok_or(OidfError::Time)?;
    if exp_ms.saturating_add(SKEW_MS) <= now_ms
        || exp_ms > now_ms.saturating_add(MAX_REQUEST_LIFETIME_MS)
        || time_ms(c, "iat")?.is_some_and(|t| t > now_ms.saturating_add(SKEW_MS))
    {
        return Err(OidfError::Time);
    }
    Ok(RequestObject {
        jti: String::from(jti),
        exp_ms,
        claims: c.clone(),
    })
}

/// An explicit registration request: the RP's self-signed entity configuration with `aud`
/// the OP's entity identifier, optionally carrying a `trust_chain` header. Its chain is
/// resolved and its metadata checked by the caller.
///
/// # Errors
/// [`OidfError`].
pub fn verify_explicit_registration(
    jwt: &str,
    op_entity_id: &str,
    now_ms: u64,
) -> Result<(EntityStatement, Option<Vec<String>>), OidfError> {
    let (iss, _) = statement::peek(jwt)?;
    let keys = statement::self_keys(jwt)?;
    let s = verify_with(jwt, &keys, now_ms, &["trust_chain"])?;
    if s.iss != iss || !s.is_configuration() {
        return Err(OidfError::Claims);
    }
    let aud_ok = match s.claims.get("aud") {
        Some(Json::Str(a)) => a == op_entity_id,
        Some(Json::Array(a)) => a.len() == 1 && a.iter().any(|v| v.as_str() == Some(op_entity_id)),
        _ => false,
    };
    if !aud_ok {
        return Err(OidfError::Audience);
    }
    let parts = jws::split(jwt, MAX_STATEMENT)?;
    let chain = trust_chain_of(&parts.header).map_err(|_| OidfError::Header)?;
    Ok((s, chain))
}

#[cfg(test)]
mod tests;
