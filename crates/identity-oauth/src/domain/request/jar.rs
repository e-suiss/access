//! JWT-Secured Authorization Requests (RFC 9101; §10.4.3, CR-4, IDI-6, OP-155 m.3 (k)): a
//! request object the client signed, sent as `request` to `/par` only. Its claims are the
//! authorization request; the outer parameters may only repeat `client_id`. A request object
//! encrypted to the realm is opened first with the realm's `jwe-enc` key.

use access_kernel::json::Json;

use crate::domain::jwt::{Jwk, JwtError, SKEW_MS, verify_client_jws};
use crate::domain::request::{MAX_PARAMS, Params};

/// Longest a request object may live, from `nbf` to `exp` (FAPI 2.0 Message Signing §5.3.1:
/// at most 60 minutes).
pub const MAX_LIFETIME_MS: u64 = 60 * 60 * 1000;

/// The `typ` of a request object (RFC 9101 §10.8).
pub const TYP: &str = "oauth-authz-req+jwt";

/// Why a request object is refused; every case answers `invalid_request_object`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JarError {
    /// Not a compact JWS, or its header is outside the profile.
    #[error("format")]
    Format,
    /// Signed with an algorithm outside the client's allowlist (IDI-6).
    #[error("algorithm")]
    Algorithm,
    /// The signature does not verify against the client's keys.
    #[error("signature")]
    Signature,
    /// `iss`, `aud` or `client_id` is wrong, or a claim is not a request parameter.
    #[error("claims")]
    Claims,
    /// Expired, not yet valid, or too long-lived.
    #[error("time")]
    Time,
    /// An encrypted request object that does not open.
    #[error("encryption")]
    Encryption,
}

impl JarError {
    /// A short description for the developer.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Format => "the request object is malformed",
            Self::Algorithm => {
                "the request object is signed with an algorithm this client may not use"
            }
            Self::Signature => "the request object signature does not verify",
            Self::Claims => "the request object claims are not valid",
            Self::Time => "the request object is expired or too long-lived",
            Self::Encryption => "the encrypted request object does not open",
        }
    }
}

impl From<JwtError> for JarError {
    fn from(e: JwtError) -> Self {
        match e {
            JwtError::Algorithm => Self::Algorithm,
            JwtError::Signature | JwtError::Key | JwtError::Jwks => Self::Signature,
            JwtError::Time => Self::Time,
            JwtError::Claims => Self::Claims,
            _ => Self::Format,
        }
    }
}

/// What a request object is held against.
#[derive(Clone, Copy, Debug)]
pub struct JarRules<'a> {
    /// The client that pushed it.
    pub client_id: &'a str,
    /// The realm issuer, which `aud` names alone or among others (RFC 7519 §4.1.3).
    pub issuer: &'a str,
    /// Now, Unix milliseconds.
    pub now_ms: u64,
    /// Whether the client may sign with RS256 (its opt-in, never under FAPI 2.0).
    pub rs256: bool,
}

const REGISTERED: [&str; 6] = ["iss", "aud", "exp", "nbf", "iat", "jti"];
const FORBIDDEN: [&str; 2] = ["request", "request_uri"];

fn ms(v: Option<&Json>) -> Result<Option<u64>, JarError> {
    v.map(|v| {
        v.as_int()
            .and_then(|s| u64::try_from(s).ok())
            .and_then(|s| s.checked_mul(1000))
            .ok_or(JarError::Time)
    })
    .transpose()
}

fn param_value(v: &Json) -> Result<String, JarError> {
    Ok(match v {
        Json::Str(s) => s.clone(),
        Json::Int(i) => i.to_string(),
        Json::Object(_) | Json::Array(_) => access_crypto::jose::output::to_string(v),
        Json::Bool(_) | Json::Null => return Err(JarError::Claims),
    })
}

/// RFC 9101 §6, FAPI 2.0 Message Signing §5.3.1: the authorization request a signed request
/// object `token` carries, after its signature verified against `keys` with an allowed
/// algorithm. `iss` and `client_id` are the client, `aud` the issuer, `exp` and `nbf` present
/// with at most [`MAX_LIFETIME_MS`] between them, and it nests no other request.
///
/// # Errors
/// [`JarError`].
pub fn verify(token: &str, keys: &[Jwk], rules: &JarRules<'_>) -> Result<Params, JarError> {
    let signed = verify_client_jws(token, keys, rules.rs256)?;
    if signed
        .typ
        .as_deref()
        .is_some_and(|t| t != TYP && t != "JWT")
    {
        return Err(JarError::Format);
    }
    let c = &signed.claims;
    let Json::Object(members) = c else {
        return Err(JarError::Claims);
    };
    let text = |n: &str| c.get(n).and_then(Json::as_str);
    let aud_ok = match c.get("aud") {
        Some(Json::Str(a)) => a == rules.issuer,
        Some(Json::Array(a)) => a.iter().any(|v| v.as_str() == Some(rules.issuer)),
        _ => false,
    };
    if text("iss") != Some(rules.client_id) || text("client_id") != Some(rules.client_id) || !aud_ok
    {
        return Err(JarError::Claims);
    }
    let exp = ms(c.get("exp"))?.ok_or(JarError::Time)?;
    let nbf = ms(c.get("nbf"))?.ok_or(JarError::Time)?;
    let now = rules.now_ms;
    if exp.saturating_add(SKEW_MS) < now
        || nbf > now.saturating_add(SKEW_MS)
        || exp.saturating_sub(nbf) > MAX_LIFETIME_MS
        || now.saturating_sub(nbf) > MAX_LIFETIME_MS
    {
        return Err(JarError::Time);
    }
    let mut pairs = Vec::new();
    for (name, value) in members {
        if REGISTERED.contains(&name.as_str()) {
            continue;
        }
        if FORBIDDEN.contains(&name.as_str()) || pairs.len() >= MAX_PARAMS {
            return Err(JarError::Claims);
        }
        pairs.push((name.clone(), param_value(value)?));
    }
    Params::new(pairs).map_err(|_| JarError::Claims)
}

/// Whether the outer parameters of a pushed request that carries `request` add nothing to it:
/// only `client_id`, `request` and client authentication may stand beside the request object
/// (RFC 9101 §5, RFC 9126 §3).
#[must_use]
pub fn outer_ok(outer: &Params) -> bool {
    const ALLOWED: [&str; 5] = [
        "client_id",
        "request",
        "client_assertion",
        "client_assertion_type",
        "client_secret",
    ];
    outer.names().all(|n| ALLOWED.contains(&n))
}

#[cfg(test)]
mod tests;
