//! The application token a forward-auth proxy carries to the application (IDP-30 (3), OP-156
//! m.3 (l)): a compact JWS in the `Access-Identity` header, `typ: access-app+jwt`, ES256 under
//! the realm JOSE key, for this application only (`aud`), with the realm's pairwise `sub` for it,
//! living 60 s. The application reads identity from it, never from a plain header unless it
//! knows it is only reachable through the proxy.
//!
//! It is an identity assertion: it carries who the request is for and the decision that let it
//! through, not authority (§10.4.5). Read the keys with [`super::keys::key_set`] from the realm
//! JWKS with [`app_token_algorithms`]. Nothing is accepted on a fault (MD-8, TI-9).

use alloc::collections::BTreeSet;
use alloc::string::String;

use access_kernel::json::Json;
use access_kernel::model::TrustedTime;
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{Algorithm, KeySet};
use access_kernel::verify::jws::{self, ClaimRules, Origin};

/// The header the token comes in.
pub const APP_TOKEN_HEADER: &str = "access-identity";

/// The token `typ`.
pub const APP_TYP: &str = "access-app+jwt";

/// The longest a token lives, seconds.
pub const APP_TTL_S: i64 = 60;

/// Largest token accepted, checked before anything else.
pub const MAX_APP_TOKEN: usize = 8 * 1024;

/// Default clock skew, ms.
pub const APP_SKEW_MS: u64 = 5_000;

/// The algorithms an application token is signed with: ES256 only (OP-156 m.3 (l)).
#[must_use]
pub fn app_token_algorithms() -> BTreeSet<Algorithm> {
    [Algorithm::Es256].into_iter().collect()
}

/// What the application expects.
#[derive(Clone, Copy, Debug)]
pub struct AppTokenRules<'a> {
    /// The realm's issuer.
    pub issuer: &'a str,
    /// This application's origin, the `aud` its proxy was registered with.
    pub audience: &'a str,
    /// The application's time.
    pub now: TrustedTime,
    /// Clock skew, ms.
    pub skew_ms: u64,
}

/// Who a verified token says the request is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppIdentity {
    /// The realm's issuer.
    pub issuer: String,
    /// The `sub` this application reads: pairwise, never the same at another application.
    pub sub: String,
    /// The decision that let the request through.
    pub decision: String,
    /// The token's id.
    pub jti: String,
}

/// Why a token is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AppTokenError {
    /// Larger than [`MAX_APP_TOKEN`].
    #[error("app-token-size")]
    Size,
    /// Not an ES256 `access-app+jwt` signed by a realm key.
    #[error("app-token-signature")]
    Signature,
    /// `iss`, `aud`, `exp` or `iat` wrong, or expired.
    #[error("app-token-claims")]
    Claims,
    /// It lives longer than [`APP_TTL_S`].
    #[error("app-token-lifetime")]
    Lifetime,
    /// `sub`, `jti` or `decision` missing or out of bounds.
    #[error("app-token-subject")]
    Subject,
}

fn text(claims: &Json, name: &str, len: core::ops::RangeInclusive<usize>) -> Option<String> {
    claims
        .get(name)
        .and_then(Json::as_str)
        .filter(|s| len.contains(&s.len()))
        .map(String::from)
}

/// Verifies `token` against the realm's `keys` under `rules`.
///
/// # Errors
/// [`AppTokenError`].
pub fn verify_app_token(
    token: &str,
    keys: &KeySet,
    rules: &AppTokenRules<'_>,
) -> Result<AppIdentity, AppTokenError> {
    if token.len() > MAX_APP_TOKEN {
        return Err(AppTokenError::Size);
    }
    let verified = jws::verify_compact(&PureBackend, token, keys, APP_TYP, Origin::Native)
        .map_err(|_| AppTokenError::Signature)?;
    if verified.algorithm != Algorithm::Es256 {
        return Err(AppTokenError::Signature);
    }
    let claims = jws::check_claims(
        &verified.payload,
        &ClaimRules {
            issuer: rules.issuer,
            audience: rules.audience,
            now: rules.now,
            skew_ms: rules.skew_ms,
        },
    )
    .map_err(|_| AppTokenError::Claims)?;
    if !matches!(claims.get("aud"), Some(Json::Str(_))) {
        return Err(AppTokenError::Claims);
    }
    let (Some(iat), Some(exp)) = (
        claims.get("iat").and_then(Json::as_int),
        claims.get("exp").and_then(Json::as_int),
    ) else {
        return Err(AppTokenError::Claims);
    };
    let life = exp.checked_sub(iat).ok_or(AppTokenError::Lifetime)?;
    if !(0..=APP_TTL_S).contains(&life) {
        return Err(AppTokenError::Lifetime);
    }
    let (Some(sub), Some(jti), Some(decision)) = (
        text(&claims, "sub", 1..=128),
        text(&claims, "jti", 16..=64),
        text(&claims, "decision", 1..=128),
    ) else {
        return Err(AppTokenError::Subject);
    };
    Ok(AppIdentity {
        issuer: String::from(rules.issuer),
        sub,
        decision,
        jti,
    })
}
