//! The realm key set's rules: which rotation policies a realm may take and the JWKS document
//! that publishes its keys (CR-19, CR-24 to CR-26, MD-3).

use access_crypto::jose::{JoseError, public_jwk};
use suiss_crypto::cose::PublicKey;
use suiss_crypto::rotation::Policy;

/// The JWKS response's `Cache-Control` (CR-25, PD).
pub const CACHE_CONTROL: &str = "max-age=300, stale-while-revalidate=600, stale-if-error=86400";

/// The JWKS media type (RFC 7517 §8.5).
pub const JWKS_CONTENT_TYPE: &str = "application/jwk-set+json";

/// `T_cache`: how long a JWKS response may be served from a cache, `max-age` plus
/// `stale-while-revalidate` (CR-25).
pub const JWKS_CACHE_MS: u64 = 900_000;

/// `T_token_max`: the longest identity token a realm key signs; access tokens above 60 minutes
/// are refused (MD-7, U36).
pub const TOKEN_MAX_MS: u64 = 3_600_000;

/// Why a realm rotation policy is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// A key would sign for less time than a token lives (CR-26, `T_token < T_sign`).
    #[error("lifetime not above the token ceiling")]
    Lifetime,
    /// A key would leave the JWKS before its last token expires (CR-26).
    #[error("retention below the token ceiling")]
    Retention,
    /// A key would sign before caches could have seen it (CR-25).
    #[error("publish lead below the JWKS cache time")]
    Lead,
    /// A published backup could lapse before the active key is due (CR-27).
    #[error("window shorter than the jittered lifetime and lead")]
    Window,
}

impl PolicyError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Lifetime => "realm-key-lifetime",
            Self::Retention => "realm-key-retention",
            Self::Lead => "realm-key-lead",
            Self::Window => "realm-key-window",
        }
    }
}

/// Checks a realm's rotation policy against the token ceiling and the JWKS cache time.
///
/// # Errors
/// [`PolicyError`].
pub fn check(policy: &Policy) -> Result<(), PolicyError> {
    if policy.lifetime_ms <= TOKEN_MAX_MS {
        return Err(PolicyError::Lifetime);
    }
    if policy.retain_ms < TOKEN_MAX_MS {
        return Err(PolicyError::Retention);
    }
    if policy.publish_lead_ms < JWKS_CACHE_MS {
        return Err(PolicyError::Lead);
    }
    let longest = u128::from(policy.lifetime_ms)
        .checked_mul(1000_u128.saturating_add(u128::from(policy.jitter_permille)))
        .and_then(|n| n.checked_div(1000))
        .and_then(|n| n.checked_add(u128::from(policy.publish_lead_ms)))
        .ok_or(PolicyError::Window)?;
    if u128::from(policy.window_ms) <= longest {
        return Err(PolicyError::Window);
    }
    Ok(())
}

/// The JWKS document of `keys`, in the given order (RFC 7517 §5).
///
/// # Errors
/// [`JoseError::Key`] for a key Access does not publish, such as `AKP` (MD-3).
pub fn jwks<'a>(
    keys: impl IntoIterator<Item = (&'a [u8; 32], &'a PublicKey)>,
) -> Result<String, JoseError> {
    let mut out = String::from(r#"{"keys":["#);
    for (i, (kid, key)) in keys.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&public_jwk(kid, key)?);
    }
    out.push_str("]}");
    Ok(out)
}

#[cfg(test)]
mod tests;
