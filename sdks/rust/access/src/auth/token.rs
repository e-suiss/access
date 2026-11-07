//! The token response and the ID token (RFC 6749 §5, RFC 9449 §5, OIDC Core §3.1.3.7). The ID
//! token is verified through the Kernel's compact JWS check against the realm JWKS: header
//! `alg`/`kid`/`typ` only, `typ` `JWT`, an Access signature algorithm; then `iss`, `aud`, `exp`,
//! `iat`, `azp`, the request's `nonce`, and `sub`.
//!
//! A `sub` is the subject at this client only (OIDC Core §8.1): a realm may issue pairwise
//! identifiers, so [`Subject`] carries the issuer and the client and two clients' subjects are
//! never equal, even when the strings are.

use alloc::collections::BTreeSet;
use alloc::string::String;

use access_kernel::json::{self, Json};
use access_kernel::model::TrustedTime;
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{Algorithm, KeySet};
use access_kernel::verify::jws::{self, ClaimRules, Origin};

use super::OAuthClass;
use crate::transport::Answer;

/// Largest token response read (§14.6).
pub const MAX_TOKEN_RESPONSE: usize = 64 * 1024;

/// The ID token `typ`.
pub const ID_TYP: &str = "JWT";

/// Default clock skew for ID tokens.
pub const ID_SKEW_MS: u64 = 60_000;

/// The ID token algorithms Access signs with (MD-3); never taken from the token.
#[must_use]
pub fn id_token_algorithms() -> BTreeSet<Algorithm> {
    [Algorithm::Es256, Algorithm::Ed25519].into_iter().collect()
}

/// How the access token is bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenType {
    /// `DPoP` (RFC 9449).
    Dpop,
    /// `Bearer`; only accepted where the caller asked for no binding.
    Bearer,
}

/// A secret string whose `Debug` hides the value (OP-64).
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Secret {
    /// Wraps `value`.
    #[must_use]
    pub const fn new(value: String) -> Self {
        Self(value)
    }

    /// The value, for the one header or body that carries it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// A successful token response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tokens {
    /// `access_token`.
    pub access_token: Secret,
    /// `token_type`.
    pub token_type: TokenType,
    /// `expires_in`, seconds.
    pub expires_in: u64,
    /// `refresh_token`, when issued.
    pub refresh_token: Option<Secret>,
    /// `id_token`, when issued; verify it with [`validate_id_token`].
    pub id_token: Option<String>,
    /// `scope`, when sent.
    pub scope: Option<String>,
}

/// Why the token response is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// No answer.
    #[error("token-unavailable")]
    Unavailable,
    /// An OAuth error answer (P15: an unknown `error` is [`OAuthClass::Refused`]).
    #[error("token-refused")]
    Refused {
        /// The class.
        class: OAuthClass,
        /// The HTTP status.
        status: u16,
    },
    /// Not a token response.
    #[error("token-malformed")]
    Malformed,
    /// A `Bearer` token where a DPoP-bound one was asked for (RFC 9449 §5).
    #[error("token-unbound")]
    Unbound,
}

/// Reads the token endpoint's answer; with `expect_dpop` a `Bearer` token is refused.
///
/// # Errors
/// [`TokenError`].
pub fn parse_response(answer: &Answer, expect_dpop: bool) -> Result<Tokens, TokenError> {
    let Answer::Response(r) = answer else {
        return Err(TokenError::Unavailable);
    };
    let body = json::parse(&r.body, MAX_TOKEN_RESPONSE).ok();
    if r.status != 200 {
        let class = body
            .as_ref()
            .and_then(|b| b.get("error"))
            .and_then(Json::as_str)
            .map_or(
                if r.status >= 500 {
                    OAuthClass::Unavailable
                } else {
                    OAuthClass::Refused
                },
                OAuthClass::of,
            );
        return Err(TokenError::Refused {
            class,
            status: r.status,
        });
    }
    let body = body.ok_or(TokenError::Malformed)?;
    let text = |n: &str| body.get(n).and_then(Json::as_str).map(String::from);
    let access_token = text("access_token")
        .filter(|t| !t.is_empty())
        .ok_or(TokenError::Malformed)?;
    let token_type = match text("token_type").as_deref() {
        Some(t) if t.eq_ignore_ascii_case("dpop") => TokenType::Dpop,
        Some(t) if t.eq_ignore_ascii_case("bearer") => TokenType::Bearer,
        _ => return Err(TokenError::Malformed),
    };
    if expect_dpop && token_type != TokenType::Dpop {
        return Err(TokenError::Unbound);
    }
    let expires_in = body
        .get("expires_in")
        .and_then(Json::as_int)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(TokenError::Malformed)?;
    Ok(Tokens {
        access_token: Secret(access_token),
        token_type,
        expires_in,
        refresh_token: text("refresh_token").map(Secret),
        id_token: text("id_token"),
        scope: text("scope"),
    })
}

/// What the ID token must match.
#[derive(Clone, Copy, Debug)]
pub struct IdTokenRules<'a> {
    /// The issuer the request went to.
    pub issuer: &'a str,
    /// This client.
    pub client_id: &'a str,
    /// The request's `nonce`.
    pub nonce: &'a str,
    /// Trusted time.
    pub now: TrustedTime,
    /// Clock skew, milliseconds.
    pub skew_ms: u64,
}

/// The authenticated subject, as this client knows it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Subject {
    /// `iss`.
    pub issuer: String,
    /// The client the identifier is for; part of the identity because `sub` may be pairwise.
    pub client_id: String,
    /// `sub`.
    pub sub: String,
}

/// Why an ID token is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdTokenError {
    /// The signature, header or algorithm does not verify.
    #[error("id-token-signature")]
    Signature,
    /// `iss`, `aud`, `exp`, `iat` or `nbf` do not hold.
    #[error("id-token-claims")]
    Claims,
    /// Several audiences without `azp` = this client, or `azp` naming another client.
    #[error("id-token-azp")]
    Azp,
    /// `nonce` is missing or not this request's.
    #[error("id-token-nonce")]
    Nonce,
    /// No `sub`, or one longer than 255 characters.
    #[error("id-token-sub")]
    Sub,
}

/// Verifies an ID token against the realm's keys (see [`crate::resource::keys::key_set`]).
///
/// # Errors
/// [`IdTokenError`].
pub fn validate_id_token(
    token: &str,
    keys: &KeySet,
    rules: &IdTokenRules<'_>,
) -> Result<Subject, IdTokenError> {
    let verified = jws::verify_compact(&PureBackend, token, keys, ID_TYP, Origin::Native)
        .map_err(|_| IdTokenError::Signature)?;
    let claims = jws::check_claims(
        &verified.payload,
        &ClaimRules {
            issuer: rules.issuer,
            audience: rules.client_id,
            now: rules.now,
            skew_ms: rules.skew_ms,
        },
    )
    .map_err(|_| IdTokenError::Claims)?;
    // OIDC Core §3.1.3.7 items 4 and 5
    let several = matches!(claims.get("aud"), Some(Json::Array(a)) if a.len() > 1);
    match claims.get("azp").map(Json::as_str) {
        Some(Some(azp)) if azp == rules.client_id => {}
        Some(_) => return Err(IdTokenError::Azp),
        None if several => return Err(IdTokenError::Azp),
        None => {}
    }
    if claims.get("iat").and_then(Json::as_int).is_none() {
        return Err(IdTokenError::Claims);
    }
    if claims.get("nonce").and_then(Json::as_str) != Some(rules.nonce) {
        return Err(IdTokenError::Nonce);
    }
    let sub = claims
        .get("sub")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 255)
        .ok_or(IdTokenError::Sub)?;
    Ok(Subject {
        issuer: String::from(rules.issuer),
        client_id: String::from(rules.client_id),
        sub: String::from(sub),
    })
}
