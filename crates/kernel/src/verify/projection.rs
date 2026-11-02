//! Profile checks of authority projections in JOSE containers (§9.9.1, §9.9.3, §9.10,
//! OP-143 m.6 (a)): the RFC 9068 access token whose authority is in RFC 9396
//! `authorization_details`, and the SD-JWT container of a PAP.

use alloc::string::String;

use super::Backend;
use super::cose::KeySet;
use super::jws::{self, ClaimError, ClaimRules, JwsError, MAX_PAYLOAD, Origin, verify_compact};
use super::sd_jwt::{self, SdJwtError};
use crate::digest::Digest;
use crate::json::{self, Json, JsonError, b64url_decode, b64url_encode};
use crate::model::TrustedTime;

/// `typ` of an access token projection (RFC 9068).
pub const ACCESS_TOKEN_TYP: &str = "at+jwt";

/// `typ` of the issuer-signed JWT of a PAP in its SD-JWT container.
pub const PAP_TYP: &str = "access-pap+sd-jwt";

/// The text form of a digest, `sha-256:<base64url>` (L0-ENC-20).
#[must_use]
pub fn digest_text(digest: &Digest) -> String {
    let mut out = String::from("sha-256:");
    out.push_str(&b64url_encode(&digest.0));
    out
}

/// How an access token is bound to its holder; bearer tokens do not exist (§9.9.3 rule 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirmation {
    /// `DPoP`: the RFC 7638 thumbprint of the holder key (`cnf.jkt`, RFC 9449).
    Jkt([u8; 32]),
    /// mTLS: the SHA-256 of the client certificate (`cnf.x5t#S256`, RFC 8705).
    X5tS256([u8; 32]),
}

impl Confirmation {
    /// The `cnf` member name.
    #[must_use]
    pub const fn member(&self) -> &'static str {
        match self {
            Self::Jkt(_) => "jkt",
            Self::X5tS256(_) => "x5t#S256",
        }
    }

    /// The thumbprint.
    #[must_use]
    pub const fn thumbprint(&self) -> &[u8; 32] {
        match self {
            Self::Jkt(t) | Self::X5tS256(t) => t,
        }
    }
}

/// The RAR `kind` of an access token (§9.13.5); the two never mix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Exact-intent token: one intent.
    Intent,
    /// Bounds token.
    Bounds,
}

/// What the resource server expects of an access token.
#[derive(Clone, Copy, Debug)]
pub struct AccessTokenRules<'a> {
    /// Expected `iss`.
    pub issuer: &'a str,
    /// This resource server, the token's only audience (RFC 8707).
    pub audience: &'a str,
    /// The domain whose authority the token projects (§9.9.3 rule 7, TI-RT6).
    pub domain: &'a Digest,
    /// The key or certificate the request was made with.
    pub confirmation: &'a Confirmation,
    /// Verifier time.
    pub now: TrustedTime,
    /// Clock skew in milliseconds.
    pub skew_ms: u64,
}

/// A verified access token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessToken {
    /// The verified JWS.
    pub token: jws::Verified,
    /// Its claims.
    pub claims: Json,
    /// Its authority kind.
    pub kind: Kind,
}

/// Why a projection is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionError {
    /// The JWS is rejected.
    #[error("jws: {0}")]
    Jws(#[from] JwsError),
    /// The SD-JWT presentation is rejected.
    #[error("sd-jwt: {0}")]
    SdJwt(#[from] SdJwtError),
    /// The payload is not strict I-JSON.
    #[error("payload: {0}")]
    Json(#[from] JsonError),
    /// `iss`, `aud` or a time claim is rejected.
    #[error("claims: {0}")]
    Claims(#[from] ClaimError),
    /// A required member is missing or has the wrong type.
    #[error("member {0}")]
    Member(&'static str),
    /// `cnf` is not exactly one confirmation, or not the presented one.
    #[error("confirmation")]
    Confirmation,
    /// `authorization_details` is empty, mixes kinds or carries more than one intent.
    #[error("authority")]
    Authority,
    /// The projection names another domain.
    #[error("domain")]
    Domain,
    /// The PAP is presented without holder binding.
    #[error("holder")]
    Holder,
}

impl ProjectionError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Jws(_) => "projection-jws",
            Self::SdJwt(_) => "projection-sd-jwt",
            Self::Json(_) => "projection-json",
            Self::Claims(_) => "projection-claims",
            Self::Member(_) => "projection-member",
            Self::Confirmation => "projection-confirmation",
            Self::Authority => "projection-authority",
            Self::Domain => "projection-domain",
            Self::Holder => "projection-holder",
        }
    }
}

fn text<'a>(claims: &'a Json, name: &'static str) -> Result<&'a str, ProjectionError> {
    claims
        .get(name)
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(ProjectionError::Member(name))
}

fn confirmation(claims: &Json, expected: &Confirmation) -> Result<(), ProjectionError> {
    let Some(Json::Object(members)) = claims.get("cnf") else {
        return Err(ProjectionError::Member("cnf"));
    };
    let [(name, Json::Str(value))] = members.as_slice() else {
        return Err(ProjectionError::Confirmation);
    };
    let raw = b64url_decode(value).map_err(|_| ProjectionError::Confirmation)?;
    if name != expected.member() || raw.as_slice() != expected.thumbprint() {
        return Err(ProjectionError::Confirmation);
    }
    Ok(())
}

fn authority(claims: &Json, domain: &str) -> Result<Kind, ProjectionError> {
    let Some(Json::Array(details)) = claims.get("authorization_details") else {
        return Err(ProjectionError::Member("authorization_details"));
    };
    let mut kind = None;
    for detail in details {
        if !matches!(detail, Json::Object(_)) {
            return Err(ProjectionError::Authority);
        }
        text(detail, "type")?;
        let this = match text(detail, "kind")? {
            "intent" => Kind::Intent,
            "bounds" => Kind::Bounds,
            _ => return Err(ProjectionError::Authority),
        };
        if kind.is_some_and(|k| k != this) {
            return Err(ProjectionError::Authority);
        }
        kind = Some(this);
        if text(detail, "domain")? != domain {
            return Err(ProjectionError::Domain);
        }
        if !matches!(detail.get("validity"), Some(Json::Object(_))) {
            return Err(ProjectionError::Member("validity"));
        }
    }
    match kind {
        Some(Kind::Intent) if details.len() != 1 => Err(ProjectionError::Authority),
        Some(k) => Ok(k),
        None => Err(ProjectionError::Authority),
    }
}

/// Verifies an access token projection (§9.9, §9.9.3 rules 1, 2, 3, 7; RFC 9068): a native
/// `at+jwt` JWS, one string `aud`, `sub`, `iat`, `jti`, `client_id`, the presented `cnf`, and
/// `authorization_details` of one kind naming this domain.
///
/// # Errors
/// [`ProjectionError`].
pub fn verify_access_token(
    backend: &impl Backend,
    token: &str,
    keys: &KeySet,
    rules: &AccessTokenRules<'_>,
) -> Result<AccessToken, ProjectionError> {
    let verified = verify_compact(backend, token, keys, ACCESS_TOKEN_TYP, Origin::Native)?;
    let claims = json::parse(&verified.payload, MAX_PAYLOAD)?;
    if !matches!(claims, Json::Object(_)) {
        return Err(ProjectionError::Member("payload"));
    }
    // §9.9.3 rule 1
    if !matches!(claims.get("aud"), Some(Json::Str(_))) {
        return Err(ClaimError::Audience.into());
    }
    jws::check_claims_json(
        &claims,
        &ClaimRules {
            issuer: rules.issuer,
            audience: rules.audience,
            now: rules.now,
            skew_ms: rules.skew_ms,
        },
    )?;
    if claims.get("iat").and_then(Json::as_int).is_none() {
        return Err(ProjectionError::Member("iat"));
    }
    for name in ["sub", "jti", "client_id"] {
        text(&claims, name)?;
    }
    // §9.9.3 rule 2
    confirmation(&claims, rules.confirmation)?;
    // §9.9.3 rule 3, §9.13.5
    let kind = authority(&claims, &digest_text(rules.domain))?;
    Ok(AccessToken {
        token: verified,
        claims,
        kind,
    })
}

/// Verifies a PAP presented in its SD-JWT container (OP-143 m.6 (a), L0-SIG-50…52): the
/// presentation under `rules` with `typ` [`PAP_TYP`], holder-bound, `iss` the domain's text
/// form, and the PAP members present. The rest of L2-PAP-3 is the caller's.
///
/// # Errors
/// [`ProjectionError`].
pub fn verify_pap_sd_jwt(
    backend: &impl Backend,
    presentation: &str,
    keys: &KeySet,
    rules: &sd_jwt::Rules<'_>,
    domain: &Digest,
) -> Result<sd_jwt::Verified, ProjectionError> {
    let rules = sd_jwt::Rules {
        typ: PAP_TYP,
        ..*rules
    };
    let verified = sd_jwt::verify(backend, presentation, keys, &rules, Origin::Native)?;
    if !verified.holder_bound {
        return Err(ProjectionError::Holder);
    }
    if text(&verified.claims, "iss")? != digest_text(domain) {
        return Err(ProjectionError::Domain);
    }
    if verified.claims.get("iat").and_then(Json::as_int).is_none() {
        return Err(ProjectionError::Member("iat"));
    }
    for name in ["projection_exercise", "lineage_commitment"] {
        text(&verified.claims, name)?;
    }
    for name in ["holder", "bounds", "validity"] {
        if !matches!(verified.claims.get(name), Some(Json::Object(_))) {
            return Err(ProjectionError::Member(name));
        }
    }
    if verified.claims.get("capacity").is_none() {
        return Err(ProjectionError::Member("capacity"));
    }
    Ok(verified)
}

#[cfg(test)]
mod tests;
