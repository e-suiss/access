//! Compact JWS and JWT claim checks (CR-55 m.8, m.9, CR-56).

use alloc::vec::Vec;

use super::cose::{Algorithm, KeySet, PublicKey};
use super::{Backend, SignatureError, ed25519, p256};
use crate::json::{self, Json, JsonError, b64url_decode};
use crate::model::TrustedTime;

/// Largest JOSE header accepted, checked before parsing (§14.6).
pub const MAX_HEADER: usize = 2048;
/// Largest JWS payload accepted (§14.6).
pub const MAX_PAYLOAD: usize = 64 * 1024;
/// Largest compact token accepted, checked before decoding.
pub const MAX_TOKEN: usize = 96 * 1024;

/// Who produced the token; Access-native tokens reject high-S ECDSA (CR-9, CR-55 m.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Produced by Access.
    Native,
    /// Produced by an external issuer.
    External,
}

/// A verified compact JWS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Algorithm.
    pub algorithm: Algorithm,
    /// Key identifier.
    pub kid: [u8; 32],
    /// Payload bytes.
    pub payload: Vec<u8>,
}

/// Why a JWS is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JwsError {
    /// Not three dot-separated parts, or too large.
    #[error("not a compact JWS")]
    Format,
    /// A part is not canonical base64url.
    #[error("bad base64url")]
    Base64,
    /// Header is not strict I-JSON.
    #[error("header: {0}")]
    Json(#[from] JsonError),
    /// A header parameter outside `alg`, `kid`, `typ`, or one of them missing.
    #[error("header not in profile")]
    Header,
    /// Algorithm not allowed by metadata, or not a fully-specified one.
    #[error("algorithm not allowed")]
    Algorithm,
    /// No key with this `kid`.
    #[error("unknown kid")]
    UnknownKid,
    /// Key type does not match the algorithm.
    #[error("key type does not match algorithm")]
    KeyType,
    /// `typ` differs from the expected one.
    #[error("unexpected typ")]
    Type,
    /// The signature does not verify.
    #[error("signature: {0}")]
    Signature(#[from] SignatureError),
}

fn algorithm(name: &str) -> Option<Algorithm> {
    match name {
        "Ed25519" => Some(Algorithm::Ed25519),
        "ES256" => Some(Algorithm::Es256),
        "ML-DSA-44" => Some(Algorithm::MlDsa44),
        "ML-DSA-65" => Some(Algorithm::MlDsa65),
        "ML-DSA-87" => Some(Algorithm::MlDsa87),
        _ => None,
    }
}

struct Header {
    alg: Algorithm,
    kid: Option<[u8; 32]>,
    typ: alloc::string::String,
}

fn header(bytes: &[u8]) -> Result<Header, JwsError> {
    let Json::Object(members) = json::parse(bytes, MAX_HEADER)? else {
        return Err(JwsError::Header);
    };
    let (mut alg, mut kid, mut typ) = (None, None, None);
    for (k, v) in &members {
        let s = v.as_str().ok_or(JwsError::Header)?;
        match k.as_str() {
            "alg" => alg = Some(algorithm(s).ok_or(JwsError::Algorithm)?),
            "kid" => {
                let raw = b64url_decode(s).map_err(|_| JwsError::Header)?;
                kid = Some(<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| JwsError::Header)?);
            }
            "typ" => typ = Some(alloc::string::String::from(s)),
            _ => return Err(JwsError::Header),
        }
    }
    Ok(Header {
        alg: alg.ok_or(JwsError::Header)?,
        kid,
        typ: typ.ok_or(JwsError::Header)?,
    })
}

struct Parts<'a> {
    header: Header,
    signing_input: &'a str,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

fn split(token: &str) -> Result<Parts<'_>, JwsError> {
    if token.len() > MAX_TOKEN {
        return Err(JwsError::Format);
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwsError::Format);
    };
    let end = h
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(p.len()))
        .ok_or(JwsError::Format)?;
    Ok(Parts {
        header: header(&b64url_decode(h).map_err(|_| JwsError::Base64)?)?,
        signing_input: token.get(..end).ok_or(JwsError::Format)?,
        payload: b64url_decode(p).map_err(|_| JwsError::Base64)?,
        signature: b64url_decode(s).map_err(|_| JwsError::Base64)?,
    })
}

fn check_signature(
    backend: &impl Backend,
    key: &PublicKey,
    parts: &Parts<'_>,
    origin: Origin,
) -> Result<(), JwsError> {
    let input = parts.signing_input.as_bytes();
    match (key, parts.header.alg) {
        (PublicKey::Ed25519(pk), Algorithm::Ed25519) => {
            ed25519(backend, pk, input, &parts.signature)?;
        }
        (PublicKey::P256(pk), Algorithm::Es256) => p256(
            backend,
            pk,
            input,
            &parts.signature,
            origin == Origin::Native,
        )?,
        _ => return Err(JwsError::KeyType),
    }
    Ok(())
}

/// Verifies a compact JWS whose header has exactly `alg`, `kid` and `typ` (CR-55 m.8, CR-56).
///
/// # Errors
/// [`JwsError`].
pub fn verify_compact(
    backend: &impl Backend,
    token: &str,
    keys: &KeySet,
    typ: &str,
    origin: Origin,
) -> Result<Verified, JwsError> {
    let parts = split(token)?;
    let kid = parts.header.kid.ok_or(JwsError::Header)?;
    if !keys.allowed.contains(&parts.header.alg) || !parts.header.alg.enabled() {
        return Err(JwsError::Algorithm);
    }
    if parts.header.typ != typ {
        return Err(JwsError::Type);
    }
    let key = keys.keys.get(&kid).ok_or(JwsError::UnknownKid)?;
    check_signature(backend, key, &parts, origin)?;
    Ok(Verified {
        algorithm: parts.header.alg,
        kid,
        payload: parts.payload,
    })
}

/// Verifies a compact JWS against one given key; the header has exactly `alg` and `typ`
/// (key binding JWT, RFC 9901 §4.3).
///
/// # Errors
/// [`JwsError`].
pub fn verify_with_key(
    backend: &impl Backend,
    token: &str,
    key: &PublicKey,
    allowed: &alloc::collections::BTreeSet<Algorithm>,
    typ: &str,
) -> Result<Vec<u8>, JwsError> {
    let parts = split(token)?;
    if parts.header.kid.is_some() {
        return Err(JwsError::Header);
    }
    if !allowed.contains(&parts.header.alg) || !parts.header.alg.enabled() {
        return Err(JwsError::Algorithm);
    }
    if parts.header.typ != typ {
        return Err(JwsError::Type);
    }
    check_signature(backend, key, &parts, Origin::External)?;
    Ok(parts.payload)
}

/// Expected issuer and audience, the verifier's time and the artefact class's skew (CR-55 m.9).
#[derive(Clone, Copy, Debug)]
pub struct ClaimRules<'a> {
    /// Expected `iss`.
    pub issuer: &'a str,
    /// This verifier's audience identifier.
    pub audience: &'a str,
    /// Verifier time.
    pub now: TrustedTime,
    /// Clock skew tolerance in milliseconds.
    pub skew_ms: u64,
}

/// Why JWT claims are rejected (CR-56 row 17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClaimError {
    /// Payload is not a JSON object.
    #[error("payload: {0}")]
    Json(#[from] JsonError),
    /// `iss` missing or different.
    #[error("issuer")]
    Issuer,
    /// `aud` missing or not this verifier.
    #[error("audience")]
    Audience,
    /// `exp` missing, or expired.
    #[error("expired")]
    Expired,
    /// Not yet valid (`nbf`) or issued in the future (`iat`).
    #[error("not yet valid")]
    NotYetValid,
    /// A time claim is not an integer, or arithmetic overflowed (OP-108 m.2).
    #[error("bad time claim")]
    Time,
}

fn seconds(ms: u64) -> Result<i64, ClaimError> {
    ms.checked_div(1000)
        .and_then(|s| i64::try_from(s).ok())
        .ok_or(ClaimError::Time)
}

/// Checks `iss`, `aud`, `exp`, `nbf` and `iat` of a JWT payload.
///
/// # Errors
/// [`ClaimError`].
pub fn check_claims(payload: &[u8], rules: &ClaimRules<'_>) -> Result<Json, ClaimError> {
    let claims = json::parse(payload, MAX_PAYLOAD)?;
    check_claims_json(&claims, rules)?;
    Ok(claims)
}

/// [`check_claims`] on an already parsed payload.
///
/// # Errors
/// [`ClaimError`].
pub fn check_claims_json(claims: &Json, rules: &ClaimRules<'_>) -> Result<(), ClaimError> {
    if claims.get("iss").and_then(Json::as_str) != Some(rules.issuer) {
        return Err(ClaimError::Issuer);
    }
    let aud_ok = match claims.get("aud") {
        Some(Json::Str(a)) => a == rules.audience,
        Some(Json::Array(items)) => {
            !items.is_empty() && items.iter().any(|a| a.as_str() == Some(rules.audience))
        }
        _ => false,
    };
    if !aud_ok {
        return Err(ClaimError::Audience);
    }
    let now = seconds(rules.now)?;
    let skew = i64::try_from(rules.skew_ms.checked_div(1000).ok_or(ClaimError::Time)?)
        .map_err(|_| ClaimError::Time)?;
    let time = |name: &str| -> Result<Option<i64>, ClaimError> {
        claims
            .get(name)
            .map(|v| v.as_int().ok_or(ClaimError::Time))
            .transpose()
    };
    let exp = time("exp")?.ok_or(ClaimError::Expired)?;
    if now >= exp.checked_add(skew).ok_or(ClaimError::Time)? {
        return Err(ClaimError::Expired);
    }
    let latest_start = now.checked_add(skew).ok_or(ClaimError::Time)?;
    for name in ["nbf", "iat"] {
        if time(name)?.is_some_and(|t| t > latest_start) {
            return Err(ClaimError::NotYetValid);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
