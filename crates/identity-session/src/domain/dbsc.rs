//! Device Bound Session Credentials (TN-33, IDP-22, OP-153 m.3 (y)), following the W3C draft:
//! a sign-in answer offers registration with `Secure-Session-Registration`; the browser makes a
//! key it cannot export and posts a `dbsc+jwt` proof naming the challenge and its public key;
//! from then on the session is carried only together with a short-lived bound cookie, which the
//! browser renews at the refresh endpoint with a fresh proof from the same key. A browser
//! without DBSC never registers and keeps the plain session (silent fallback).
//!
//! Sans-I/O: parsing and checking the proof, the header values and the session document.

use access_crypto::oauth::{ClientAlg, ClientKey, verify_client_signature};
use access_kernel::json::b64url_decode;
use serde::Deserialize;
use serde_json::{Value, json};

/// The bound cookie: `__Host-`, `Secure`, `HttpOnly`, short-lived.
pub const BOUND_COOKIE: &str = "__Host-access-bound";

/// How long a bound cookie lives before the browser must refresh it (PD).
pub const COOKIE_TTL_MS: u64 = 600_000;

/// How long a registration or refresh challenge stays usable.
pub const CHALLENGE_TTL_MS: u64 = 300_000;

/// The registration endpoint below the realm issuer.
pub const REGISTER_PATH: &str = "/v1/dbsc/register";

/// The refresh endpoint below the realm issuer.
pub const REFRESH_PATH: &str = "/v1/dbsc/refresh";

/// The header a sign-in answer offers registration with.
pub const REGISTRATION_HEADER: &str = "secure-session-registration";

/// The header a proof arrives in.
pub const RESPONSE_HEADER: &str = "secure-session-response";

/// The header a refresh challenge is sent in.
pub const CHALLENGE_HEADER: &str = "secure-session-challenge";

/// The header that names the session at refresh.
pub const SESSION_ID_HEADER: &str = "sec-secure-session-id";

/// Longest proof read.
pub const MAX_PROOF: usize = 4096;

/// Longest `jti` read.
const MAX_JTI: usize = 128;

/// Why a proof is refused. One answer on the wire; the reason stays in logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofError {
    /// Not a compact JWS, or too long.
    #[error("malformed proof")]
    Malformed,
    /// Not `ES256` with `typ` `dbsc+jwt`.
    #[error("unsupported proof algorithm or type")]
    Algorithm,
    /// The key is not a P-256 point.
    #[error("unusable proof key")]
    Key,
    /// The signature does not verify.
    #[error("proof signature does not verify")]
    Signature,
}

/// A parsed proof, not yet checked against a key.
#[derive(Clone, Debug)]
pub struct Proof {
    /// The challenge it answers.
    pub jti: String,
    /// The public key it carries (registration), an uncompressed P-256 point.
    pub key: Option<[u8; 65]>,
    input: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    jwk: Option<Jwk>,
}

#[derive(Deserialize)]
struct Payload {
    jti: String,
    #[serde(default)]
    key: Option<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

fn point(jwk: &Jwk) -> Result<[u8; 65], ProofError> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(ProofError::Key);
    }
    let x = b64url_decode(&jwk.x).map_err(|_| ProofError::Key)?;
    let y = b64url_decode(&jwk.y).map_err(|_| ProofError::Key)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(ProofError::Key);
    }
    let mut out = [0_u8; 65];
    out[0] = 4;
    out[1..33].copy_from_slice(&x);
    out[33..].copy_from_slice(&y);
    Ok(out)
}

/// Parses a compact `dbsc+jwt` proof.
///
/// # Errors
/// [`ProofError`].
pub fn parse(compact: &str) -> Result<Proof, ProofError> {
    if compact.len() > MAX_PROOF {
        return Err(ProofError::Malformed);
    }
    let mut parts = compact.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ProofError::Malformed);
    };
    let header: Header = b64url_decode(h)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(ProofError::Malformed)?;
    if header.alg != "ES256" || header.typ.as_deref() != Some("dbsc+jwt") {
        return Err(ProofError::Algorithm);
    }
    let payload: Payload = b64url_decode(p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(ProofError::Malformed)?;
    if payload.jti.is_empty() || payload.jti.len() > MAX_JTI {
        return Err(ProofError::Malformed);
    }
    let key = payload
        .key
        .as_ref()
        .or(header.jwk.as_ref())
        .map(point)
        .transpose()?;
    let signature = b64url_decode(s).map_err(|_| ProofError::Malformed)?;
    let input_len = h.len().saturating_add(1).saturating_add(p.len());
    let input = compact
        .get(..input_len)
        .ok_or(ProofError::Malformed)?
        .as_bytes()
        .to_vec();
    Ok(Proof {
        jti: payload.jti,
        key,
        input,
        signature,
    })
}

impl Proof {
    /// Checks the signature with `key`.
    ///
    /// # Errors
    /// [`ProofError::Signature`].
    pub fn verify(&self, key: &[u8; 65]) -> Result<(), ProofError> {
        verify_client_signature(
            ClientAlg::Es256,
            &ClientKey::P256(key.to_vec()),
            &self.input,
            &self.signature,
        )
        .map_err(|_| ProofError::Signature)
    }
}

/// The `Secure-Session-Registration` value: ES256 only, the realm's endpoint and the challenge.
#[must_use]
pub fn registration(base: &str, challenge: &str) -> String {
    format!("(ES256);path=\"{base}{REGISTER_PATH}\";challenge=\"{challenge}\"")
}

/// The `Secure-Session-Challenge` value for session `id`.
#[must_use]
pub fn challenge(challenge: &str, id: &str) -> String {
    format!("\"{challenge}\";id=\"{id}\"")
}

/// The session instructions the browser keeps: the refresh endpoint, the scope (the realm's
/// origin) and the one bound cookie.
#[must_use]
pub fn session_config(id: &str, origin: &str, base: &str) -> Value {
    json!({
        "session_identifier": id,
        "refresh_url": format!("{base}{REFRESH_PATH}"),
        "scope": {
            "origin": origin,
            "include_site": false,
            "scope_specification": [],
        },
        "credentials": [{
            "type": "cookie",
            "name": BOUND_COOKIE,
            "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax",
        }],
    })
}

/// The session cookie and the bound cookie as the request carried them: the hosted surface
/// passes `session.bound` when both came.
#[must_use]
pub fn split_cookie(cookie: &str) -> (&str, Option<&str>) {
    match cookie.split_once('.') {
        Some((session, bound)) => (session, Some(bound)),
        None => (cookie, None),
    }
}

/// Whether a session tied to a key may be used with `bound`: its digest must be the stored one
/// and not past its end. An untied session needs no bound cookie.
#[must_use]
pub fn bound_ok(
    tied: bool,
    stored: Option<(&[u8], i64)>,
    presented: Option<[u8; 32]>,
    now_ms: u64,
) -> bool {
    if !tied {
        return true;
    }
    let (Some((digest, expires_ms)), Some(presented)) = (stored, presented) else {
        return false;
    };
    let live = i64::try_from(now_ms).is_ok_and(|n| n < expires_ms);
    live && access_crypto::Secret::new(presented).ct_eq_bytes(digest)
}

#[cfg(test)]
mod tests;
