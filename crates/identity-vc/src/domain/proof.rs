//! The holder's key proof (OID4VCI 1.0 §8.2.1.1, `openid4vci-proof+jwt`): signed by the key the
//! credential will be bound to, for this issuer and this `c_nonce`, recently. A device holder
//! names its P-256 key in the header `jwk`; an agent holder signs with the key its `KeyBinding`
//! already names, and no other key is accepted for it.

use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::model::TrustedTime;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::{Backend, ed25519, p256};

use crate::domain::metadata::PROOF_TYP;

/// How old a proof may be, milliseconds.
pub const MAX_AGE_MS: u64 = 5 * 60 * 1000;
/// Clock skew, milliseconds.
pub const SKEW_MS: u64 = 60_000;
/// Largest proof.
pub const MAX_PROOF: usize = 8 * 1024;

/// The key the credential is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Holder {
    /// The holder's device: the key in the proof's `jwk`.
    Device,
    /// An agent: the key its `KeyBinding` names.
    KeyBinding(PublicKey),
}

/// What the proof must say.
#[derive(Clone, Copy, Debug)]
pub struct Expect<'a> {
    /// The credential issuer (`aud`).
    pub issuer: &'a str,
    /// The `c_nonce` the issuer gave.
    pub nonce: &'a str,
    /// Issuer time, milliseconds.
    pub now: TrustedTime,
}

/// Why a proof is refused (OID4VCI 1.0 `invalid_proof`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// Not a JWS in the profile.
    #[error("invalid-proof")]
    Malformed,
    /// The key is not the holder's, or the signature does not verify.
    #[error("invalid-proof-key")]
    Key,
    /// `aud`, `nonce` or `iat` wrong.
    #[error("invalid-nonce")]
    Claims,
}

fn jwk_key(jwk: &Json) -> Option<PublicKey> {
    let field = |n: &str| {
        jwk.get(n)
            .and_then(Json::as_str)
            .and_then(|s| b64url_decode(s).ok())
    };
    if jwk.get("d").is_some() {
        return None;
    }
    let key = match (
        jwk.get("kty").and_then(Json::as_str),
        jwk.get("crv").and_then(Json::as_str),
    ) {
        (Some("EC"), Some("P-256")) => {
            let (x, y) = (field("x")?, field("y")?);
            if x.len() != 32 || y.len() != 32 {
                return None;
            }
            PublicKey::P256([&[0x04][..], &x, &y].concat())
        }
        (Some("OKP"), Some("Ed25519")) => {
            PublicKey::Ed25519(<[u8; 32]>::try_from(field("x")?.as_slice()).ok()?)
        }
        _ => return None,
    };
    key.check().ok()?;
    Some(key)
}

fn millis(v: Option<&Json>) -> Option<u64> {
    u64::try_from(v?.as_int()?).ok()?.checked_mul(1000)
}

/// Verifies a key proof and answers the key to bind.
///
/// # Errors
/// [`ProofError`].
pub fn verify(
    backend: &impl Backend,
    jwt: &str,
    holder: &Holder,
    expect: &Expect<'_>,
) -> Result<PublicKey, ProofError> {
    if jwt.len() > MAX_PROOF {
        return Err(ProofError::Malformed);
    }
    let mut parts = jwt.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ProofError::Malformed);
    };
    let header = json::parse(&b64url_decode(h).map_err(|_| ProofError::Malformed)?, 4096)
        .map_err(|_| ProofError::Malformed)?;
    let Json::Object(members) = &header else {
        return Err(ProofError::Malformed);
    };
    if members
        .iter()
        .any(|(k, _)| !matches!(k.as_str(), "alg" | "typ" | "jwk"))
        || header.get("typ").and_then(Json::as_str) != Some(PROOF_TYP)
    {
        return Err(ProofError::Malformed);
    }
    let named = header
        .get("jwk")
        .map(|j| jwk_key(j).ok_or(ProofError::Key))
        .transpose()?;
    let key = match (holder, named) {
        (Holder::Device, Some(k @ PublicKey::P256(_))) => k,
        (Holder::KeyBinding(bound), None) => bound.clone(),
        (Holder::KeyBinding(bound), Some(k)) if k == *bound => k,
        _ => return Err(ProofError::Key),
    };
    let input = jwt
        .get(..h.len().saturating_add(1).saturating_add(p.len()))
        .ok_or(ProofError::Malformed)?;
    let sig = b64url_decode(s).map_err(|_| ProofError::Malformed)?;
    let ok = match (&key, header.get("alg").and_then(Json::as_str)) {
        (PublicKey::P256(sec1), Some("ES256")) => {
            p256(backend, sec1, input.as_bytes(), &sig, false).is_ok()
        }
        (PublicKey::Ed25519(pk), Some("Ed25519" | "EdDSA")) => {
            ed25519(backend, pk, input.as_bytes(), &sig).is_ok()
        }
        _ => false,
    };
    if !ok {
        return Err(ProofError::Key);
    }
    let claims = json::parse(&b64url_decode(p).map_err(|_| ProofError::Malformed)?, 4096)
        .map_err(|_| ProofError::Malformed)?;
    let aud_ok = match claims.get("aud") {
        Some(Json::Str(a)) => a == expect.issuer,
        Some(Json::Array(items)) => items.iter().any(|a| a.as_str() == Some(expect.issuer)),
        _ => false,
    };
    let iat = millis(claims.get("iat")).ok_or(ProofError::Claims)?;
    let earliest = expect
        .now
        .saturating_sub(MAX_AGE_MS.saturating_add(SKEW_MS));
    if !aud_ok
        || claims.get("nonce").and_then(Json::as_str) != Some(expect.nonce)
        || iat < earliest
        || iat > expect.now.saturating_add(SKEW_MS)
    {
        return Err(ProofError::Claims);
    }
    Ok(key)
}
