//! ML-DSA verification over the provider port (CR-41, L0-SIG-8, OP-159 m.3 (c)). The layer
//! is the Kernel's: header, key and length checks run here, and only the equation is the
//! backend's. A backend without ML-DSA rejects every ML-DSA signature with `algorithm`.

use alloc::string::String;

use suiss_crypto::cose::{
    self as shared, ALG, CONTENT_TYPE, CRIT, CoseError, KID, KeySet, PublicKey, Verified,
};
use suiss_crypto::dcbor::{self, Limits, Value};

use super::cose::Algorithm;
use super::{Backend, SignatureError};

/// Whether `alg` is an ML-DSA parameter set.
#[must_use]
pub const fn is_ml_dsa(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87
    )
}

/// The public key length of an ML-DSA parameter set (FIPS 204 Table 2).
#[must_use]
pub const fn key_length(alg: Algorithm) -> Option<usize> {
    match alg {
        Algorithm::MlDsa44 => Some(1312),
        Algorithm::MlDsa65 => Some(1952),
        Algorithm::MlDsa87 => Some(2592),
        _ => None,
    }
}

/// The signature length of an ML-DSA parameter set (FIPS 204 Table 2).
#[must_use]
pub const fn signature_length(alg: Algorithm) -> Option<usize> {
    match alg {
        Algorithm::MlDsa44 => Some(2420),
        Algorithm::MlDsa65 => Some(3309),
        Algorithm::MlDsa87 => Some(4627),
        _ => None,
    }
}

/// Pure ML-DSA with the empty context over `message` (L0-SIG-8): exact lengths first, then the
/// backend's equation.
///
/// # Errors
/// [`SignatureError::Length`] or [`SignatureError::Invalid`].
pub fn signature(
    backend: &impl Backend,
    alg: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let (Some(k), Some(s)) = (key_length(alg), signature_length(alg)) else {
        return Err(SignatureError::Invalid);
    };
    if public_key.len() != k || signature.len() != s {
        return Err(SignatureError::Length);
    }
    if backend.ml_dsa(alg, public_key, message, signature) {
        Ok(())
    } else {
        Err(SignatureError::Invalid)
    }
}

struct Header {
    alg: Algorithm,
    kid: [u8; 32],
    content_type: String,
}

// L0-SIG-11, L0-SIG-13
fn header(bytes: &[u8]) -> Result<Header, CoseError> {
    let Value::Map(entries) = dcbor::decode(bytes, Limits::CEILING)? else {
        return Err(CoseError::Header);
    };
    let (mut alg, mut kid, mut ct) = (None, None, None);
    for (k, v) in &entries {
        match (k, v) {
            (Value::Unsigned(CRIT), _) => return Err(CoseError::Crit),
            (Value::Unsigned(ALG), v) => {
                alg = Some(
                    v.as_i64()
                        .and_then(Algorithm::from_cose)
                        .ok_or(CoseError::Algorithm)?,
                );
            }
            (Value::Unsigned(KID), Value::Bytes(b)) => {
                kid = Some(<[u8; 32]>::try_from(b.as_slice()).map_err(|_| CoseError::Header)?);
            }
            (Value::Unsigned(CONTENT_TYPE), Value::Text(t)) => ct = Some(t.clone()),
            _ => return Err(CoseError::Header),
        }
    }
    Ok(Header {
        alg: alg.ok_or(CoseError::Header)?,
        kid: kid.ok_or(CoseError::Header)?,
        content_type: ct.ok_or(CoseError::Header)?,
    })
}

/// [`shared::verify_sign1_with`] that also verifies ML-DSA through the backend (L0-SIG-8,
/// L0-SIG-10…L0-SIG-17). A classical algorithm takes the shared path unchanged.
///
/// # Errors
/// [`CoseError`].
pub fn verify_sign1_with(
    backend: &impl Backend,
    bytes: &[u8],
    detached: Option<&[u8]>,
    keys: &KeySet,
    content_type: &str,
    native: bool,
) -> Result<Verified, CoseError> {
    let msg = shared::parse_sign1(bytes)?;
    let h = match header(&msg.protected) {
        Ok(h) if is_ml_dsa(h.alg) => h,
        _ => {
            return shared::verify_sign1_with(backend, bytes, detached, keys, content_type, native);
        }
    };
    let payload = match (&msg.payload, detached) {
        (Some(p), None) => p.as_slice(),
        (None, Some(p)) => p,
        _ => return Err(CoseError::Payload),
    };
    if !keys.allowed.contains(&h.alg) || !backend.supports(h.alg) {
        return Err(CoseError::Algorithm);
    }
    if h.content_type != content_type {
        return Err(CoseError::ContentType);
    }
    let key = keys.keys.get(&h.kid).ok_or(CoseError::UnknownKid)?;
    let PublicKey::MlDsa(a, pk) = key else {
        return Err(CoseError::KeyType);
    };
    if *a != h.alg {
        return Err(CoseError::KeyType);
    }
    let tbs = shared::to_be_signed(&msg.protected, payload)?;
    signature(backend, h.alg, pk, &tbs, &msg.signature)?;
    Ok(Verified {
        algorithm: h.alg,
        kid: h.kid,
        payload: payload.to_vec(),
    })
}

/// [`verify_sign1_with`] for an attached payload signed by the producer itself (CR-9).
///
/// # Errors
/// [`CoseError`].
pub fn verify_sign1(
    backend: &impl Backend,
    bytes: &[u8],
    keys: &KeySet,
    content_type: &str,
) -> Result<Verified, CoseError> {
    verify_sign1_with(backend, bytes, None, keys, content_type, true)
}

/// [`verify_sign1`] for a detached payload.
///
/// # Errors
/// [`CoseError`].
pub fn verify_sign1_detached(
    backend: &impl Backend,
    bytes: &[u8],
    payload: &[u8],
    keys: &KeySet,
    content_type: &str,
) -> Result<Verified, CoseError> {
    verify_sign1_with(backend, bytes, Some(payload), keys, content_type, true)
}

/// The algorithm a `COSE_Sign1` names, without verifying it.
///
/// # Errors
/// [`CoseError`].
pub fn algorithm_of(bytes: &[u8]) -> Result<Algorithm, CoseError> {
    Ok(header(&shared::parse_sign1(bytes)?.protected)?.alg)
}

/// The two `COSE_Sign1` of a hybrid artefact must sign the same payload (CR-42 m.4, INV-27).
#[must_use]
pub fn same_payload(classic: &Verified, pq: &Verified) -> bool {
    classic.payload == pq.payload
}

#[cfg(test)]
mod tests;
