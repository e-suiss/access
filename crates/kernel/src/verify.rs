//! Signature verification: Kernel pre-checks in front of a provider backend (CR-9, CR-53…CR-55).

pub mod cose;
pub mod jws;
pub mod sd_jwt;

use curve25519_dalek::Scalar;
use curve25519_dalek::edwards::CompressedEdwardsY;

/// A verification provider. The Kernel runs every pre-check first, so a backend only answers
/// the equation (CR-53, CR-54).
pub trait Backend {
    /// Ed25519 verification of an already pre-checked key and signature.
    fn ed25519(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool;

    /// ECDSA P-256 with SHA-256 over `message`; `signature` is `r ‖ s`.
    fn p256(&self, public_key_sec1: &[u8], message: &[u8], signature: &[u8; 64]) -> bool;
}

/// Pure-Rust backend for the `no_std` Kernel, Wasm and mobile (CR-54, CR-55 m.1).
#[derive(Clone, Copy, Debug, Default)]
pub struct PureBackend;

impl Backend for PureBackend {
    fn ed25519(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        key.verify_strict(message, &sig).is_ok()
    }

    fn p256(&self, public_key_sec1: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
        use p256::ecdsa::signature::Verifier as _;
        let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_sec1) else {
            return false;
        };
        let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) else {
            return false;
        };
        key.verify(message, &sig).is_ok()
    }
}

/// Why a signature is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// Signature or key has the wrong length.
    #[error("wrong length")]
    Length,
    /// Public key is not a canonical point encoding.
    #[error("non-canonical public key")]
    NonCanonicalKey,
    /// `R` is not a canonical point encoding.
    #[error("non-canonical R")]
    NonCanonicalR,
    /// `S ≥ L`.
    #[error("S not reduced")]
    UnreducedS,
    /// Public key of small order.
    #[error("small-order public key")]
    SmallOrderKey,
    /// `R` of small order.
    #[error("small-order R")]
    SmallOrderR,
    /// ECDSA `r` or `s` outside `1..n`.
    #[error("ECDSA scalar out of range")]
    ScalarRange,
    /// High-S ECDSA signature on an Access-native artefact (CR-9).
    #[error("high-S signature")]
    HighS,
    /// The equation does not hold.
    #[error("invalid signature")]
    Invalid,
}

fn canonical_point(bytes: &[u8; 32]) -> Option<curve25519_dalek::EdwardsPoint> {
    let point = CompressedEdwardsY(*bytes).decompress()?;
    (point.compress().as_bytes() == bytes).then_some(point)
}

/// CR-53 pre-checks: canonical `A`, `R`, `S`; `S < L`; `A` and `R` not of small order.
///
/// # Errors
/// The first failed check.
pub fn ed25519_precheck(public_key: &[u8; 32], signature: &[u8; 64]) -> Result<(), SignatureError> {
    let (r, s) = signature.split_at(32);
    let r: &[u8; 32] = r.try_into().map_err(|_| SignatureError::Length)?;
    let s: [u8; 32] = s.try_into().map_err(|_| SignatureError::Length)?;
    let a = canonical_point(public_key).ok_or(SignatureError::NonCanonicalKey)?;
    let r_point = canonical_point(r).ok_or(SignatureError::NonCanonicalR)?;
    if Option::<Scalar>::from(Scalar::from_canonical_bytes(s)).is_none() {
        return Err(SignatureError::UnreducedS);
    }
    if a.is_small_order() {
        return Err(SignatureError::SmallOrderKey);
    }
    if r_point.is_small_order() {
        return Err(SignatureError::SmallOrderR);
    }
    Ok(())
}

/// Ed25519 under CR-53: pre-checks, then the backend's cofactorless equation.
///
/// # Errors
/// [`SignatureError`].
pub fn ed25519(
    backend: &impl Backend,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let pk: &[u8; 32] = public_key.try_into().map_err(|_| SignatureError::Length)?;
    let sig: &[u8; 64] = signature.try_into().map_err(|_| SignatureError::Length)?;
    ed25519_precheck(pk, sig)?;
    if backend.ed25519(pk, message, sig) {
        Ok(())
    } else {
        Err(SignatureError::Invalid)
    }
}

const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const P256_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

fn in_scalar_range(x: &[u8]) -> bool {
    x.iter().any(|b| *b != 0) && x < P256_N.as_slice()
}

/// ECDSA P-256 / SHA-256 with a raw `r ‖ s` signature (CR-55 m.1, CR-56 rows 12–13).
/// `native` rejects high-S (Access-native artefacts, CR-9).
///
/// # Errors
/// [`SignatureError`].
pub fn p256(
    backend: &impl Backend,
    public_key_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
    native: bool,
) -> Result<(), SignatureError> {
    let sig: &[u8; 64] = signature.try_into().map_err(|_| SignatureError::Length)?;
    let (r, s) = sig.split_at(32);
    if !in_scalar_range(r) || !in_scalar_range(s) {
        return Err(SignatureError::ScalarRange);
    }
    if native && s > P256_HALF_N.as_slice() {
        return Err(SignatureError::HighS);
    }
    if backend.p256(public_key_sec1, message, sig) {
        Ok(())
    } else {
        Err(SignatureError::Invalid)
    }
}

#[cfg(test)]
mod tests;
