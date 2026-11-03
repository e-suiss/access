//! WebAuthn relying-party primitives on aws-lc-rs (OP-146 m.3): assertion signature checks under
//! the CR-9 acceptance profile for external signatures, and the realm key that derives
//! deterministic decoy credential IDs (TN-97, CR-3 (a)).

use std::fmt::Write as _;

use aws_lc_rs::digest;
#[cfg(any(test, feature = "testing"))]
use aws_lc_rs::hmac;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ParsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents,
};
use suiss_crypto::pkcs11::{HsmError, HsmMac};
use suiss_crypto::sig::{self, SignatureError};

use crate::AwsLcBackend;
#[cfg(any(test, feature = "testing"))]
use crate::dit::DitGuard;
#[cfg(any(test, feature = "testing"))]
use crate::secret::Secret;

/// Why a WebAuthn signature or key is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The ECDSA signature is not strict DER.
    #[error("malformed ECDSA signature")]
    Der,
    /// The RSA key is outside 2048–8192 bits or has an invalid exponent (CR-9 m.5).
    #[error("unacceptable RSA key")]
    RsaKey,
    /// A CR-9 pre-check or the equation failed.
    #[error(transparent)]
    Signature(#[from] SignatureError),
}

impl VerifyError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Der => "signature-der",
            Self::RsaKey => "signature-rsa-key",
            Self::Signature(e) => e.code(),
        }
    }
}

/// SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, data).as_ref());
    out
}

/// Whether `sec1` is an uncompressed point on P-256.
#[must_use]
pub fn p256_point_valid(sec1: &[u8]) -> bool {
    sec1.len() == 65 && ParsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, sec1).is_ok()
}

fn der_integer(input: &[u8]) -> Result<([u8; 32], &[u8]), VerifyError> {
    let (&tag, rest) = input.split_first().ok_or(VerifyError::Der)?;
    let (&len, rest) = rest.split_first().ok_or(VerifyError::Der)?;
    let len = usize::from(len);
    if tag != 0x02 || len == 0 || len > 33 {
        return Err(VerifyError::Der);
    }
    let body = rest.get(..len).ok_or(VerifyError::Der)?;
    let tail = rest.get(len..).ok_or(VerifyError::Der)?;
    let first = *body.first().ok_or(VerifyError::Der)?;
    if first & 0x80 != 0 {
        return Err(VerifyError::Der);
    }
    let digits = if body == [0] {
        &[]
    } else if first == 0 {
        let second = *body.get(1).ok_or(VerifyError::Der)?;
        if second & 0x80 == 0 {
            return Err(VerifyError::Der);
        }
        body.get(1..).ok_or(VerifyError::Der)?
    } else {
        body
    };
    let pad = 32_usize.checked_sub(digits.len()).ok_or(VerifyError::Der)?;
    let mut out = [0; 32];
    out.get_mut(pad..)
        .ok_or(VerifyError::Der)?
        .copy_from_slice(digits);
    Ok((out, tail))
}

/// Strict DER `ECDSA-Sig-Value` to `r ‖ s`.
///
/// # Errors
/// [`VerifyError::Der`].
pub fn ecdsa_der_to_fixed(der: &[u8]) -> Result<[u8; 64], VerifyError> {
    let (&tag, rest) = der.split_first().ok_or(VerifyError::Der)?;
    let (&len, body) = rest.split_first().ok_or(VerifyError::Der)?;
    if tag != 0x30 || len & 0x80 != 0 || usize::from(len) != body.len() {
        return Err(VerifyError::Der);
    }
    let (r, rest) = der_integer(body)?;
    let (s, rest) = der_integer(rest)?;
    if !rest.is_empty() {
        return Err(VerifyError::Der);
    }
    let mut out = [0; 64];
    out.get_mut(..32)
        .ok_or(VerifyError::Der)?
        .copy_from_slice(&r);
    out.get_mut(32..)
        .ok_or(VerifyError::Der)?
        .copy_from_slice(&s);
    Ok(out)
}

/// ES256 / ESP256 with a DER signature. High-S is accepted: WebAuthn assertions are external
/// signatures and replay protection rests on the single-use challenge (CR-9 m.4).
///
/// # Errors
/// [`VerifyError`].
pub fn verify_es256(sec1: &[u8], message: &[u8], der: &[u8]) -> Result<(), VerifyError> {
    let fixed = ecdsa_der_to_fixed(der)?;
    sig::p256(&AwsLcBackend, sec1, message, &fixed, false)?;
    Ok(())
}

/// Ed25519 under the CR-9 m.1 / CR-53 pre-checks.
///
/// # Errors
/// [`VerifyError`].
pub fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    sig::ed25519(&AwsLcBackend, public_key, message, signature)?;
    Ok(())
}

fn significant(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes.get(start..).unwrap_or_default()
}

/// Whether `n`, `e` form an acceptable RSA key: 2048–8192-bit modulus, odd exponent ≥ 3 (CR-9 m.5).
#[must_use]
pub fn rsa_key_valid(n: &[u8], e: &[u8]) -> bool {
    let n = significant(n);
    let e = significant(e);
    let bits = n.first().map_or(0, |top| {
        n.len()
            .saturating_sub(1)
            .saturating_mul(8)
            .saturating_add(usize::from(
                8_u8.saturating_sub(top.leading_zeros().try_into().unwrap_or(8)),
            ))
    });
    let odd = e.last().is_some_and(|b| b & 1 == 1);
    let at_least_three = e.len() > 1 || e.first().is_some_and(|b| *b >= 3);
    (2048..=8192).contains(&bits) && e.len() <= 8 && odd && at_least_three
}

/// RS256 (RSASSA-PKCS1-v1_5, SHA-256); legacy authenticators only (§10.2.4).
///
/// # Errors
/// [`VerifyError`].
pub fn verify_rs256(
    n: &[u8],
    e: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    if !rsa_key_valid(n, e) {
        return Err(VerifyError::RsaKey);
    }
    RsaPublicKeyComponents {
        n: significant(n),
        e: significant(e),
    }
    .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
    .map_err(|_| VerifyError::Signature(SignatureError::Invalid))
}

const DECOY_CONTEXT: &[u8] = b"access/webauthn-decoy/v1\0";

/// The token label of a realm's decoy key: `access/webauthn-decoy/<RealmID hex>`.
#[must_use]
pub fn decoy_label(realm: &[u8; 16]) -> String {
    let mut out = String::from("access/webauthn-decoy/");
    for b in realm {
        let _ = write!(out, "{b:02x}");
    }
    out
}

enum Key {
    Token(HsmMac),
    #[cfg(any(test, feature = "testing"))]
    Memory(Secret<[u8; 32]>),
}

/// A realm's key for decoy credential IDs: unknown identifiers get stable, plausible
/// `allowCredentials` lists so the answer does not reveal whether an account exists (TN-97).
pub struct DecoyKey(Key);

impl DecoyKey {
    /// The key inside the token.
    #[must_use]
    pub const fn token(mac: HsmMac) -> Self {
        Self(Key::Token(mac))
    }

    /// An in-process key with the same output as the token's, for tests.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn new(key: Secret<[u8; 32]>) -> Self {
        Self(Key::Memory(key))
    }

    /// `HMAC-SHA-256(K_r, "access/webauthn-decoy/v1" ‖ 0x00 ‖ input)`.
    ///
    /// # Errors
    /// [`HsmError`] when the token refuses.
    pub fn derive(&self, input: &[u8]) -> Result<[u8; 32], HsmError> {
        let mut message = DECOY_CONTEXT.to_vec();
        message.extend_from_slice(input);
        match &self.0 {
            Key::Token(mac) => mac.mac(&message),
            #[cfg(any(test, feature = "testing"))]
            Key::Memory(key) => {
                // CR-39 m.6
                let _dit = DitGuard::new();
                let key = hmac::Key::new(hmac::HMAC_SHA256, key.expose());
                let mut out = [0; 32];
                out.copy_from_slice(hmac::sign(&key, &message).as_ref());
                Ok(out)
            }
        }
    }
}

#[cfg(test)]
mod tests;
