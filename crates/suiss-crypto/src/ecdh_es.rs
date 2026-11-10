//! JWE `ECDH-ES` content encryption on P-256 (RFC 7518 §4.6, direct key agreement) with
//! `A128GCM` or `A256GCM`, as an OID4VP verifier receives `direct_post.jwt` responses (HAIP;
//! OP-155 m.3 (p)). The compact framing and the header are the caller's; this module agrees the
//! key, runs the Concat KDF and opens or seals the content. A recipient key may be derived from
//! a 32-byte secret and a context with HKDF-SHA-256, so a verifier keeps no private key per
//! request.

use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, ECDH_P256, PrivateKey, UnparsedPublicKey};
use aws_lc_rs::hkdf;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::secret::Secret;

/// The HKDF salt of a derived recipient key.
const DERIVE_SALT: &[u8] = b"esuiss/ecdh-es/recipient/v1";

/// Why an operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EcdhEsError {
    /// No key could be made or read.
    #[error("ecdh-es key")]
    Key,
    /// The peer key is not a P-256 point.
    #[error("ecdh-es peer key")]
    Peer,
    /// The content does not open.
    #[error("ecdh-es decrypt")]
    Decrypt,
    /// The random source failed.
    #[error("random source")]
    Random,
}

/// The content encryption (`enc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enc {
    /// `A128GCM`.
    A128Gcm,
    /// `A256GCM`.
    A256Gcm,
}

impl Enc {
    /// The JOSE name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A256Gcm => "A256GCM",
        }
    }

    /// The `enc` of a JOSE name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "A128GCM" => Some(Self::A128Gcm),
            "A256GCM" => Some(Self::A256Gcm),
            _ => None,
        }
    }

    const fn key_len(self) -> usize {
        match self {
            Self::A128Gcm => 16,
            Self::A256Gcm => 32,
        }
    }

    const fn aead(self) -> &'static aws_lc_rs::aead::Algorithm {
        match self {
            Self::A128Gcm => &AES_128_GCM,
            Self::A256Gcm => &AES_256_GCM,
        }
    }
}

/// A P-256 key-agreement key.
pub struct EcdhKey {
    key: PrivateKey,
}

struct ScalarLen;

impl hkdf::KeyType for ScalarLen {
    fn len(&self) -> usize {
        32
    }
}

fn other_info(enc: Enc, apu: &[u8], apv: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for part in [enc.name().as_bytes(), apu, apv] {
        out.extend_from_slice(&u32::try_from(part.len()).ok()?.to_be_bytes());
        out.extend_from_slice(part);
    }
    let bits = u32::try_from(enc.key_len().checked_mul(8)?).ok()?;
    out.extend_from_slice(&bits.to_be_bytes());
    Some(out)
}

/// The Concat KDF of RFC 7518 §4.6.2 for direct key agreement: one SHA-256 round.
fn concat_kdf(z: &[u8], enc: Enc, apu: &[u8], apv: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut input = Zeroizing::new(1_u32.to_be_bytes().to_vec());
    input.extend_from_slice(z);
    input.extend(other_info(enc, apu, apv)?);
    let digest = Zeroizing::new(crate::digest::sha256(&input));
    digest
        .get(..enc.key_len())
        .map(|k| Zeroizing::new(k.to_vec()))
}

impl EcdhKey {
    /// A fresh key.
    ///
    /// # Errors
    /// [`EcdhEsError::Key`].
    pub fn generate() -> Result<Self, EcdhEsError> {
        PrivateKey::generate(&ECDH_P256)
            .map(|key| Self { key })
            .map_err(|_| EcdhEsError::Key)
    }

    /// The key HKDF-SHA-256 derives from `secret` for `context`; the same inputs give the same
    /// key.
    ///
    /// # Errors
    /// [`EcdhEsError::Key`].
    pub fn derive(secret: &Secret<[u8; 32]>, context: &[u8]) -> Result<Self, EcdhEsError> {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, DERIVE_SALT).extract(secret.expose());
        for counter in 0_u8..16 {
            let info = [context, &[counter]];
            let okm = prk.expand(&info, ScalarLen).map_err(|_| EcdhEsError::Key)?;
            let mut scalar = Zeroizing::new([0u8; 32]);
            okm.fill(scalar.as_mut()).map_err(|_| EcdhEsError::Key)?;
            if let Ok(key) = PrivateKey::from_private_key(&ECDH_P256, scalar.as_ref()) {
                return Ok(Self { key });
            }
        }
        Err(EcdhEsError::Key)
    }

    /// The public key, uncompressed SEC1 (65 bytes).
    ///
    /// # Errors
    /// [`EcdhEsError::Key`].
    pub fn public_point(&self) -> Result<Vec<u8>, EcdhEsError> {
        self.key
            .compute_public_key()
            .map(|p| p.as_ref().to_vec())
            .map_err(|_| EcdhEsError::Key)
    }

    fn cek(
        &self,
        peer: &[u8],
        enc: Enc,
        apu: &[u8],
        apv: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, EcdhEsError> {
        agreement::agree(
            &self.key,
            UnparsedPublicKey::new(&ECDH_P256, peer),
            EcdhEsError::Peer,
            |z| concat_kdf(z, enc, apu, apv).ok_or(EcdhEsError::Key),
        )
    }

    /// Opens content sent to this key by the ephemeral key `epk` (uncompressed SEC1):
    /// `ciphertext` with its 16-byte tag appended, `aad` the protected header as sent.
    ///
    /// # Errors
    /// [`EcdhEsError`].
    pub fn open(
        &self,
        epk: &[u8],
        (enc, apu, apv): (Enc, &[u8], &[u8]),
        iv: [u8; 12],
        aad: &[u8],
        mut ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, EcdhEsError> {
        let cek = self.cek(epk, enc, apu, apv)?;
        let key =
            LessSafeKey::new(UnboundKey::new(enc.aead(), &cek).map_err(|_| EcdhEsError::Key)?);
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(iv),
                Aad::from(aad),
                &mut ciphertext,
            )
            .map_err(|_| EcdhEsError::Decrypt)?;
        Ok(plain.to_vec())
    }

    /// Seals `plaintext` from this (ephemeral) key to `recipient`, as a wallet does: answers the
    /// fresh nonce and the ciphertext with its tag appended.
    ///
    /// # Errors
    /// [`EcdhEsError`].
    pub fn seal(
        &self,
        recipient: &[u8],
        enc: Enc,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; 12], Vec<u8>), EcdhEsError> {
        let cek = self.cek(recipient, enc, &[], &[])?;
        let key =
            LessSafeKey::new(UnboundKey::new(enc.aead(), &cek).map_err(|_| EcdhEsError::Key)?);
        let mut iv = [0u8; 12];
        SystemRandom::new()
            .fill(&mut iv)
            .map_err(|_| EcdhEsError::Random)?;
        let mut out = plaintext.to_vec();
        key.seal_in_place_append_tag(Nonce::assume_unique_for_key(iv), Aad::from(aad), &mut out)
            .map_err(|_| EcdhEsError::Key)?;
        Ok((iv, out))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::{EcdhKey, Enc};
    use crate::secret::Secret;

    #[test]
    fn seals_and_opens_and_derives_stably() {
        let mut s = [0u8; 32];
        aws_lc_rs::rand::fill(&mut s).unwrap();
        let secret = Secret::new(s);
        let recipient = EcdhKey::derive(&secret, b"request-1").unwrap();
        let again = EcdhKey::derive(&secret, b"request-1").unwrap();
        let other = EcdhKey::derive(&secret, b"request-2").unwrap();
        assert_eq!(
            recipient.public_point().unwrap(),
            again.public_point().unwrap()
        );
        assert_ne!(
            recipient.public_point().unwrap(),
            other.public_point().unwrap()
        );
        let eph = EcdhKey::generate().unwrap();
        for enc in [Enc::A128Gcm, Enc::A256Gcm] {
            let (iv, ct) = eph
                .seal(&recipient.public_point().unwrap(), enc, b"hdr", b"payload")
                .unwrap();
            let epk = eph.public_point().unwrap();
            let opened = recipient
                .open(&epk, (enc, &[], &[]), iv, b"hdr", ct.clone())
                .unwrap();
            assert_eq!(opened, b"payload");
            assert!(
                other
                    .open(&epk, (enc, &[], &[]), iv, b"hdr", ct.clone())
                    .is_err()
            );
            assert!(
                recipient
                    .open(&epk, (enc, &[], &[]), iv, b"hdx", ct)
                    .is_err()
            );
        }
    }
}
