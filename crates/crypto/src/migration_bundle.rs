//! A migration bundle's encryption (TN-86, OP-153 m.19 (d), m.25 (i),
//! `conformance/cddl/migration-bundle.cddl`): an ephemeral P-256 key agrees with the key the
//! receiving deployment bound to the export, HKDF-SHA256 (salt the recipient key's RFC 7638
//! thumbprint, info [`INFO`]) derives an AES-256-GCM key from the shared secret, and the
//! bundle's own fields without its ciphertext are the additional data. The ephemeral key is
//! used once and never kept.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, ECDH_P256, EphemeralPrivateKey, PrivateKey, UnparsedPublicKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::rand::{self, SystemRandom};

/// The HKDF info of a bundle key.
pub const INFO: &[u8] = b"access/migration-bundle/v1";

/// Length of a SEC1 uncompressed P-256 public key.
pub const KEY_LEN: usize = 65;

/// Why a bundle could not be sealed or opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    /// The recipient or ephemeral key is not a SEC1 uncompressed P-256 point.
    #[error("not a P-256 public key")]
    Key,
    /// The randomness source failed.
    #[error("randomness unavailable")]
    Random,
    /// The ciphertext does not open under this key and additional data.
    #[error("the bundle does not open")]
    Open,
}

fn key_from(shared: &[u8], salt: &[u8; 32]) -> Result<LessSafeKey, BundleError> {
    let prk = Salt::new(HKDF_SHA256, salt).extract(shared);
    let okm = prk
        .expand(&[INFO], &AES_256_GCM)
        .map_err(|_| BundleError::Key)?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

/// One bundle's sealing: the ephemeral key, the nonce and the derived key, made before the
/// additional data so the bundle can name `epk` and `nonce` in it.
pub struct Sealer {
    epk: Vec<u8>,
    nonce: [u8; NONCE_LEN],
    key: LessSafeKey,
}

impl core::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealer").finish_non_exhaustive()
    }
}

impl Sealer {
    /// Agrees an ephemeral key with `recipient` (SEC1 uncompressed) and derives the bundle key
    /// with `salt`, the recipient's thumbprint.
    ///
    /// # Errors
    /// [`BundleError`].
    pub fn new(recipient: &[u8], salt: &[u8; 32]) -> Result<Self, BundleError> {
        if recipient.len() != KEY_LEN {
            return Err(BundleError::Key);
        }
        let rng = SystemRandom::new();
        let ephemeral =
            EphemeralPrivateKey::generate(&ECDH_P256, &rng).map_err(|_| BundleError::Random)?;
        let epk = ephemeral
            .compute_public_key()
            .map_err(|_| BundleError::Key)?
            .as_ref()
            .to_vec();
        let mut nonce = [0; NONCE_LEN];
        rand::fill(&mut nonce).map_err(|_| BundleError::Random)?;
        let key = agreement::agree_ephemeral(
            ephemeral,
            UnparsedPublicKey::new(&ECDH_P256, recipient),
            BundleError::Key,
            |shared| key_from(shared, salt),
        )?;
        Ok(Self { epk, nonce, key })
    }

    /// The ephemeral public key, SEC1 uncompressed.
    #[must_use]
    pub fn epk(&self) -> &[u8] {
        &self.epk
    }

    /// The AES-GCM nonce.
    #[must_use]
    pub const fn nonce(&self) -> [u8; NONCE_LEN] {
        self.nonce
    }

    /// Encrypts `plaintext` with `aad`: the ciphertext with its tag.
    ///
    /// # Errors
    /// [`BundleError::Key`].
    pub fn seal(self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BundleError> {
        let mut out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(self.nonce),
                Aad::from(aad),
                &mut out,
            )
            .map_err(|_| BundleError::Key)?;
        Ok(out)
    }
}

/// The receiving deployment's P-256 key a migration export is bound to.
pub struct RecipientKey(PrivateKey);

impl core::fmt::Debug for RecipientKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecipientKey(<redacted>)")
    }
}

impl RecipientKey {
    /// A new key.
    ///
    /// # Errors
    /// [`BundleError::Random`].
    pub fn generate() -> Result<Self, BundleError> {
        PrivateKey::generate(&ECDH_P256)
            .map(Self)
            .map_err(|_| BundleError::Random)
    }

    /// Its public key, SEC1 uncompressed: what the export names.
    ///
    /// # Errors
    /// [`BundleError::Key`].
    pub fn public(&self) -> Result<Vec<u8>, BundleError> {
        Ok(self
            .0
            .compute_public_key()
            .map_err(|_| BundleError::Key)?
            .as_ref()
            .to_vec())
    }

    /// Opens a bundle's `ciphertext` sealed to this key with ephemeral key `epk`, `nonce`,
    /// `aad` and `salt`, the thumbprint of [`Self::public`].
    ///
    /// # Errors
    /// [`BundleError`].
    pub fn open(
        &self,
        (epk, salt): (&[u8], &[u8; 32]),
        nonce: [u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, BundleError> {
        let key = agreement::agree(
            &self.0,
            UnparsedPublicKey::new(&ECDH_P256, epk),
            BundleError::Key,
            |shared| key_from(shared, salt),
        )?;
        let mut buf = ciphertext.to_vec();
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut buf,
            )
            .map_err(|_| BundleError::Open)?;
        Ok(plain.to_vec())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // TN-86, OP-153 m.19 (d), m.25 (i)
    #[test]
    fn a_bundle_opens_only_with_its_key_salt_and_additional_data() {
        let r = RecipientKey::generate().unwrap();
        let public = r.public().unwrap();
        assert_eq!(public.len(), KEY_LEN);
        let salt = [7; 32];
        let s = Sealer::new(&public, &salt).unwrap();
        let (epk, nonce) = (s.epk().to_vec(), s.nonce());
        let ct = s.seal(b"aad", b"lines").unwrap();
        assert_eq!(r.open((&epk, &salt), nonce, b"aad", &ct).unwrap(), b"lines");
        assert_eq!(
            r.open((&epk, &salt), nonce, b"other", &ct),
            Err(BundleError::Open)
        );
        assert_eq!(
            r.open((&epk, &[8; 32]), nonce, b"aad", &ct),
            Err(BundleError::Open)
        );
        let other = RecipientKey::generate().unwrap();
        assert_eq!(
            other.open((&epk, &salt), nonce, b"aad", &ct),
            Err(BundleError::Open)
        );
        assert_eq!(
            Sealer::new(&public[..33], &salt).err(),
            Some(BundleError::Key)
        );
    }
}
