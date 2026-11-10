//! The primitives of XML Signature and XML Encryption for the SAML identity provider (OP-155
//! m.3 (d), (e), §10.6.1, §13.2, CR-4, TI-9): SHA-2 digests; RSA PKCS#1 v1.5 and ECDSA
//! verification for the parser worker; the realm's RSA-3072 and P-256 SAML keys for the identity
//! signer; and AES-256-GCM with RSA-OAEP (SHA-256, MGF1 SHA-256) for encrypted assertions. SHA-1,
//! RSA 1.5 encryption, PSS and Ed25519 have no entry here.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{
    KeyPair as RsaKeyPair, KeySize, OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey,
    PublicEncryptingKey,
};
use aws_lc_rs::signature::{
    self, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair,
    KeyPair as _, UnparsedPublicKey, VerificationAlgorithm,
};

use crate::Secret;

/// Why nothing was produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("xml security primitive failed")]
pub struct XmlSecError;

/// A SHA-2 digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Digest {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// The digest of `data`.
#[must_use]
pub fn digest(d: Digest, data: &[u8]) -> Vec<u8> {
    let a = match d {
        Digest::Sha256 => &aws_lc_rs::digest::SHA256,
        Digest::Sha384 => &aws_lc_rs::digest::SHA384,
        Digest::Sha512 => &aws_lc_rs::digest::SHA512,
    };
    aws_lc_rs::digest::digest(a, data).as_ref().to_vec()
}

/// A signature the parser worker verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verify {
    /// RSA PKCS#1 v1.5, SHA-256, 2048 to 8192 bits; the key is a PKCS#1 `RSAPublicKey`.
    RsaSha256,
    /// RSA PKCS#1 v1.5, SHA-384.
    RsaSha384,
    /// RSA PKCS#1 v1.5, SHA-512.
    RsaSha512,
    /// ECDSA P-256, SHA-256, `r ‖ s`; the key is an uncompressed point.
    P256Sha256,
    /// ECDSA P-384, SHA-384, `r ‖ s`.
    P384Sha384,
}

/// Whether `sig` is `alg`'s signature of `message` under `public_key`.
#[must_use]
pub fn verify(alg: Verify, public_key: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let a: &'static dyn VerificationAlgorithm = match alg {
        Verify::RsaSha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        Verify::RsaSha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
        Verify::RsaSha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
        Verify::P256Sha256 => &signature::ECDSA_P256_SHA256_FIXED,
        Verify::P384Sha384 => &signature::ECDSA_P384_SHA384_FIXED,
    };
    UnparsedPublicKey::new(a, public_key)
        .verify(message, sig)
        .is_ok()
}

/// Fills `out` from the operating system's source.
///
/// # Errors
/// [`XmlSecError`].
pub fn fill(out: &mut [u8]) -> Result<(), XmlSecError> {
    aws_lc_rs::rand::fill(out).map_err(|_| XmlSecError)
}

/// Whether `a` and `b` are equal, in time independent of where they differ.
#[must_use]
pub fn same(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// `plaintext` encrypted with RSA-OAEP (SHA-256, MGF1 SHA-256) for the RSA
/// `subjectPublicKeyInfo` `spki`.
///
/// # Errors
/// [`XmlSecError`] for a key that is not RSA or a plaintext too long for it.
pub fn rsa_oaep_encrypt(spki: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, XmlSecError> {
    let public = PublicEncryptingKey::from_der(spki).map_err(|_| XmlSecError)?;
    let oaep = OaepPublicEncryptingKey::new(public).map_err(|_| XmlSecError)?;
    let mut out = vec![0_u8; oaep.ciphertext_size()];
    let n = oaep
        .encrypt(&OAEP_SHA256_MGF1SHA256, plaintext, &mut out, None)
        .map_err(|_| XmlSecError)?
        .len();
    out.truncate(n);
    Ok(out)
}

/// `data` sealed in place with AES-256-GCM under `key` and the unique `nonce`; the tag is
/// appended.
///
/// # Errors
/// [`XmlSecError`].
pub fn aes256_gcm_seal(
    key: &[u8; 32],
    nonce: [u8; 12],
    data: &mut Vec<u8>,
) -> Result<(), XmlSecError> {
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| XmlSecError)?);
    k.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), data)
        .map_err(|_| XmlSecError)
}

/// An RSA-3072 SAML key.
pub struct RsaKey(RsaKeyPair);

impl RsaKey {
    /// A new key, with its PKCS#8 document for sealing.
    ///
    /// # Errors
    /// [`XmlSecError`].
    pub fn generate() -> Result<(Self, Secret<Vec<u8>>), XmlSecError> {
        let k = RsaKeyPair::generate(KeySize::Rsa3072).map_err(|_| XmlSecError)?;
        let doc: Pkcs8V1Der<'static> = k.as_der().map_err(|_| XmlSecError)?;
        Ok((Self(k), Secret::new(doc.as_ref().to_vec())))
    }

    /// The key of a PKCS#8 document.
    ///
    /// # Errors
    /// [`XmlSecError`].
    pub fn from_pkcs8(doc: &Secret<Vec<u8>>) -> Result<Self, XmlSecError> {
        RsaKeyPair::from_pkcs8(doc.expose())
            .map(Self)
            .map_err(|_| XmlSecError)
    }

    /// Its `subjectPublicKeyInfo`, DER.
    ///
    /// # Errors
    /// [`XmlSecError`].
    pub fn spki(&self) -> Result<Vec<u8>, XmlSecError> {
        let der: PublicKeyX509Der<'static> =
            self.0.public_key().as_der().map_err(|_| XmlSecError)?;
        Ok(der.as_ref().to_vec())
    }

    /// Its PKCS#1 v1.5 signature of `message` with `d`.
    ///
    /// # Errors
    /// [`XmlSecError`].
    pub fn sign(&self, d: Digest, message: &[u8]) -> Result<Vec<u8>, XmlSecError> {
        let padding = match d {
            Digest::Sha256 => &signature::RSA_PKCS1_SHA256,
            Digest::Sha384 => &signature::RSA_PKCS1_SHA384,
            Digest::Sha512 => &signature::RSA_PKCS1_SHA512,
        };
        let mut out = vec![0; self.0.public_modulus_len()];
        self.0
            .sign(padding, &SystemRandom::new(), message, &mut out)
            .map_err(|_| XmlSecError)?;
        Ok(out)
    }
}

/// A P-256 SAML key.
pub struct P256Key {
    fixed: EcdsaKeyPair,
    asn1: EcdsaKeyPair,
}

impl P256Key {
    /// A new key, with its PKCS#8 document for sealing.
    ///
    /// # Errors
    /// [`XmlSecError`].
    pub fn generate() -> Result<(Self, Secret<Vec<u8>>), XmlSecError> {
        let d =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|_| XmlSecError)?;
        let doc = Secret::new(d.as_ref().to_vec());
        Ok((Self::from_pkcs8(&doc)?, doc))
    }

    /// The key of a PKCS#8 document.
    ///
    /// # Errors
    /// [`XmlSecError`].
    pub fn from_pkcs8(doc: &Secret<Vec<u8>>) -> Result<Self, XmlSecError> {
        Ok(Self {
            fixed: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.expose())
                .map_err(|_| XmlSecError)?,
            asn1: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, doc.expose())
                .map_err(|_| XmlSecError)?,
        })
    }

    /// Its uncompressed public point.
    #[must_use]
    pub fn point(&self) -> Vec<u8> {
        self.fixed.public_key().as_ref().to_vec()
    }

    /// Its ECDSA-SHA256 signature of `message`, `r ‖ s` (XML Signature).
    ///
    /// # Errors
    /// [`XmlSecError`].
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, XmlSecError> {
        Ok(self
            .fixed
            .sign(&SystemRandom::new(), message)
            .map_err(|_| XmlSecError)?
            .as_ref()
            .to_vec())
    }

    /// Its ECDSA-SHA256 signature of `message`, DER (X.509).
    ///
    /// # Errors
    /// [`XmlSecError`].
    pub fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, XmlSecError> {
        Ok(self
            .asn1
            .sign(&SystemRandom::new(), message)
            .map_err(|_| XmlSecError)?
            .as_ref()
            .to_vec())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-155 m.3 (d), (e)
    #[test]
    fn saml_keys_sign_what_verification_accepts() {
        let (p, doc) = P256Key::generate().unwrap();
        let back = P256Key::from_pkcs8(&doc).unwrap();
        let s = back.sign(b"m").unwrap();
        assert!(verify(Verify::P256Sha256, &p.point(), b"m", &s));
        assert!(!verify(Verify::P256Sha256, &p.point(), b"n", &s));
        assert_eq!(digest(Digest::Sha384, b"").len(), 48);
        assert!(same(b"ab", b"ab") && !same(b"ab", b"ac"));
        let mut key = <[u8; 32]>::default();
        fill(&mut key).unwrap();
        let mut nonce = <[u8; 12]>::default();
        fill(&mut nonce).unwrap();
        let mut data = b"x".to_vec();
        aes256_gcm_seal(&key, nonce, &mut data).unwrap();
        assert_eq!(data.len(), 17);
    }
}
