//! Opaque per-domain tokens (OP-141 m.22 (d), TI-RT10): `basis_ref`, consistency and page
//! tokens. AES-256-GCM under the domain's token key `access/token/<DomainID hex>` in the
//! PKCS#11 token; the text is base64url of `nonce ‖ ciphertext ‖ tag`.

use std::fmt::Write as _;

use access_kernel::json::{b64url_decode, b64url_encode};
use suiss_crypto::pkcs11::HsmAead;

#[cfg(any(test, feature = "testing"))]
use crate::secret::Secret;

/// Why a token was not made or not opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// Not base64url, not this domain's, not this kind, or altered.
    #[error("token")]
    Invalid,
    /// The key failed.
    #[error("key")]
    Key,
}

/// The token label of a domain's token key: `access/token/<DomainID hex>`.
#[must_use]
pub fn label(domain: &[u8; 32]) -> String {
    let mut out = String::from("access/token/");
    for b in domain {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn aad(domain: &[u8; 32], kind: &str) -> Vec<u8> {
    [domain.as_slice(), &[0], kind.as_bytes()].concat()
}

enum Key {
    Token(HsmAead),
    #[cfg(any(test, feature = "testing"))]
    Memory(Secret<[u8; 32]>),
}

/// A domain's token key.
pub struct TokenKey(Key);

impl TokenKey {
    /// The key inside the token.
    #[must_use]
    pub const fn token(aead: HsmAead) -> Self {
        Self(Key::Token(aead))
    }

    /// An in-process key with the same token format, for tests.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn new(key: Secret<[u8; 32]>) -> Self {
        Self(Key::Memory(key))
    }

    /// Seals `body` as a token of `kind` for `domain`.
    ///
    /// # Errors
    /// [`TokenError::Key`].
    pub fn seal(&self, domain: &[u8; 32], kind: &str, body: &[u8]) -> Result<String, TokenError> {
        let aad = aad(domain, kind);
        let sealed = match &self.0 {
            Key::Token(k) => k.seal(&aad, body).map_err(|_| TokenError::Key)?,
            #[cfg(any(test, feature = "testing"))]
            Key::Memory(k) => memory::seal(k.expose(), &aad, body)?,
        };
        Ok(b64url_encode(&sealed))
    }

    /// Opens a token of `kind` for `domain`.
    ///
    /// # Errors
    /// [`TokenError::Invalid`] for anything this key did not seal for this domain and kind.
    pub fn open(&self, domain: &[u8; 32], kind: &str, text: &str) -> Result<Vec<u8>, TokenError> {
        let sealed = b64url_decode(text).map_err(|_| TokenError::Invalid)?;
        let aad = aad(domain, kind);
        match &self.0 {
            Key::Token(k) => k.open(&aad, &sealed).map_err(|_| TokenError::Invalid),
            #[cfg(any(test, feature = "testing"))]
            Key::Memory(k) => memory::open(k.expose(), &aad, &sealed),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
mod memory {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
    use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};

    use super::TokenError;

    fn key(k: &[u8; 32]) -> Result<LessSafeKey, TokenError> {
        Ok(LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, k).map_err(|_| TokenError::Key)?,
        ))
    }

    pub(super) fn seal(k: &[u8; 32], aad: &[u8], body: &[u8]) -> Result<Vec<u8>, TokenError> {
        let mut nonce = [0_u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| TokenError::Key)?;
        let mut out = body.to_vec();
        key(k)?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut out,
            )
            .map_err(|_| TokenError::Key)?;
        Ok([nonce.as_slice(), &out].concat())
    }

    pub(super) fn open(k: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, TokenError> {
        if sealed.len() < NONCE_LEN {
            return Err(TokenError::Invalid);
        }
        let (nonce, body) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| TokenError::Invalid)?;
        let mut buf = body.to_vec();
        let plain = key(k)?
            .open_in_place(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| TokenError::Invalid)?;
        Ok(plain.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> TokenKey {
        TokenKey::new(Secret::new([7; 32]))
    }

    // OP-141 m.22 (d), TI-RT10: a token opens only for its domain and kind
    #[test]
    fn a_token_opens_for_its_domain_and_kind_only() {
        let t = key().seal(&[1; 32], "basis_ref", b"17").unwrap();
        assert_eq!(key().open(&[1; 32], "basis_ref", &t).unwrap(), b"17");
        assert_ne!(key().seal(&[1; 32], "basis_ref", b"17").unwrap(), t);
        assert_eq!(
            key().open(&[2; 32], "basis_ref", &t),
            Err(TokenError::Invalid)
        );
        assert_eq!(key().open(&[1; 32], "page", &t), Err(TokenError::Invalid));
        assert_eq!(
            key().open(&[1; 32], "basis_ref", "!"),
            Err(TokenError::Invalid)
        );
        let other = TokenKey::new(Secret::new([8; 32]));
        assert_eq!(
            other.open(&[1; 32], "basis_ref", &t),
            Err(TokenError::Invalid)
        );
        assert!(label(&[0xab; 32]).starts_with("access/token/abab"));
    }
}
