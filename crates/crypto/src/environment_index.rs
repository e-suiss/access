//! The environment's blind index of identifiers (OP-153 m.3 (aa), TN-76 m.5, OP-74 m.6): the PII
//! vault finds and keeps unique a sealed identifier by a keyed digest of its folded form. The key
//! lives in the PKCS#11 token under `access/environment-index/<EnvironmentID hex>` and never leaves it; one
//! key per environment, so two environments cannot link one address. The index outlives the subject's DEK as
//! the peppered tombstone; it is a pseudonym, not anonymous data (WP29 05/2014).

use std::fmt::Write as _;

#[cfg(any(test, feature = "testing"))]
use aws_lc_rs::hmac;
use suiss_crypto::pkcs11::{HsmError, HsmMac};

#[cfg(any(test, feature = "testing"))]
use crate::dit::DitGuard;
#[cfg(any(test, feature = "testing"))]
use crate::secret::Secret;

const CONTEXT: &[u8] = b"access/environment-index/v1\0";

/// The token label of an environment's index key: `access/environment-index/<EnvironmentID hex>`.
#[must_use]
pub fn label(environment: &[u8; 16]) -> String {
    environment
        .iter()
        .fold(String::from("access/environment-index/"), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

enum Key {
    Token(HsmMac),
    #[cfg(any(test, feature = "testing"))]
    Memory(Secret<[u8; 32]>),
}

/// One environment's index key.
pub struct EnvironmentIndexKey(Key);

impl EnvironmentIndexKey {
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

    /// `HMAC-SHA-256(K_r, "access/environment-index/v1" ‖ 0x00 ‖ tenant ‖ environment ‖ folded)`, where
    /// `folded` is the identifier in NFKC and lower case.
    ///
    /// # Errors
    /// [`HsmError`] when the token refuses.
    pub fn index(
        &self,
        tenant: &[u8; 16],
        environment: &[u8; 16],
        folded: &str,
    ) -> Result<[u8; 32], HsmError> {
        let mut message = CONTEXT.to_vec();
        message.extend_from_slice(tenant);
        message.extend_from_slice(environment);
        message.extend_from_slice(folded.as_bytes());
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
mod tests {
    use super::*;

    // OP-153 m.3 (aa), TN-76
    #[test]
    fn indexes_are_per_environment_and_key() {
        let a = EnvironmentIndexKey::new(Secret::new([1; 32]));
        let b = EnvironmentIndexKey::new(Secret::new([2; 32]));
        let one = a.index(&[1; 16], &[2; 16], "alice@example.com").unwrap();
        assert_eq!(
            one,
            a.index(&[1; 16], &[2; 16], "alice@example.com").unwrap()
        );
        assert_ne!(
            one,
            a.index(&[1; 16], &[3; 16], "alice@example.com").unwrap()
        );
        assert_ne!(
            one,
            b.index(&[1; 16], &[2; 16], "alice@example.com").unwrap()
        );
        assert_ne!(one, a.index(&[1; 16], &[2; 16], "bob@example.com").unwrap());
        assert_eq!(
            label(&[0xab; 16]).len(),
            "access/environment-index/".len() + 32
        );
    }
}
