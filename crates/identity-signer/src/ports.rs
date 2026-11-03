//! What the identity signer needs from outside: a place to create realm keys and to load them
//! back after a restart.

use access_crypto::jose::JwsAlg;
use suiss_crypto::signer::{SignError, Signer};

/// A new realm key: its signer and the sealed form the factory can load it back from.
pub struct Generated {
    /// The key.
    pub signer: Box<dyn Signer + Send>,
    /// KEK-sealed private material, or a key-store reference; never plaintext (CR-21 m.3).
    pub sealed: Vec<u8>,
}

/// Creates realm keys under the realm's own KMS key, apart from the domain keys (T31, CR-21).
/// Failing is an outage, not an error of the caller (CR-23).
pub trait KeyFactory {
    /// A new key for `alg`.
    ///
    /// # Errors
    /// [`SignError`] when the key store cannot create one.
    fn generate(&mut self, alg: JwsAlg) -> Result<Generated, SignError>;

    /// The key a [`Generated::sealed`] value holds.
    ///
    /// # Errors
    /// [`SignError::Key`] when it cannot be unsealed.
    fn load(&mut self, alg: JwsAlg, sealed: &[u8]) -> Result<Box<dyn Signer + Send>, SignError>;
}

/// Why the vault failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("vault")]
pub struct VaultError;

/// Keeps each realm's key set across restarts, keyed by the realm; never shared with the
/// authority signer's store (CMP-22b, OP-143 m.9 (e)).
pub trait Vault {
    /// Every realm the vault holds, as stored bytes.
    ///
    /// # Errors
    /// [`VaultError`].
    fn all(&mut self) -> Result<Vec<Vec<u8>>, VaultError>;

    /// Replaces a realm's stored bytes.
    ///
    /// # Errors
    /// [`VaultError`].
    fn put(&mut self, realm: &crate::protocol::Realm, bytes: &[u8]) -> Result<(), VaultError>;
}
