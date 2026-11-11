//! What the signer needs from outside: a place to create operational keys and a vault that
//! keeps them across restarts.

use suiss_crypto::cose::Algorithm;
use suiss_crypto::signer::{SignError, Signer};

/// A new operational key: its signer and the sealed form the factory can load it back from.
pub struct Generated {
    /// The key.
    pub signer: Box<dyn Signer + Send>,
    /// KEK-sealed private material, or a key-store reference; never plaintext (CR-21 m.3).
    pub sealed: Vec<u8>,
}

/// Creates operational keys: in the signer process with KMS-wrapped material, or in the HSM
/// under the FIPS profile (CR-21). Failing is an outage, not an error of the caller (CR-23).
pub trait KeyFactory {
    /// A new key for `alg`.
    ///
    /// # Errors
    /// [`SignError`] when the key store cannot create one.
    fn generate(&mut self, alg: Algorithm) -> Result<Generated, SignError>;

    /// The key a [`Generated::sealed`] value holds.
    ///
    /// # Errors
    /// [`SignError::Key`] when it cannot be unsealed.
    fn load(&mut self, alg: Algorithm, sealed: &[u8]) -> Result<Box<dyn Signer + Send>, SignError>;
}

/// The binding key of each domain, behind its quorum in the HSM (CR-29).
pub trait Bindings {
    /// The binding key of `domain`.
    ///
    /// # Errors
    /// [`SignError::Key`] when the domain has none.
    fn binding(
        &mut self,
        domain: &access_kernel::digest::Digest,
    ) -> Result<Box<dyn Signer + Send>, SignError>;

    /// Generation `generation` of `domain`'s binding key, created when missing; generation 0 is
    /// [`Bindings::binding`]. A binding re-anchor moves the domain to the next one (OP-60,
    /// §16.6.1 RB-2, OP-158 m.3 (l)).
    ///
    /// # Errors
    /// [`SignError::Key`] when the store holds no such generation and cannot create it.
    fn generation(
        &mut self,
        domain: &access_kernel::digest::Digest,
        generation: u64,
    ) -> Result<Box<dyn Signer + Send>, SignError> {
        if generation == 0 {
            self.binding(domain)
        } else {
            Err(SignError::Key)
        }
    }
}

/// Why the vault failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("vault")]
pub struct VaultError;

/// Keeps each domain's template and sealed keys across restarts (CR-23, OP-143 m.4).
pub trait Vault {
    /// Every domain the vault holds, as stored bytes.
    ///
    /// # Errors
    /// [`VaultError`].
    fn all(&mut self) -> Result<Vec<Vec<u8>>, VaultError>;

    /// Replaces a domain's stored bytes.
    ///
    /// # Errors
    /// [`VaultError`].
    fn put(
        &mut self,
        domain: &access_kernel::digest::Digest,
        bytes: &[u8],
    ) -> Result<(), VaultError>;
}
