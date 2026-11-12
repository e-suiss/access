//! What the identity signer needs from outside: a place to create realm keys and to load them
//! back after a restart.

use access_crypto::jose::JwsAlg;
use access_crypto::rsa_id::RsaIdKey;
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

    /// Whether this factory can hold an ML-DSA key of `alg` (OP-159 m.3 (d)); a factory that
    /// cannot refuses the realm's post-quantum profile, with no classical key in its place.
    fn pq_ready(&mut self, alg: JwsAlg) -> bool {
        let _ = alg;
        false
    }

    /// A new RSA-3072 `rsa-id` key and its sealed form (MD-6, OP-155 m.3 (k)); a factory
    /// without RSA refuses.
    ///
    /// # Errors
    /// [`SignError`].
    fn generate_rsa_id(&mut self) -> Result<(RsaIdKey, Vec<u8>), SignError> {
        Err(SignError::Algorithm)
    }

    /// The `rsa-id` key a sealed form holds.
    ///
    /// # Errors
    /// [`SignError::Key`].
    fn load_rsa_id(&mut self, sealed: &[u8]) -> Result<RsaIdKey, SignError> {
        let _ = sealed;
        Err(SignError::Key)
    }

    /// Seals a private key document made elsewhere in the signer (a SAML key, OP-155 m.3 (d)).
    ///
    /// # Errors
    /// [`SignError::Key`] when this factory cannot seal one.
    fn seal_document(
        &mut self,
        doc: &suiss_crypto::secret::Secret<Vec<u8>>,
    ) -> Result<Vec<u8>, SignError> {
        let _ = doc;
        Err(SignError::Key)
    }

    /// Opens a document [`Self::seal_document`] sealed.
    ///
    /// # Errors
    /// [`SignError::Key`].
    fn open_document(
        &mut self,
        sealed: &[u8],
    ) -> Result<suiss_crypto::secret::Secret<Vec<u8>>, SignError> {
        let _ = sealed;
        Err(SignError::Key)
    }
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

    /// The stored cell `audit-checkpoint` key, if one was made (OP-150 m.3 (h)).
    ///
    /// # Errors
    /// [`VaultError`].
    fn cell(&mut self) -> Result<Option<Vec<u8>>, VaultError>;

    /// Stores the cell `audit-checkpoint` key; it is written once.
    ///
    /// # Errors
    /// [`VaultError`].
    fn put_cell(&mut self, bytes: &[u8]) -> Result<(), VaultError>;

    /// The stored Claim issuer key of `realm`, if one was made (§10.1.7).
    ///
    /// # Errors
    /// [`VaultError`].
    fn issuer(&mut self, realm: &crate::protocol::Realm) -> Result<Option<Vec<u8>>, VaultError>;

    /// Stores the Claim issuer key of `realm`; it is written once.
    ///
    /// # Errors
    /// [`VaultError`].
    fn put_issuer(
        &mut self,
        realm: &crate::protocol::Realm,
        bytes: &[u8],
    ) -> Result<(), VaultError>;

    /// The stored `rsa-id` key of `realm`, if one was made (MD-6, OP-155 m.3 (k)).
    ///
    /// # Errors
    /// [`VaultError`].
    fn rsa_id(&mut self, realm: &crate::protocol::Realm) -> Result<Option<Vec<u8>>, VaultError> {
        let _ = realm;
        Ok(None)
    }

    /// Stores the `rsa-id` key of `realm`; it is written once. A vault without the slot refuses.
    ///
    /// # Errors
    /// [`VaultError`].
    fn put_rsa_id(
        &mut self,
        realm: &crate::protocol::Realm,
        bytes: &[u8],
    ) -> Result<(), VaultError> {
        let _ = (realm, bytes);
        Err(VaultError)
    }

    /// The stored SAML keys of `realm`, if any were made (OP-155 m.3 (d)).
    ///
    /// # Errors
    /// [`VaultError`].
    fn saml(&mut self, realm: &crate::protocol::Realm) -> Result<Option<Vec<u8>>, VaultError> {
        let _ = realm;
        Ok(None)
    }

    /// Replaces the stored SAML keys of `realm`.
    ///
    /// # Errors
    /// [`VaultError`] when this vault keeps none.
    fn put_saml(&mut self, realm: &crate::protocol::Realm, bytes: &[u8]) -> Result<(), VaultError> {
        let _ = (realm, bytes);
        Err(VaultError)
    }

    /// The stored SSH CA keys of `realm`, if any were made (OP-156 m.3 (o)).
    ///
    /// # Errors
    /// [`VaultError`].
    fn ssh(&mut self, realm: &crate::protocol::Realm) -> Result<Option<Vec<u8>>, VaultError> {
        let _ = realm;
        Ok(None)
    }

    /// Replaces the stored SSH CA keys of `realm`.
    ///
    /// # Errors
    /// [`VaultError`] when this vault keeps none.
    fn put_ssh(&mut self, realm: &crate::protocol::Realm, bytes: &[u8]) -> Result<(), VaultError> {
        let _ = (realm, bytes);
        Err(VaultError)
    }
}
