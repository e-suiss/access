//! The PKCS#11 token the bootstrap keeps the test user's keys in (OP-149 m.26 (e), m.28 (b)):
//! the client signs with those keys through the token, as the server does; nothing is exported.

use std::path::Path;

use suiss_crypto::pkcs11::{HsmSigner, KeyStore};
use suiss_crypto::secret::Secret;

use crate::ClientError;

/// An open token.
pub struct Token(KeyStore);

impl Token {
    /// Opens the token `label` of `module` with the user PIN in `pin_file`.
    ///
    /// # Errors
    /// [`ClientError::File`] for the PIN file, [`ClientError::Key`] for the token.
    pub fn open(module: &Path, label: &str, pin_file: &Path) -> Result<Self, ClientError> {
        let pin = std::fs::read_to_string(pin_file)
            .map_err(|e| ClientError::File(pin_file.display().to_string(), e.to_string()))?;
        let pin = Secret::new(String::from(pin.trim_end_matches(['\r', '\n'])));
        KeyStore::open(module, label, &pin)
            .map(Self)
            .map_err(|e| ClientError::Key(format!("token {label}: {e}")))
    }

    /// The signing key `label` in the token.
    ///
    /// # Errors
    /// [`ClientError::Key`] when there is none.
    pub fn signer(&self, label: &str) -> Result<HsmSigner, ClientError> {
        self.0
            .signer(label)
            .map_err(|e| ClientError::Key(format!("key {label}: {e}")))
    }
}
