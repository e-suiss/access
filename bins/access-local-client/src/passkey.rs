//! The test user's software passkey on the client side (OP-149 m.26 (e)): the same virtual
//! authenticator the bootstrap registered, signing with the key the operator names, never a
//! default. It answers a realm's assertion ceremonies: the identifier-first sign-in and the
//! Approval Surface's challenge over H(AAS) (§9.14.1 step 3).

use access_identity_webauthn::domain::software::SoftwareAuthenticator;
use access_kernel::verify::cose::PublicKey;
use serde_json::Value;
use suiss_crypto::signer::Signer;

use crate::ClientError;

/// A passkey: its key, and the relying party it was registered for.
pub struct Passkey<'a> {
    /// The Ed25519 key.
    pub key: &'a dyn Signer,
    /// The realm's RP ID: the issuer's host.
    pub rp_id: &'a str,
    /// The origin the ceremony runs at: `https://<issuer authority>`.
    pub origin: &'a str,
}

impl Passkey<'_> {
    /// The authenticator of the key.
    ///
    /// # Errors
    /// [`ClientError::Key`] for a key that is not Ed25519.
    pub fn authenticator(&self) -> Result<SoftwareAuthenticator, ClientError> {
        match self.key.public_key() {
            PublicKey::Ed25519(k) => Ok(SoftwareAuthenticator::ed25519(k)),
            _ => Err(ClientError::Key(String::from(
                "the passkey is not an Ed25519 key",
            ))),
        }
    }

    /// The `PublicKeyCredential` JSON of an assertion over `challenge`.
    ///
    /// # Errors
    /// [`ClientError::Key`].
    pub fn assert(&self, challenge: &[u8]) -> Result<Value, ClientError> {
        let assertion =
            self.authenticator()?
                .assertion(self.rp_id, self.origin, challenge, |m| {
                    self.key
                        .sign(m)
                        .map_err(|_| ClientError::Key(String::from("passkey signing")))
                })?;
        Ok(assertion.json())
    }
}

/// The RP ID and origin of an issuer URL: its host, and `https://` with its authority.
///
/// # Errors
/// [`ClientError::Url`].
pub fn relying_party(issuer: &str) -> Result<(String, String), ClientError> {
    let url = crate::http::Url::parse(issuer)?;
    Ok((url.host.clone(), url.origin()))
}
