//! What the signer needs from outside: a place to create operational keys.

use suiss_crypto::cose::Algorithm;
use suiss_crypto::signer::{SignError, Signer};

/// Creates operational keys: in the signer process from KMS-wrapped material, or in the HSM
/// under the FIPS profile (CR-21). Failing is an outage, not an error of the caller (CR-23).
pub trait KeyFactory {
    /// A new key for `alg`.
    ///
    /// # Errors
    /// [`SignError`] when the key store cannot create one.
    fn generate(&mut self, alg: Algorithm) -> Result<Box<dyn Signer + Send>, SignError>;
}
