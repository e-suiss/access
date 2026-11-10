//! What the SAML use cases need from outside: the realm's SAML key, a random source and an
//! encrypter (OP-63: clock and RNG are ports).

use std::future::Future;

use crate::alg::SigAlg;
use crate::xml::El;

/// A signature from the realm's SAML key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The signature value (PKCS#1 v1.5, or raw `r || s` for ECDSA).
    pub value: Vec<u8>,
    /// The signing key's certificate, DER, for `KeyInfo` (a hint, never a trust anchor).
    pub certificate: Vec<u8>,
}

/// Why nothing was signed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("signer: {0}")]
pub struct SignError(pub String);

/// Signs canonical `SignedInfo` octets with the realm's SAML key (§10.6.1 `XmlSigner`).
pub trait XmlSigner: Sync {
    /// The signature of `signed_info` with `alg`.
    fn sign(
        &self,
        signed_info: Vec<u8>,
        alg: SigAlg,
    ) -> impl Future<Output = Result<Signature, SignError>> + Send;
}

/// Random bytes from the process's random source (a port: clock and RNG are ports, OP-63).
pub trait Random: Sync {
    /// Fills `out`.
    ///
    /// # Errors
    /// [`SignError`] when no randomness is available.
    fn fill(&self, out: &mut [u8]) -> Result<(), SignError>;
}

/// Encrypts a signed assertion for the registration's encryption certificate.
pub trait Encrypter: Sync {
    /// The `saml:EncryptedAssertion` of `assertion`.
    ///
    /// # Errors
    /// [`SignError`].
    fn encrypt(&self, assertion: &El, cert: &[u8]) -> Result<El, SignError>;
}
