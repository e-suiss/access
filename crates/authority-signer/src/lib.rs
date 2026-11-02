//! CMP-22a authority signer: domain-scoped operational keys that rotate under the binding key,
//! the binding-signed Domain Metadata and key excerpts that declare them, and artefact
//! signatures (T20, CR-18 to CR-27, OP-143).

pub mod app;
pub mod domain;
pub mod ports;

/// Why the signer refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// No key may sign now; the artefact waits (CR-23, G42).
    #[error("no signing key")]
    NoKey,
    /// The key cannot sign this usage.
    #[error("usage")]
    Usage,
    /// The binding key or an operational key failed.
    #[error("sign: {0}")]
    Sign(#[from] suiss_crypto::signer::SignError),
    /// Metadata or an excerpt could not be encoded.
    #[error("encode")]
    Encode,
}

impl SignerError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoKey => "signer-no-key",
            Self::Usage => "signer-usage",
            Self::Sign(e) => e.code(),
            Self::Encode => "signer-encode",
        }
    }
}
