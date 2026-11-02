//! CMP-22b identity signer: the realm JOSE key set, which rotates under publish-before-use and
//! is published as a JWKS, and the compact JWS signatures of identity tokens (MD-3, MD-6,
//! CR-18 to CR-27, OP-143 m.1 E7).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

/// Why the signer refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// No key may sign now; the token waits (CR-23, G42).
    #[error("no signing key")]
    NoKey,
    /// The token could not be produced.
    #[error("jose: {0}")]
    Jose(#[from] access_crypto::jose::JoseError),
}

impl SignerError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoKey => "signer-no-key",
            Self::Jose(e) => e.code(),
        }
    }
}
