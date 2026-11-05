//! CMP-22b identity signer: the realm JOSE key set, which rotates under publish-before-use and
//! is published as a JWKS, and the compact JWS signatures of identity tokens (MD-3, MD-6,
//! CR-18 to CR-27, OP-143 m.1 E7), and the `COSE_Sign1` of identity plane artifacts such as
//! `auth_context` (OP-149 m.8); and the cell's `audit-checkpoint` key, which signs the identity
//! audit log's checkpoints (OP-150 m.3 (h)).

pub mod adapters;
pub mod app;
pub mod cell;
pub mod domain;
pub mod ports;
pub mod protocol;
pub mod service;

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
    /// The `COSE_Sign1` payload is not deterministic CBOR, or its content type is not an
    /// identity plane `+cbor` type (OP-149 m.8).
    #[error("payload")]
    Payload,
    /// The note body is not a canonical checkpoint of the cell's audit log (L2-CKP-3).
    #[error("note")]
    Note,
    /// The key could not sign.
    #[error("sign")]
    Sign,
}

impl SignerError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoKey => "signer-no-key",
            Self::Jose(e) => e.code(),
            Self::Payload => "signer-payload",
            Self::Note => "signer-note",
            Self::Sign => "signer-sign",
        }
    }
}
