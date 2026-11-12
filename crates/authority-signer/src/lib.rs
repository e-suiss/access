//! CMP-22a authority signer: domain-scoped operational keys that rotate under the binding key,
//! the binding-signed Domain Metadata and key excerpts that declare them, and artefact
//! signatures (T20, CR-18 to CR-27, OP-143).

pub mod adapters;
pub mod app;
pub mod ceremony;
pub mod domain;
pub mod genesis;
pub mod handover;
/// CR-51 m.3: the known-answer tests, shared with the identity signer (CMP-22b).
pub use access_crypto::kat;
pub mod ports;
pub mod protocol;
pub mod service;

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
    /// A note body that is not a checkpoint of the domain's log.
    #[error("note")]
    Note,
    /// Token claims that are not a holder-bound claims set with an `exp` (PI-11).
    #[error("token claims")]
    Token,
    /// A token that would outlive the publication of the key that signs it (CR-19).
    #[error("token horizon")]
    TokenHorizon,
    /// An algorithm the domain's declarations or binding exclude (CR-44, OP-159 m.3 (e), (r)).
    #[error("algorithm profile conflict")]
    AlgorithmConflict,
    /// The binding key cannot sign once the algorithm is retired: no ML-DSA binding (OP-159
    /// m.3 (d), (f)).
    #[error("post-quantum key unavailable")]
    PqKeyUnavailable,
    /// No re-anchor checkpoint cosigned by an independent witness covers the head (RA-6,
    /// OP-159 m.3 (f)).
    #[error("re-anchor required")]
    ReanchorRequired,
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
            Self::Note => "signer-note",
            Self::Token => "signer-token",
            Self::TokenHorizon => "signer-token-horizon",
            Self::AlgorithmConflict => "algorithm-profile-conflict",
            Self::PqKeyUnavailable => "pq-key-unavailable",
            Self::ReanchorRequired => "reanchor-required",
        }
    }
}
