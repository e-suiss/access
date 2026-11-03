//! WebAuthn relying party and authenticator registry (CMP-15.7), on aws-lc-rs (OP-146 m.3).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

use domain::mds::MdsError;

/// An infrastructure failure. Ceremony refusals are [`domain::Rejection`] decisions, not errors
/// (OP-64).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WebAuthnError {
    /// No trusted time.
    #[error("clock unavailable")]
    Clock,
    /// No randomness.
    #[error("randomness unavailable")]
    Random,
    /// The decoy key failed.
    #[error("decoy key unavailable")]
    Decoy,
    /// The registry failed.
    #[error("registry: {0}")]
    Registry(String),
    /// The signal sink failed.
    #[error("signal sink: {0}")]
    Signals(String),
    /// The metadata source or cache failed.
    #[error("metadata source: {0}")]
    MdsSource(String),
    /// A fetched metadata blob was not accepted.
    #[error("metadata: {0}")]
    Mds(#[from] MdsError),
}

impl WebAuthnError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Clock => "webauthn-clock",
            Self::Random => "webauthn-random",
            Self::Decoy => "webauthn-decoy",
            Self::Registry(_) => "webauthn-registry",
            Self::Signals(_) => "webauthn-signals",
            Self::MdsSource(_) => "webauthn-mds-source",
            Self::Mds(e) => e.code(),
        }
    }
}
