//! CMP-4 authority core (§17.1.1, OP-141): from a verified request to committed records.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
pub mod query;

use access_authority_sequencer::SequencerError;
use access_kernel::ais::AisError;
use access_kernel::combinator::Rejection;
use access_store::StoreError;

/// Why a request produced no decision (protocol errors and rejections, §9.5 k.3–k.4).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// The request is malformed.
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    /// The AIS does not make the request the actor's.
    #[error("actor statement: {0}")]
    Ais(AisError),
    /// The evaluator refused to evaluate (L0-EVAL-60).
    #[error("rejected: {0:?}")]
    Rejected(Rejection),
    /// The nonce belongs to another intent or actor, or is closed for a batch.
    #[error("nonce conflict")]
    Nonce,
    /// The evaluation needed more state than the pass limit allows.
    #[error("too many passes")]
    Passes,
    /// The sequencer refused the batch.
    #[error("sequencer: {0}")]
    Sequencer(#[from] SequencerError),
    /// Storage failed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// The domain cannot decide now; the PEP retries with the same nonce (OP-141 m.18).
    #[error("unavailable: {0}")]
    Unavailable(&'static str),
}

impl CoreError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Protocol(_) => "protocol",
            Self::Ais(e) => e.code(),
            Self::Rejected(_) => "rejected",
            Self::Nonce => "nonce-conflict",
            Self::Passes => "too-many-passes",
            Self::Sequencer(_) | Self::Store(_) | Self::Unavailable(_) => "unavailable",
        }
    }
}
