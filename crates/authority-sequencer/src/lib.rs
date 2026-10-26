//! CMP-3 sequencer (OP-130 m.1): Kernel records sealed by the ledger engine and committed to
//! the domain log, one leader per domain.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

use access_kernel::record::{LinkError, RecordError};
use access_store::StoreError;
use suiss_ledger::merkle::FrontierError;
use suiss_ledger::sequencer::{OutcomeError, PlanError};
use suiss_ledger::time::TimeError;

impl SequencerError {
    /// Whether the batch was refused by the step 9 checks: the leader stays, the caller
    /// evaluates again (§17.1.1 step 9).
    #[must_use]
    pub const fn is_retry(&self) -> bool {
        matches!(
            self,
            Self::BatchConflict(_)
                | Self::Store(StoreError::Stale | StoreError::Exhausted | StoreError::Consumed)
        )
    }
}

/// Why a sequencer operation failed.
#[derive(Debug, thiserror::Error)]
pub enum SequencerError {
    /// Storage refused; after a failed commit the leader has stepped down.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// A record could not be built.
    #[error("record: {0}")]
    Record(#[from] RecordError),
    /// The batch could not be planned.
    #[error("plan: {0}")]
    Plan(#[from] PlanError<RecordError>),
    /// The engine rejected a commit outcome.
    #[error("outcome: {0}")]
    Outcome(#[from] OutcomeError),
    /// The stored head and the log disagree (§17.6.12: commit stops).
    #[error("stored head does not match the log")]
    Diverged,
    /// The stored frontier does not match the head.
    #[error("frontier: {0}")]
    Frontier(#[from] FrontierError),
    /// Two records do not chain.
    #[error("link: {0}")]
    Link(#[from] LinkError),
    /// The leader stepped down and must be acquired again.
    #[error("leader stepped down")]
    SteppedDown,
    /// The same nonce with a different intent or actor (§9.5 k.5).
    #[error("nonce already used for another intent")]
    NonceConflict,
    /// A batch uses one nonce twice.
    #[error("nonce repeated in one batch")]
    NonceRepeated,
    /// A Genesis record was offered to the log after position 0.
    #[error("genesis only at position 0")]
    Genesis,
    /// A record of the batch depends on an earlier one of the same batch; re-evaluate it.
    #[error("record {0} depends on an earlier record of its batch")]
    BatchConflict(usize),
    /// No trusted time (TI-RT2): commit stops.
    #[error("time: {0}")]
    Time(#[from] TimeError),
}
