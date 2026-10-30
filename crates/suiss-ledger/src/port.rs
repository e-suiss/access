//! The storage port and one commit cycle of the single writer (OP-130 m.1, §17.1.1 steps 10–12,
//! Work T-74 m.1). The product's store implements the port; SQL stays there.

use core::future::Future;

use crate::fence::Fence;
use crate::sequencer::{Batch, Entry, OutcomeError, PlanError, Sequencer};

/// How a store answers an append.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AppendError<E> {
    /// Refused before anything was written for a reason that is not about leadership (a read
    /// set changed, a counter is spent): the writer stays leader.
    #[error("append refused: {0}")]
    Refused(E),
    /// Anything else: the head moved, the epoch is stale, or the outcome is unknown. The writer
    /// steps down and rebuilds from storage.
    #[error("append failed: {0}")]
    Failed(E),
}

/// Durable storage for one log.
pub trait LogStore<S: Sync> {
    /// The store's error.
    type Error;

    /// Writes `batch` in one transaction that succeeds only if the stored head is still at
    /// `batch.after` under `batch.epoch`. It returns `Ok` only once the batch is durable.
    fn append(
        &self,
        batch: &Batch<S>,
    ) -> impl Future<Output = Result<(), AppendError<Self::Error>>> + Send;
}

/// Why a commit cycle did not append.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CommitError<P, E> {
    /// The batch could not be planned.
    #[error("plan: {0}")]
    Plan(PlanError<P>),
    /// The store refused the batch; the writer is still leader.
    #[error("refused: {0}")]
    Refused(E),
    /// The store failed; the writer stepped down.
    #[error("failed: {0}")]
    Failed(E),
    /// The engine and the store disagree about the batch in flight; the writer stepped down.
    #[error("{0}")]
    Outcome(OutcomeError),
}

/// Plans a batch at trusted time `now`, appends it, then advances the head and the fence, or
/// abandons it, or steps down.
///
/// # Errors
/// [`CommitError`].
pub async fn commit<En, St>(
    seq: &mut Sequencer,
    fence: &mut Fence,
    store: &St,
    now: u64,
    entries: &[En],
) -> Result<u64, CommitError<En::Error, St::Error>>
where
    En: Entry,
    En::Sealed: Sync,
    St: LogStore<En::Sealed>,
{
    let batch = seq.plan(now, entries).map_err(CommitError::Plan)?;
    match store.append(&batch).await {
        Ok(()) => {
            let pos = batch.head.pos;
            seq.committed(batch).map_err(CommitError::Outcome)?;
            if fence.advance(pos).is_err() {
                seq.failed();
                return Err(CommitError::Outcome(OutcomeError));
            }
            Ok(pos)
        }
        Err(AppendError::Refused(e)) => {
            seq.abandoned(&batch).map_err(CommitError::Outcome)?;
            Err(CommitError::Refused(e))
        }
        Err(AppendError::Failed(e)) => {
            seq.failed();
            Err(CommitError::Failed(e))
        }
    }
}

#[cfg(test)]
mod tests;
