//! What the leader needs from storage (OP-63): the store adapter implements it over
//! PostgreSQL, a deterministic simulation can implement it in memory (OP-8).

use std::future::Future;

use access_store::authority::{CommitBatch, HeadRow, Lease, LogRecord, NonceRow};

use crate::SequencerError;

/// One domain's log as seen by its leader.
pub trait DomainLog {
    /// Takes the lease under a new epoch that fences the head; returns the stored head.
    fn acquire(&self) -> impl Future<Output = Result<(Lease, HeadRow), SequencerError>> + Send;
    /// Extends the lease.
    fn renew(&self, lease: Lease) -> impl Future<Output = Result<(), SequencerError>> + Send;
    /// Gives the lease up.
    fn release(&self, lease: Lease) -> impl Future<Output = Result<(), SequencerError>> + Send;
    /// The record at `pos`.
    fn record(
        &self,
        pos: u64,
    ) -> impl Future<Output = Result<Option<LogRecord>, SequencerError>> + Send;
    /// A committed nonce.
    fn nonce(
        &self,
        nonce: &[u8],
    ) -> impl Future<Output = Result<Option<NonceRow>, SequencerError>> + Send;
    /// Commits a batch atomically behind the head compare-and-set.
    fn commit(
        &self,
        batch: &CommitBatch,
    ) -> impl Future<Output = Result<(), SequencerError>> + Send;
}

/// Trusted time (OP-63, OP-129 m.1): never read from the system clock directly.
pub trait Clock {
    /// Trusted time in Unix milliseconds; an error means no commit.
    fn now(&mut self) -> impl Future<Output = Result<u64, SequencerError>> + Send;
}
