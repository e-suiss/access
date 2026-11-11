//! The domain leader (§17.1.1 steps 6, 10–12; OP-31): one writer, fenced by its lease epoch.

use access_crypto::event_id::EventKey;
use access_kernel::digest::Digest;
use access_kernel::model::TrustedTime;
use access_kernel::record::RecordKind;
use access_store::authority::{Lease, Renewal};
use std::sync::Arc;

use suiss_ledger::doorbell::{Bell, Gate, Ring};
use suiss_ledger::fence::{Cursor, Fence};
use suiss_ledger::sequencer::{Head, Sequencer};

pub mod group;

use crate::SequencerError;
use crate::domain::{
    Bound, Item, Outcome, check_effects, check_last, head_of, independent, nonces, replay, rows,
};
use crate::ports::DomainLog;
use access_store::StoreError;
use access_telemetry::metrics::Stopwatch;
use access_telemetry::signals::{CAS_FAILURES, COMMIT_BATCH_SIZE, COMMIT_DURATION, FENCE_EVENTS};

/// The leader of one domain over a [`DomainLog`].
pub struct Leader<L: DomainLog> {
    log: L,
    domain: Digest,
    lease: Lease,
    seq: Sequencer,
    key: EventKey,
    gate: Gate,
    bell: Option<Arc<dyn Bell>>,
}

impl<L: DomainLog> Leader<L> {
    /// Acquires the domain under a new epoch and checks the stored head against the log's
    /// last record (§17.6.12).
    ///
    /// # Errors
    /// [`SequencerError`]; `Store(LeaseHeld)` while another leader holds the domain.
    pub async fn acquire(log: L, domain: Digest, key: EventKey) -> Result<Self, SequencerError> {
        let (lease, row) = log.acquire().await?;
        let last = log.record(row.pos).await?.ok_or(SequencerError::Diverged)?;
        check_last(&last, &row, &domain)?;
        let seq = Sequencer::lead(lease.epoch, head_of(&row)?);
        let gate = Gate::new(Fence::at(seq.head().pos));
        Ok(Self {
            log,
            domain,
            lease,
            seq,
            key,
            gate,
            bell: None,
        })
    }

    /// Rings `bell` after each durable commit with outbox events (OP-156 m.3 (j), T26).
    #[must_use]
    pub fn with_bell(mut self, bell: Arc<dyn Bell>) -> Self {
        self.bell = Some(bell);
        self
    }

    /// The last committed head.
    #[must_use]
    pub const fn head(&self) -> &Head {
        self.seq.head()
    }

    /// The fencing epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.lease.epoch
    }

    /// Extends the lease; [`Renewal::HandoffRequested`] asks the caller to release it
    /// (OP-149 m.28 (a)).
    ///
    /// # Errors
    /// [`SequencerError::Store`] with `LeaseLost`; the caller must stop.
    pub async fn renew(&self) -> Result<Renewal, SequencerError> {
        self.log.renew(self.lease).await
    }

    /// Releases the lease after the last batch (OP-31).
    ///
    /// # Errors
    /// [`SequencerError::Store`].
    pub async fn release(self) -> Result<(), SequencerError> {
        self.log.release(self.lease).await
    }

    /// Appends `items` as one batch at trusted time `now`. Nothing is acknowledged unless the
    /// whole batch committed (TI-6); on a failed commit the leader steps down.
    ///
    /// # Errors
    /// [`SequencerError`]; after `Store(HeadMoved)` or any commit failure the leader is unusable.
    pub async fn commit(
        &mut self,
        now: TrustedTime,
        items: &[Item],
    ) -> Result<Outcome, SequencerError> {
        if self.seq.stepped_down() {
            return Err(SequencerError::SteppedDown);
        }
        if items.iter().any(|i| i.draft.kind == RecordKind::Genesis) {
            return Err(SequencerError::Genesis);
        }
        independent(items)?;
        check_effects(items)?;
        for n in nonces(items)? {
            if let Some(stored) = self.log.nonce(&n.nonce).await?
                && let Some(pos) = replay(n, &stored, items.len() == 1)?
            {
                return Ok(Outcome::Replayed(pos));
            }
        }
        let entries: Vec<Bound<'_>> = items
            .iter()
            .map(|i| Bound {
                domain: self.domain,
                draft: &i.draft,
            })
            .collect();
        let batch = self.seq.plan(now, &entries)?;
        let mut stored = match rows(&self.domain.0, &self.key, items, &batch) {
            Ok(stored) => stored,
            Err(e) => {
                self.seq.failed();
                return Err(e);
            }
        };
        // OP-67 m.1
        let trace_parent = access_telemetry::trace::current_header();
        for row in &mut stored.outbox {
            row.trace_parent.clone_from(&trace_parent);
        }
        let watch = Stopwatch::start();
        let committed = self.log.commit(&stored).await;
        observe(&committed, watch, items.len());
        match committed {
            Ok(()) => {
                self.seq.committed(batch)?;
                self.ring(&stored);
                Ok(Outcome::Appended(
                    stored.records.iter().map(|r| r.pos).collect(),
                ))
            }
            Err(e) if e.is_retry() => {
                // §17.1.1 step 9
                self.seq.abandoned(&batch)?;
                Err(e)
            }
            Err(e) => {
                // §17.1.1 step 12
                self.seq.failed();
                Err(e)
            }
        }
    }
}

impl<L: DomainLog> Leader<L> {
    /// TI-6, OP-156 m.3 (j): the fence moves to the committed head, then the batch's last
    /// outbox event rings the bell; a ring the fence does not cover never leaves.
    fn ring(&mut self, stored: &access_store::authority::CommitBatch) {
        if self.gate.fence().advance(self.seq.head().pos).is_err() {
            return;
        }
        let (Some(bell), Some(last)) = (self.bell.as_deref(), stored.outbox.last()) else {
            return;
        };
        let ring = Ring {
            domain: self.domain.0,
            at: Cursor {
                pos: last.pos,
                idx: last.idx,
            },
            id: last.event_id,
        };
        self.gate.release(ring, bell);
    }
}

/// §17.8.2: commit latency and batch size; a moved head is a CAS failure and a lost lease a
/// fence event (TI-2, FA-13). Telemetry only (TI-18).
fn observe(committed: &Result<(), SequencerError>, watch: Stopwatch, batch: usize) {
    let outcome = match committed {
        Ok(()) => {
            COMMIT_BATCH_SIZE.record(f64::from(u32::try_from(batch).unwrap_or(u32::MAX)), []);
            "ok"
        }
        Err(e) if e.is_retry() => "retry",
        Err(SequencerError::Store(StoreError::HeadMoved)) => {
            CAS_FAILURES.incr([]);
            tracing::warn!(
                event = "sequencer.cas.failed",
                outcome = "stepped_down",
                "the domain head moved under the leader (TI-2)"
            );
            "error"
        }
        Err(SequencerError::Store(StoreError::LeaseLost)) => {
            fenced("lease_lost");
            "error"
        }
        Err(_) => "error",
    };
    COMMIT_DURATION.record_duration(watch.elapsed(), [outcome]);
}

/// Counts and logs a fence event (§17.8.2, TI-2, FA-13).
pub fn fenced(reason: &'static str) {
    FENCE_EVENTS.incr([reason]);
    tracing::warn!(
        event = "sequencer.fenced",
        outcome = "fenced",
        reason,
        "the sequencer leader was fenced (TI-2)"
    );
}

#[cfg(test)]
mod tests;
