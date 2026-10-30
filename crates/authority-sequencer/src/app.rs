//! The domain leader (§17.1.1 steps 6, 10–12; OP-31): one writer, fenced by its lease epoch.

use access_crypto::event_id::EventKey;
use access_kernel::digest::Digest;
use access_kernel::model::TrustedTime;
use access_kernel::record::RecordKind;
use access_store::authority::Lease;
use suiss_ledger::sequencer::{Head, Sequencer};

use crate::SequencerError;
use crate::domain::{
    Bound, Item, Outcome, check_effects, check_last, head_of, independent, nonces, replay, rows,
};
use crate::ports::DomainLog;

/// The leader of one domain over a [`DomainLog`].
pub struct Leader<L: DomainLog> {
    log: L,
    domain: Digest,
    lease: Lease,
    seq: Sequencer,
    key: EventKey,
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
        Ok(Self {
            log,
            domain,
            lease,
            seq,
            key,
        })
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

    /// Extends the lease.
    ///
    /// # Errors
    /// [`SequencerError::Store`] with `LeaseLost`; the caller must stop.
    pub async fn renew(&self) -> Result<(), SequencerError> {
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
        let stored = rows(&self.domain.0, &self.key, items, &batch)?;
        match self.log.commit(&stored).await {
            Ok(()) => {
                self.seq.committed(batch)?;
                Ok(Outcome::Appended(
                    stored.records.iter().map(|r| r.pos).collect(),
                ))
            }
            Err(e) if e.is_retry() => {
                // §17.1.1 step 9: nothing was written; the leader stays
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

#[cfg(test)]
mod tests;
