//! Single-writer sequencer for one log (OP-8, OP-130 m.1, §17.1.1 steps 10–12).
//!
//! The sequencer assigns positions, chain links and `recorded_at` to a batch and advances its
//! head only after the driver reports a durable commit. A failed commit steps it down: it
//! drops its state and must be rebuilt from storage under a new epoch (TI-2, TI-9).

use alloc::vec::Vec;

use crate::Hash;
use crate::merkle::{Frontier, FrontierError};

/// Most records in one batch (OP-130 m.6, PD).
pub const MAX_BATCH: usize = 256;

/// The last committed record of a log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    /// Position of the last record.
    pub pos: u64,
    /// Its leaf hash.
    pub leaf: Hash,
    /// Its `recorded_at`.
    pub recorded_at: u64,
    /// Merkle frontier over positions `0..=pos`.
    pub frontier: Frontier,
}

/// The header slot the sequencer gives one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    /// Position.
    pub pos: u64,
    /// Leaf hash of the previous record.
    pub prev: Hash,
    /// Trusted time, never below the previous record's (TI-19).
    pub recorded_at: u64,
}

/// A record that can be sealed once its slot is known.
pub trait Entry {
    /// The sealed form handed to storage.
    type Sealed;
    /// Why sealing failed.
    type Error;

    /// Builds the record for `slot` and returns its leaf hash with the sealed form.
    ///
    /// # Errors
    /// The entry's own error.
    fn seal(&self, slot: &Slot) -> Result<(Hash, Self::Sealed), Self::Error>;
}

/// One sealed record of a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed<S> {
    /// Its slot.
    pub slot: Slot,
    /// Its leaf hash.
    pub leaf: Hash,
    /// The sealed form.
    pub record: S,
}

/// A planned batch: the storage commit must succeed only if the stored head is still at
/// `after` under `epoch` (head CAS, OP-130 m.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch<S> {
    /// Leader epoch.
    pub epoch: u64,
    /// Head position the batch extends.
    pub after: u64,
    /// The records, in position order.
    pub records: Vec<Sealed<S>>,
    /// The head after a successful commit.
    pub head: Head,
}

/// Why a batch could not be planned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlanError<E> {
    /// The sequencer stepped down.
    #[error("sequencer stepped down")]
    SteppedDown,
    /// A batch is already waiting for its commit outcome.
    #[error("a batch is in flight")]
    InFlight,
    /// No entries, or more than [`MAX_BATCH`].
    #[error("batch size out of range")]
    Size,
    /// Positions or the tree would overflow.
    #[error("log position overflow")]
    Overflow,
    /// An entry could not be sealed.
    #[error("entry could not be sealed")]
    Seal(E),
}

/// A commit outcome reported for a batch that is not the one in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("commit outcome for a batch that is not in flight")]
pub struct OutcomeError;

/// The sequencer of one log under one epoch.
#[derive(Clone, Debug)]
pub struct Sequencer {
    epoch: u64,
    head: Head,
    in_flight: Option<u64>,
    down: bool,
}

impl Sequencer {
    /// Leads a log from its stored head under a freshly acquired epoch.
    #[must_use]
    pub const fn lead(epoch: u64, head: Head) -> Self {
        Self {
            epoch,
            head,
            in_flight: None,
            down: false,
        }
    }

    /// The last committed head.
    #[must_use]
    pub const fn head(&self) -> &Head {
        &self.head
    }

    /// The leader epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Whether the sequencer stepped down.
    #[must_use]
    pub const fn stepped_down(&self) -> bool {
        self.down
    }

    /// Plans the next batch at trusted time `now` (§17.1.1 step 10).
    ///
    /// # Errors
    /// [`PlanError`].
    pub fn plan<E: Entry>(
        &mut self,
        now: u64,
        entries: &[E],
    ) -> Result<Batch<E::Sealed>, PlanError<E::Error>> {
        if self.down {
            return Err(PlanError::SteppedDown);
        }
        if self.in_flight.is_some() {
            return Err(PlanError::InFlight);
        }
        if entries.is_empty() || entries.len() > MAX_BATCH {
            return Err(PlanError::Size);
        }
        // TI-19
        let recorded_at = now.max(self.head.recorded_at);
        let mut frontier = self.head.frontier.clone();
        let mut prev = self.head.leaf;
        let mut pos = self.head.pos;
        let mut records = Vec::with_capacity(entries.len());
        for entry in entries {
            pos = pos.checked_add(1).ok_or(PlanError::Overflow)?;
            let slot = Slot {
                pos,
                prev,
                recorded_at,
            };
            let (leaf, record) = entry.seal(&slot).map_err(PlanError::Seal)?;
            frontier
                .push(leaf)
                .map_err(|FrontierError| PlanError::Overflow)?;
            records.push(Sealed { slot, leaf, record });
            prev = leaf;
        }
        self.in_flight = Some(pos);
        Ok(Batch {
            epoch: self.epoch,
            after: self.head.pos,
            records,
            head: Head {
                pos,
                leaf: prev,
                recorded_at,
                frontier,
            },
        })
    }

    /// Advances the head after the driver committed `batch` durably (TI-6).
    ///
    /// # Errors
    /// [`OutcomeError`] when `batch` is not the batch in flight; the sequencer steps down.
    pub fn committed<S>(&mut self, batch: Batch<S>) -> Result<(), OutcomeError> {
        if self.down
            || self.in_flight != Some(batch.head.pos)
            || batch.after != self.head.pos
            || batch.epoch != self.epoch
        {
            self.step_down();
            return Err(OutcomeError);
        }
        self.head = batch.head;
        self.in_flight = None;
        Ok(())
    }

    /// The commit or its head CAS failed: the sequencer steps down and sends no ack
    /// (§17.1.1 step 12).
    pub fn failed(&mut self) {
        self.step_down();
    }

    fn step_down(&mut self) {
        self.down = true;
        self.in_flight = None;
    }
}

#[cfg(test)]
mod tests;
