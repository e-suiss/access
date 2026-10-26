//! Pure sequencer logic (OP-8, OP-63): sealing Kernel records into slots, the nonce replay
//! rule, and the rows one batch writes.

use std::collections::{BTreeMap, BTreeSet};

use access_crypto::event_id::EventKey;
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::record::{Header, Opened, RecordEnvelope, RecordError, RecordKind};
use access_store::authority::{CommitBatch, HeadRow, LogRecord, NonceRow, OutboxRow, ProofRow};
use suiss_ledger::Hash;
use suiss_ledger::merkle::Frontier;
use suiss_ledger::sequencer::{Batch, Entry, Head, Slot};

use crate::SequencerError;

/// A record's kind and fields; the header comes from the sequencer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draft {
    /// `opening`, `decision` or `claim`.
    pub kind: RecordKind,
    /// Fields with their salts.
    pub fields: BTreeMap<String, Opened>,
}

/// The nonce an opening or decision consumes (TI-8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceUse {
    /// The request nonce.
    pub nonce: Vec<u8>,
    /// Actor reference.
    pub actor: Vec<u8>,
    /// Intent digest, computed by Access (§17.1.1 step 4).
    pub intent_digest: [u8; 32],
}

/// One record to append with what it writes alongside.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// The record.
    pub draft: Draft,
    /// The nonce it consumes, if any.
    pub nonce: Option<NonceUse>,
    /// Semantic events derived from it (outbox, OP-130 m.9).
    pub events: Vec<Vec<u8>>,
    /// Signed bytes it cites, as (digest, bytes) (§17.6.1 rule 2).
    pub proofs: Vec<([u8; 32], Vec<u8>)>,
}

/// What a commit produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Appended at these positions.
    Appended(Vec<u64>),
    /// A retry of an already committed nonce: the position of its record, nothing appended
    /// (§9.5 k.5).
    Replayed(u64),
}

/// A record as sealed for storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRecord {
    /// Its kind.
    pub kind: RecordKind,
    /// Canonical bytes of the full envelope.
    pub envelope: Vec<u8>,
}

/// A draft bound to its domain.
pub struct Bound<'a> {
    /// The domain.
    pub domain: Digest,
    /// The draft.
    pub draft: &'a Draft,
}

impl Entry for Bound<'_> {
    type Sealed = SealedRecord;
    type Error = RecordError;

    fn seal(&self, slot: &Slot) -> Result<(Hash, SealedRecord), RecordError> {
        // L0-ENC-27: every record after Genesis carries `domain` and `prev`
        let envelope = RecordEnvelope {
            header: Header {
                domain: Some(self.domain),
                pos: slot.pos,
                kind: self.draft.kind,
                recorded_at: slot.recorded_at,
                prev: Some(Digest(slot.prev)),
            },
            fields: self.draft.fields.clone(),
        };
        let leaf = envelope.leaf_hash()?;
        let bytes = envelope.to_bytes()?;
        Ok((
            leaf,
            SealedRecord {
                kind: self.draft.kind,
                envelope: bytes,
            },
        ))
    }
}

/// The store's name for a kind.
#[must_use]
pub const fn kind_name(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Genesis => "genesis",
        RecordKind::Opening => "opening",
        RecordKind::Decision => "decision",
        RecordKind::Claim => "claim",
    }
}

/// The engine head for a stored head row.
///
/// # Errors
/// [`SequencerError`] when the frontier does not fit the position.
pub fn head_of(row: &HeadRow) -> Result<Head, SequencerError> {
    let size = row.pos.checked_add(1).ok_or(SequencerError::Diverged)?;
    Ok(Head {
        pos: row.pos,
        leaf: row.leaf_hash,
        recorded_at: row.recorded_at,
        frontier: Frontier::from_parts(size, row.frontier.clone())?,
    })
}

/// Checks a stored last record against its head row and domain (§17.6.12).
///
/// # Errors
/// [`SequencerError::Diverged`].
pub fn check_last(last: &LogRecord, head: &HeadRow, domain: &Digest) -> Result<(), SequencerError> {
    let envelope =
        RecordEnvelope::from_bytes(&last.envelope).map_err(|_| SequencerError::Diverged)?;
    if last.pos != head.pos
        || last.leaf_hash != head.leaf_hash
        || envelope.leaf_hash()? != head.leaf_hash
        || envelope.domain()? != *domain
    {
        return Err(SequencerError::Diverged);
    }
    Ok(())
}

/// The nonces a batch consumes, refusing one used twice in it.
///
/// # Errors
/// [`SequencerError::NonceRepeated`].
pub fn nonces(items: &[Item]) -> Result<Vec<&NonceUse>, SequencerError> {
    let mut seen = BTreeSet::new();
    let out: Vec<&NonceUse> = items.iter().filter_map(|i| i.nonce.as_ref()).collect();
    if out.iter().any(|n| !seen.insert(n.nonce.as_slice())) {
        return Err(SequencerError::NonceRepeated);
    }
    Ok(out)
}

/// The replay rule for a nonce already committed (§9.5 k.5, TI-8): a lone retry with the same
/// intent and actor gets the committed record back; anything else is a conflict.
///
/// # Errors
/// [`SequencerError::NonceConflict`].
pub fn replay(wanted: &NonceUse, stored: &NonceRow, lone: bool) -> Result<u64, SequencerError> {
    if lone && stored.intent_digest == wanted.intent_digest && stored.actor == wanted.actor {
        return Ok(stored.decision_pos);
    }
    Err(SequencerError::NonceConflict)
}

/// The rows a planned batch writes in its single transaction (T7, OP-130 m.6).
///
/// # Errors
/// [`SequencerError::Diverged`] when an index does not fit.
pub fn rows(
    domain: &[u8; 32],
    key: &EventKey,
    items: &[Item],
    batch: &Batch<SealedRecord>,
) -> Result<CommitBatch, SequencerError> {
    let mut out = CommitBatch {
        epoch: batch.epoch,
        after: batch.after,
        records: Vec::with_capacity(items.len()),
        head: HeadRow {
            pos: batch.head.pos,
            epoch: batch.epoch,
            leaf_hash: batch.head.leaf,
            recorded_at: batch.head.recorded_at,
            frontier: batch.head.frontier.nodes().to_vec(),
        },
        nonces: Vec::new(),
        outbox: Vec::new(),
        proofs: Vec::new(),
    };
    for (item, sealed) in items.iter().zip(&batch.records) {
        let pos = sealed.slot.pos;
        out.records.push(LogRecord {
            pos,
            kind: kind_name(sealed.record.kind),
            recorded_at: sealed.slot.recorded_at,
            leaf_hash: sealed.leaf,
            envelope: sealed.record.envelope.clone(),
        });
        if let Some(n) = &item.nonce {
            out.nonces.push(NonceRow {
                nonce: n.nonce.clone(),
                actor: n.actor.clone(),
                intent_digest: n.intent_digest,
                decision_pos: pos,
            });
        }
        for (idx, event) in item.events.iter().enumerate() {
            let idx = u32::try_from(idx).map_err(|_| SequencerError::Diverged)?;
            out.outbox.push(OutboxRow {
                pos,
                idx,
                event_id: key.event_id(domain, pos, idx),
                event: event.clone(),
            });
        }
        for (digest, bytes) in &item.proofs {
            out.proofs.push(ProofRow {
                digest: *digest,
                bytes: bytes.clone(),
            });
        }
    }
    Ok(out)
}
