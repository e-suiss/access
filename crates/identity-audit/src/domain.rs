//! Audit leaves and the tree step (OP-37): pure.

pub mod realm;
pub mod record;
pub mod taxonomy;
pub mod tier;
pub mod tiles;

use access_kernel::digest;
use access_store::audit::{AuditRow, CheckpointRow};
use access_store::identity::Cursor;
use access_store::operational::OperationalRow;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::note::{Checkpoint, NoteError, Verifier, verify_checkpoint};
use suiss_crypto::sig::Backend;
use suiss_ledger::Hash;
use suiss_ledger::merkle::Frontier;

use crate::AuditError;

fn uint(v: i64) -> Result<Value, AuditError> {
    u64::try_from(v)
        .map(Value::Unsigned)
        .map_err(|_| AuditError::Encode)
}

/// `SHA-256(0x00 ‖ dCBOR(row))`, the row's leaf in the audit tree (L0-ENC-24's prefixes).
///
/// # Errors
/// [`AuditError::Encode`].
pub fn leaf(row: &AuditRow) -> Result<Hash, AuditError> {
    let value = Value::Map(vec![
        (Value::text("tenant"), Value::Bytes(row.tenant.to_vec())),
        (Value::text("realm"), Value::Bytes(row.realm.to_vec())),
        (Value::text("at"), uint(row.at_ms)?),
        (Value::text("id"), uint(row.id)?),
        (Value::text("event_type"), Value::text(&row.event_type)),
        (Value::text("actor"), Value::text(&row.actor)),
        (Value::text("target"), Value::text(&row.target)),
        (Value::text("correlation"), Value::text(&row.correlation)),
    ]);
    let bytes = dcbor::encode(&value, Limits::CEILING).map_err(|_| AuditError::Encode)?;
    Ok(digest::leaf_hash(&bytes))
}

/// `SHA-256(0x00 ‖ dCBOR(row))` of an operational audit row (OP-39, OP-44); the `chain` member
/// keeps its leaves apart from the identity log's.
///
/// # Errors
/// [`AuditError::Encode`].
pub fn operational_leaf(row: &OperationalRow) -> Result<Hash, AuditError> {
    let mut entries = vec![
        (
            Value::text("chain"),
            Value::text(access_identity_signer::cell::OPERATIONAL_CHAIN),
        ),
        (Value::text("at"), uint(row.at_ms)?),
        (Value::text("id"), uint(row.id)?),
        (
            Value::text("occurred_at"),
            Value::Unsigned(row.occurred_at_ms),
        ),
        (Value::text("event_type"), Value::text(&row.event_type)),
        (Value::text("actor"), Value::text(&row.actor)),
        (Value::text("target"), Value::text(&row.target)),
        (Value::text("reason"), Value::text(&row.reason)),
        (Value::text("correlation"), Value::text(&row.correlation)),
    ];
    if let Some(t) = row.tenant {
        entries.push((Value::text("tenant"), Value::Bytes(t.to_vec())));
    }
    if let Some(d) = row.domain {
        entries.push((Value::text("domain"), Value::Bytes(d.to_vec())));
    }
    let bytes =
        dcbor::encode(&Value::Map(entries), Limits::CEILING).map_err(|_| AuditError::Encode)?;
    Ok(digest::leaf_hash(&bytes))
}

/// A row a checkpoint integrates.
pub trait Leaf {
    /// Its leaf hash.
    ///
    /// # Errors
    /// [`AuditError::Encode`].
    fn leaf(&self) -> Result<Hash, AuditError>;
    /// Where it sits in integration order.
    fn cursor(&self) -> Cursor;
}

impl Leaf for AuditRow {
    fn leaf(&self) -> Result<Hash, AuditError> {
        leaf(self)
    }

    fn cursor(&self) -> Cursor {
        Cursor {
            xid: self.xid,
            id: self.id,
        }
    }
}

impl Leaf for OperationalRow {
    fn leaf(&self) -> Result<Hash, AuditError> {
        operational_leaf(self)
    }

    fn cursor(&self) -> Cursor {
        Cursor {
            xid: self.xid,
            id: self.id,
        }
    }
}

/// The next checkpoint after `last` with `rows` integrated, in their order; `None` without rows
/// (OP-38: no empty checkpoint).
///
/// # Errors
/// [`AuditError`].
pub fn next<R: Leaf>(
    last: Option<&CheckpointRow>,
    rows: &[R],
) -> Result<Option<CheckpointRow>, AuditError> {
    let Some(final_row) = rows.last() else {
        return Ok(None);
    };
    let mut frontier = match last {
        Some(c) => Frontier::from_parts(c.size, c.frontier.clone())?,
        None => Frontier::default(),
    };
    for row in rows {
        frontier.push(row.leaf()?)?;
    }
    Ok(Some(CheckpointRow {
        size: frontier.size(),
        root: frontier.root(),
        frontier: frontier.nodes().to_vec(),
        cursor: final_row.cursor(),
        note: None,
    }))
}

/// The checkpoint's last line: the signing time in Unix milliseconds (OP-143 m.10).
pub const ISSUED_AT: &str = "issued_at ";

/// The `tlog-checkpoint` body of `checkpoint` in the log `origin`, issued at `issued_at`.
///
/// # Errors
/// [`AuditError::Note`] for an origin that cannot name a log.
pub fn body(
    origin: &str,
    checkpoint: &CheckpointRow,
    issued_at: u64,
) -> Result<String, AuditError> {
    Ok(Checkpoint {
        origin: origin.to_owned(),
        size: checkpoint.size,
        root: checkpoint.root,
        extensions: vec![format!("{ISSUED_AT}{issued_at}")],
    }
    .to_body()?)
}

/// Verifies a checkpoint's signed note under the cell key `vkey` (L2-CKP-3): the note verifies,
/// names `origin`, and states the stored size and root. Returns its `issued_at`.
///
/// # Errors
/// [`AuditError::Note`].
pub fn verify(
    backend: &impl Backend,
    checkpoint: &CheckpointRow,
    origin: &str,
    vkey: &str,
) -> Result<u64, AuditError> {
    let note = checkpoint.note.as_deref().ok_or(NoteError::Unverified)?;
    let key = Verifier::parse(vkey)?;
    let (cp, _) = verify_checkpoint(backend, note, origin, &key, &[])?;
    if cp.size != checkpoint.size || cp.root != checkpoint.root {
        return Err(NoteError::Checkpoint.into());
    }
    let [line] = cp.extensions.as_slice() else {
        return Err(NoteError::Checkpoint.into());
    };
    line.strip_prefix(ISSUED_AT)
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        .filter(|n| n.len() == 1 || !n.starts_with('0'))
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| NoteError::Checkpoint.into())
}
