//! Audit leaves and the tree step (OP-37): pure.

use access_kernel::digest;
use access_store::audit::{AuditRow, CheckpointRow};
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

/// The next checkpoint after `last` with `rows` integrated, in their order; `None` without rows
/// (OP-38: no empty checkpoint).
///
/// # Errors
/// [`AuditError`].
pub fn next(
    last: Option<&CheckpointRow>,
    rows: &[AuditRow],
) -> Result<Option<CheckpointRow>, AuditError> {
    let Some(final_row) = rows.last() else {
        return Ok(None);
    };
    let mut frontier = match last {
        Some(c) => Frontier::from_parts(c.size, c.frontier.clone())?,
        None => Frontier::default(),
    };
    for row in rows {
        frontier.push(leaf(row)?)?;
    }
    Ok(Some(CheckpointRow {
        size: frontier.size(),
        root: frontier.root(),
        frontier: frontier.nodes().to_vec(),
        cursor: access_store::identity::Cursor {
            xid: final_row.xid,
            id: final_row.id,
        },
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
