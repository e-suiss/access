//! The cold tier move (OP-40, OP-73 m.4, OP-158 m.3 (w)): a due partition is copied to the cold
//! store, the stored object is read back and checked against the partition's root, and only then
//! is the partition detached. A partition whose copy fails or does not match stays hot.

use access_store::audit::AuditRow;
use access_store::audit_tier::{Due, Moved};
use access_store::identity::Cursor;

use crate::AuditError;
use crate::domain::Leaf as _;
use crate::domain::tier::{check_copy, object_key, root};
use crate::ports::{ColdCodec, ColdStore, Tiers};

/// Rows read per page.
const PAGE: u32 = 10_000;

/// What one run moved.
#[derive(Debug, Default)]
pub struct TierRun {
    /// The partitions now in the cold tier.
    pub moved: Vec<Moved>,
    /// Partitions left hot, with why.
    pub failed: Vec<(String, AuditError)>,
}

async fn all_rows<T: Tiers>(tiers: &T, partition: &str) -> Result<Vec<AuditRow>, AuditError> {
    let mut out: Vec<AuditRow> = Vec::new();
    let mut after = Cursor::default();
    loop {
        let page = tiers.rows(partition, after, PAGE).await?;
        let Some(last) = page.last() else {
            return Ok(out);
        };
        after = last.cursor();
        let full = page.len() == PAGE as usize;
        out.extend(page);
        if !full {
            return Ok(out);
        }
    }
}

/// Copies, verifies and detaches one due partition.
///
/// # Errors
/// [`AuditError`]; the partition stays hot.
pub async fn move_one<T: Tiers, S: ColdStore, C: ColdCodec>(
    (tiers, cold, codec): (&T, &S, &C),
    due: &Due,
) -> Result<Moved, AuditError> {
    let rows = all_rows(tiers, &due.partition).await?;
    let file = codec.encode(&rows)?;
    let key = object_key(&due.partition, due.month);
    cold.put(&key, &file).await?;
    let stored = cold
        .get(&key)
        .await?
        .ok_or_else(|| AuditError::Cold(String::from("object missing after write")))?;
    let root = check_copy(&rows, &codec.decode(&stored)?)?;
    let moved = Moved {
        partition: due.partition.clone(),
        tenant: due.tenant,
        rows: u64::try_from(rows.len()).map_err(|_| AuditError::Encode)?,
        root,
        object_key: key,
        object_sha256: suiss_crypto::digest::sha256(&stored),
        last: rows.last().map(AuditRow::cursor),
    };
    tiers.detach(&moved).await?;
    Ok(moved)
}

/// Moves every due partition; one that fails stays hot and is tried on the next run.
///
/// # Errors
/// [`AuditError`] when the due list cannot be read.
pub async fn move_due<T: Tiers, S: ColdStore, C: ColdCodec>(
    tiers: &T,
    cold: &S,
    codec: &C,
) -> Result<TierRun, AuditError> {
    let mut run = TierRun::default();
    for due in tiers.due().await? {
        match move_one((tiers, cold, codec), &due).await {
            Ok(m) => run.moved.push(m),
            Err(e) => run.failed.push((due.partition, e)),
        }
    }
    Ok(run)
}

/// The rows of a moved partition, read back from the cold tier and checked against the root
/// recorded when it moved: the cold half of the queryable window (OP-158 m.3 (w)).
///
/// # Errors
/// [`AuditError::ColdMismatch`] when the object is not the copy that was moved;
/// [`AuditError`] otherwise.
pub async fn read_moved<S: ColdStore, C: ColdCodec>(
    (cold, codec): (&S, &C),
    moved: &Moved,
) -> Result<Vec<AuditRow>, AuditError> {
    let file = cold
        .get(&moved.object_key)
        .await?
        .ok_or_else(|| AuditError::Cold(String::from("object missing")))?;
    if suiss_crypto::digest::sha256(&file) != moved.object_sha256 {
        return Err(AuditError::ColdMismatch);
    }
    let rows = codec.decode(&file)?;
    if u64::try_from(rows.len()).ok() != Some(moved.rows) || root(&rows)? != moved.root {
        return Err(AuditError::ColdMismatch);
    }
    Ok(rows)
}
