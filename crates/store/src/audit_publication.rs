//! Where the identity audit log's checkpoints have been published (OP-37, OP-38, U52): one row
//! per declared target and checkpoint size, written once.

use sqlx::PgPool;

use crate::StoreError;
use crate::audit::CheckpointRow;
use crate::identity::Cursor;

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn hash(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// The largest checkpoint size `sink` has, 0 when none.
///
/// # Errors
/// [`StoreError`].
pub async fn published_through(checkpointer: &PgPool, sink: &str) -> Result<u64, StoreError> {
    let size = sqlx::query_scalar!(
        r#"SELECT coalesce(max(size), 0) AS "size!" FROM access_ops.audit_publications WHERE sink = $1"#,
        sink,
    )
    .fetch_one(checkpointer)
    .await?;
    unsigned(size)
}

/// Records that `sink` has the checkpoint of `size`; a second record of the same pair fails.
///
/// # Errors
/// [`StoreError`].
pub async fn record_published(
    checkpointer: &PgPool,
    sink: &str,
    size: u64,
) -> Result<(), StoreError> {
    sqlx::query!(
        "INSERT INTO access_ops.audit_publications (sink, size) VALUES ($1, $2)",
        sink,
        i64::try_from(size).map_err(|_| StoreError::Range)?,
    )
    .execute(checkpointer)
    .await?;
    Ok(())
}

/// The latest signed checkpoint larger than `after`, if any.
///
/// # Errors
/// [`StoreError`].
pub async fn latest_after(
    checkpointer: &PgPool,
    after: u64,
) -> Result<Option<CheckpointRow>, StoreError> {
    let row = sqlx::query!(
        r#"SELECT size, root, frontier, xid::text::bigint AS "xid!", id, note
             FROM access_ops.audit_checkpoint
            WHERE size > $1 AND note IS NOT NULL
            ORDER BY size DESC LIMIT 1"#,
        i64::try_from(after).map_err(|_| StoreError::Range)?,
    )
    .fetch_optional(checkpointer)
    .await?;
    row.map(|r| {
        Ok(CheckpointRow {
            size: unsigned(r.size)?,
            root: hash(r.root)?,
            frontier: r.frontier.into_iter().map(hash).collect::<Result<_, _>>()?,
            cursor: Cursor {
                xid: unsigned(r.xid)?,
                id: r.id,
            },
            note: r.note,
        })
    })
    .transpose()
}
