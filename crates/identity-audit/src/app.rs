//! One checkpoint step (OP-38): integrate what has ended since the last checkpoint.

use access_store::audit::CheckpointRow;

use crate::AuditError;
use crate::domain::next;
use crate::ports::AuditLog;

/// Most rows one step integrates.
pub const STEP_ROWS: u32 = 10_000;

/// Integrates up to [`STEP_ROWS`] rows after the latest checkpoint and appends the new one.
/// Returns it, or `None` when nothing new ended.
///
/// # Errors
/// [`AuditError`]; a concurrent checkpointer's same-size checkpoint makes this one fail, and
/// the next step continues from whichever was stored.
pub async fn step<L: AuditLog>(log: &L) -> Result<Option<CheckpointRow>, AuditError> {
    let last = log.last().await?;
    let after = last.as_ref().map(|c| c.cursor).unwrap_or_default();
    let rows = log.pending(after, STEP_ROWS).await?;
    let Some(checkpoint) = next(last.as_ref(), &rows)? else {
        return Ok(None);
    };
    log.append(&checkpoint).await?;
    Ok(Some(checkpoint))
}
