//! The archive role's daily jobs (OP-73 m.4, m.7; OP-158 m.3 (w)), run on the partition job's
//! tick through the jobs table so that one node of the cell does each per day (OP-129 m.2):
//!
//! - `partitions.close`: the ephemeral protocol day partitions past their TTL are closed, the
//!   one partition drop OP-73 allows.

use std::time::Duration;

use access_store::Pool;
use access_store::StoreError;
use access_store::ephemeral::close_days;
use access_store::jobs::{claim_kind, complete, schedule};

/// The ephemeral close job kind.
pub(crate) const CLOSE: &str = "partitions.close";

/// How long a claim holds (PD).
const LEASE: Duration = Duration::from_mins(15);

const DAY_MS: u64 = 86_400_000;

/// What one [`tick`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Tick {
    /// Ephemeral partitions closed.
    pub(crate) closed: Vec<String>,
    /// Jobs completed.
    pub(crate) completed: u32,
}

/// Schedules today's jobs and runs the ones this node claims.
///
/// # Errors
/// [`StoreError`] when the jobs table cannot be read or written.
pub(crate) async fn tick(
    app: &Pool,
    archive: &Pool,
    worker: &str,
    now_ms: u64,
) -> Result<Tick, StoreError> {
    let today = now_ms / DAY_MS;
    schedule(
        app,
        CLOSE,
        &today.to_string(),
        &format!("{CLOSE}:{today}"),
        Duration::ZERO,
    )
    .await?;
    let mut out = Tick::default();
    for job in claim_kind(app, worker, CLOSE, 4, LEASE).await? {
        // OP-73 m.7, OP-158 m.3 (w)
        match close_days(archive).await {
            Ok(closed) => {
                if !closed.is_empty() {
                    tracing::info!(
                        event = "partitions.closed",
                        closed = closed.len(),
                        "ephemeral protocol partitions closed (OP-73 m.7)"
                    );
                }
                out.closed.extend(closed);
                if complete(app, job.id, worker).await? {
                    out.completed = out.completed.saturating_add(1);
                }
            }
            Err(error) => tracing::warn!(%error, "ephemeral partitions not closed"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
