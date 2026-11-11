//! The archive role's daily jobs (OP-73 m.4, m.7; OP-158 m.3 (w)), run on the partition job's
//! tick through the jobs table so that one node of the cell does each per day (OP-129 m.2):
//!
//! - `partitions.close`: the ephemeral protocol day partitions past their TTL are closed, the
//!   one partition drop OP-73 allows.
//! - `audit.tier`: identity audit partitions past their hot window, every row checkpointed, are
//!   copied to the cold tier, checked against their root and detached (OP-40, OP-73 m.4). With
//!   no cold tier configured every partition stays hot.

use std::path::Path;
use std::time::Duration;

use access_identity_audit::adapters::PgTiers;
use access_identity_audit::app::tier::move_due;
use access_identity_export::adapters::cold_file::FileCold;
use access_identity_export::domain::cold::ColdParquet;
use access_store::Pool;
use access_store::StoreError;
use access_store::audit_tier::Moved;
use access_store::ephemeral::close_days;
use access_store::jobs::{claim_kind, complete, schedule};
use access_store::operational::{OperationalEvent, record_operational};

/// The ephemeral close job kind.
pub(crate) const CLOSE: &str = "partitions.close";

/// The cold tier move job kind.
pub(crate) const TIER: &str = "audit.tier";

/// How long a claim holds (PD).
const LEASE: Duration = Duration::from_mins(15);

const DAY_MS: u64 = 86_400_000;

/// What one [`tick`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Tick {
    /// Ephemeral partitions closed.
    pub(crate) closed: Vec<String>,
    /// Identity audit partitions moved to the cold tier.
    pub(crate) moved: Vec<String>,
    /// Identity audit partitions left hot after a failed move.
    pub(crate) kept_hot: u32,
    /// Jobs completed.
    pub(crate) completed: u32,
}

async fn close(archive: &Pool, out: &mut Tick) -> bool {
    match close_days(archive).await {
        Ok(closed) => {
            for partition in &closed {
                tracing::info!(
                    event = "ephemeral.partition.dropped",
                    %partition,
                    "ephemeral protocol partition closed (OP-73 m.7)"
                );
            }
            out.closed.extend(closed);
            true
        }
        Err(error) => {
            tracing::warn!(%error, "ephemeral partitions not closed");
            false
        }
    }
}

/// Writes `audit.tier_moved` for a moved partition to the operational audit stream (OP-44).
async fn audited(app: &Pool, moved: &Moved, now_ms: u64) -> Result<(), StoreError> {
    let root = moved
        .root
        .iter()
        .take(8)
        .fold(String::from("root:"), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
    record_operational(
        app,
        &OperationalEvent {
            occurred_at_ms: now_ms,
            tenant: moved.tenant,
            domain: None,
            event_type: "audit.tier_moved",
            actor: "archive",
            target: &moved.partition,
            reason: "",
            correlation: &root,
        },
    )
    .await
}

async fn tier(app: &Pool, archive: &Pool, (cold, now_ms): (&Path, u64), out: &mut Tick) -> bool {
    let store = FileCold {
        root: cold.to_path_buf(),
    };
    match move_due(&PgTiers(archive.clone()), &store, &ColdParquet).await {
        Ok(run) => {
            for (partition, error) in &run.failed {
                tracing::warn!(%error, %partition, "audit partition stays hot");
            }
            out.kept_hot = out
                .kept_hot
                .saturating_add(u32::try_from(run.failed.len()).unwrap_or(u32::MAX));
            for m in run.moved {
                tracing::info!(
                    event = "audit.partition.detached",
                    partition = %m.partition,
                    "audit partition moved to the cold tier (OP-73 m.4)"
                );
                if let Err(error) = audited(app, &m, now_ms).await {
                    tracing::error!(%error, partition = %m.partition, "audit.tier_moved not recorded");
                }
                out.moved.push(m.partition);
            }
            true
        }
        Err(error) => {
            tracing::warn!(%error, "audit partitions not listed");
            false
        }
    }
}

/// Schedules today's jobs and runs the ones this node claims; `cold` is the cold tier's
/// directory, when there is one.
///
/// # Errors
/// [`StoreError`] when the jobs table cannot be read or written.
pub(crate) async fn tick(
    app: &Pool,
    archive: &Pool,
    worker: &str,
    (now_ms, cold): (u64, Option<&Path>),
) -> Result<Tick, StoreError> {
    let today = now_ms / DAY_MS;
    let mut kinds = vec![CLOSE];
    if cold.is_some() {
        kinds.push(TIER);
    }
    for kind in &kinds {
        schedule(
            app,
            kind,
            &today.to_string(),
            &format!("{kind}:{today}"),
            Duration::ZERO,
        )
        .await?;
    }
    let mut out = Tick::default();
    for kind in kinds {
        for job in claim_kind(app, worker, kind, 4, LEASE).await? {
            // OP-73 m.4, m.7; OP-158 m.3 (w)
            let done = match (kind, cold) {
                (CLOSE, _) => close(archive, &mut out).await,
                (_, Some(dir)) => tier(app, archive, (dir, now_ms), &mut out).await,
                (_, None) => false,
            };
            if done && complete(app, job.id, worker).await? {
                out.completed = out.completed.saturating_add(1);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
