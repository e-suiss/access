//! The day-partition opener of the ephemeral protocol tables (OP-146 m.5 (f), m.7 (d)), run
//! through the jobs table (OP-129 m.2) so that one node of the cell does it per day: each
//! node schedules today's job, one claims it and opens today and the days ahead as the
//! archive role. Closing old days is not done here (OP-73).

use std::time::Duration;

use access_store::Pool;
use access_store::StoreError;
use access_store::ephemeral::open_days;
use access_store::jobs::{claim_kind, complete, schedule};

/// The job kind.
pub(crate) const KIND: &str = "partitions.open";

/// Days opened ahead of today (PD).
pub(crate) const AHEAD_DAYS: i32 = 3;

/// How often a node schedules and claims (PD).
pub(crate) const INTERVAL: Duration = Duration::from_secs(600);

/// How long a claim holds (PD).
const LEASE: Duration = Duration::from_secs(300);

const DAY_MS: u64 = 86_400_000;

/// What one [`tick`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Tick {
    /// Jobs completed.
    pub(crate) completed: u32,
    /// Partition openings that failed.
    pub(crate) failed: u32,
}

/// Schedules today's job and runs the ones this node claims. A job completes once every day
/// after its own is open; today may already hold rows in a default partition and is tried
/// only.
///
/// # Errors
/// [`StoreError`] when the jobs table cannot be read or written.
pub(crate) async fn tick(
    app: &Pool,
    archive: &Pool,
    worker: &str,
    now_ms: u64,
) -> Result<Tick, StoreError> {
    let today = i32::try_from(now_ms / DAY_MS).map_err(|_| StoreError::Range)?;
    schedule(
        app,
        KIND,
        &today.to_string(),
        &format!("{KIND}:{today}"),
        Duration::ZERO,
    )
    .await?;
    let mut out = Tick::default();
    for job in claim_kind(app, worker, KIND, 8, LEASE).await? {
        let Ok(day) = job.subject.parse::<i32>() else {
            tracing::warn!(subject = %job.subject, "partition job with an unreadable day");
            continue;
        };
        let mut done = true;
        for o in open_days(archive, day, AHEAD_DAYS).await {
            if let Err(error) = o.result {
                out.failed = out.failed.saturating_add(1);
                tracing::warn!(%error, family = o.family, day = o.day, "day partition not opened");
                done &= o.day == day;
            }
        }
        if done && complete(app, job.id, worker).await? {
            out.completed = out.completed.saturating_add(1);
        }
    }
    Ok(out)
}

/// One tick at the wall clock, its failure logged: today's partitions are opened before the
/// couriers and the listener start, so the first Claim or flow of a fresh deployment finds its
/// day (OP-146 m.5 (f)).
pub(crate) async fn open_now(app: &Pool, archive: &Pool, worker: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok());
    let Some(now) = now else {
        tracing::error!("system clock before the Unix epoch; partitions not opened");
        return;
    };
    if let Err(error) = tick(app, archive, worker, now).await {
        tracing::warn!(%error, "partition job failed");
    }
}

/// Ticks every [`INTERVAL`] until the task is aborted.
pub(crate) async fn run(app: Pool, archive: Pool, worker: String) {
    let mut every = tokio::time::interval(INTERVAL);
    loop {
        every.tick().await;
        open_now(&app, &archive, &worker).await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use access_store::ephemeral::partitions;
    use access_store::testing::fresh;

    use super::*;

    // OP-146 m.5 (f), m.7 (d), OP-129 m.2: one node opens today and the days ahead of every
    // ephemeral table through the jobs table; a second tick the same day finds nothing to do
    #[tokio::test]
    async fn the_opener_opens_days_ahead_once() {
        let db = fresh().await.unwrap();
        let now = 20_000 * DAY_MS + 5;
        let first = tick(&db.app, &db.archive, "node-a", now).await.unwrap();
        assert_eq!(
            first,
            Tick {
                completed: 1,
                failed: 0
            }
        );
        let again = tick(&db.app, &db.archive, "node-b", now).await.unwrap();
        assert_eq!(again, Tick::default());
        let days = |prefix: &str| -> Vec<String> {
            (20_000..=20_003).map(|d| format!("{prefix}{d}")).collect()
        };
        for (table, prefix) in [
            ("auth_flows", "auth_flows_d"),
            ("oauth_requests", "oauth_requests_d"),
            ("oauth_codes", "oauth_codes_d"),
            ("client_assertion_replay", "client_assertion_replay_d"),
            ("dpop_replay", "dpop_replay_d"),
            ("claim_ingest", "claim_ingest_d"),
        ] {
            let open = partitions(&db.owner, table).await.unwrap();
            for name in days(prefix) {
                assert!(open.contains(&name), "{table}: {open:?}");
            }
        }
        let throttle = partitions(&db.owner, "login_throttle").await.unwrap();
        for name in ["login_throttle_20241004", "login_throttle_20241007"] {
            assert!(throttle.iter().any(|t| t == name), "{throttle:?}");
        }
    }
}
