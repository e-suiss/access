//! Notification and operational jobs (OP-129 m.2): claimed with `SKIP LOCKED`, delivered at
//! least once, marked done and never deleted (OP-73 m.7). No semantic state change waits on a
//! job: expiry and cooling are evaluated against trusted time (TI-10).

use std::time::Duration;

use sqlx::PgPool;

use crate::StoreError;

/// A claimed job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    /// Job id.
    pub id: i64,
    /// What to do.
    pub kind: String,
    /// What it is about: identifiers only, no personal data.
    pub subject: String,
    /// How many times it has been claimed, this claim included.
    pub attempts: i32,
}

fn millis(d: Duration) -> Result<i64, StoreError> {
    i64::try_from(d.as_millis()).map_err(|_| StoreError::Range)
}

/// Schedules `kind` for `subject` to run after `delay`; a repeated `dedup_key` is a no-op.
/// Returns whether a job was added.
///
/// # Errors
/// [`StoreError`].
pub async fn schedule(
    app: &PgPool,
    kind: &str,
    subject: &str,
    dedup_key: &str,
    delay: Duration,
) -> Result<bool, StoreError> {
    let added = sqlx::query!(
        "INSERT INTO access_ops.jobs (kind, subject, dedup_key, run_at)
         VALUES ($1, $2, $3, now() + $4::bigint * interval '1 millisecond')
         ON CONFLICT (dedup_key) DO NOTHING",
        kind,
        subject,
        dedup_key,
        millis(delay)?,
    )
    .execute(app)
    .await?
    .rows_affected();
    Ok(added == 1)
}

/// Claims up to `limit` due jobs for `worker` for `lease`. Jobs whose claim lapsed are due
/// again, so a crashed worker's jobs are not lost.
///
/// # Errors
/// [`StoreError`].
pub async fn claim(
    app: &PgPool,
    worker: &str,
    limit: u32,
    lease: Duration,
) -> Result<Vec<Job>, StoreError> {
    let rows = sqlx::query!(
        "UPDATE access_ops.jobs j
            SET claimed_by = $1, claimed_until = now() + $3::bigint * interval '1 millisecond',
                attempts = j.attempts + 1
          WHERE j.id IN (
                SELECT id FROM access_ops.jobs
                 WHERE done_at IS NULL AND run_at <= now()
                   AND (claimed_until IS NULL OR claimed_until < now())
                 ORDER BY run_at, id
                 LIMIT $2
                 FOR UPDATE SKIP LOCKED)
          RETURNING j.id, j.kind, j.subject, j.attempts",
        worker,
        i64::from(limit),
        millis(lease)?,
    )
    .fetch_all(app)
    .await?;
    let mut jobs: Vec<Job> = rows
        .into_iter()
        .map(|r| Job {
            id: r.id,
            kind: r.kind,
            subject: r.subject,
            attempts: r.attempts,
        })
        .collect();
    jobs.sort_by_key(|j| j.id);
    Ok(jobs)
}

/// Marks a job done once its result is in a durable record. Only the current claimant can;
/// returns whether this call finished it.
///
/// # Errors
/// [`StoreError`].
pub async fn complete(app: &PgPool, id: i64, worker: &str) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "UPDATE access_ops.jobs SET done_at = now()
          WHERE id = $1 AND claimed_by = $2 AND done_at IS NULL",
        id,
        worker,
    )
    .execute(app)
    .await?
    .rows_affected();
    Ok(done == 1)
}
