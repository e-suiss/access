//! Bulk jobs of the realm-admin surface (TN-125, X20): what each item of a job did, the
//! Exercise reference or the refusal, kept 7 days. Expiry is soft: an expired job reads as absent
//! and nothing is deleted (OP-73). Rows are in the transaction's realm scope (TN-113).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

fn ms(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// A job to record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewJob<'a> {
    /// `sequential` or `parallel`.
    pub mode: &'a str,
    /// The `kid` of the Instance whose AIS submitted it.
    pub actor: [u8; 32],
    /// Each item's operation and natural key, in order.
    pub items: &'a [(String, Option<String>)],
    /// When it was accepted, Unix milliseconds.
    pub created_ms: u64,
    /// When it stops being shown.
    pub expires_ms: u64,
}

/// A job as recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobRow {
    /// Its id.
    pub id: [u8; 16],
    /// `sequential` or `parallel`.
    pub mode: String,
    /// `running`, `succeeded`, `partial` or `failed`.
    pub status: String,
    /// Items in it.
    pub items: u32,
    /// Items committed.
    pub committed: u32,
    /// Items refused, not allowed, unavailable or not run for a failed dependency.
    pub failed: u32,
    /// Items refused by a rate limit.
    pub throttled: u32,
    /// Accepted at.
    pub created_ms: u64,
    /// Finished at.
    pub finished_ms: Option<u64>,
    /// Shown until.
    pub expires_ms: u64,
}

/// One item's outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemRow {
    /// Its place in the job.
    pub index: u32,
    /// The write operation.
    pub operation: String,
    /// The natural key it names.
    pub key: Option<String>,
    /// `pending`, `committed`, `not_allowed`, `rejected`, `throttled`, `failed_dependency` or
    /// `unavailable`.
    pub status: String,
    /// The status the write answered with.
    pub http_status: Option<u16>,
    /// The problem code of a refusal.
    pub problem: Option<String>,
    /// The committed Exercise.
    pub exercise_id: Option<String>,
    /// Its log position.
    pub position: Option<u64>,
}

/// Records a job and its pending items; returns its id.
///
/// # Errors
/// [`StoreError`].
pub async fn create(t: &mut TenantTx, job: &NewJob<'_>) -> Result<[u8; 16], StoreError> {
    let (tenant, realm) = scope(t)?;
    let count = i32::try_from(job.items.len()).map_err(|_| StoreError::Range)?;
    let id = sqlx::query_scalar!(
        "INSERT INTO access.admin_jobs (tenant_id, realm_id, mode, actor, item_count, created_ms,
                expires_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING job_id",
        tenant,
        realm,
        job.mode,
        job.actor.as_slice(),
        count,
        ms(job.created_ms)?,
        ms(job.expires_ms)?,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    for (i, (operation, key)) in job.items.iter().enumerate() {
        let index = i32::try_from(i).map_err(|_| StoreError::Range)?;
        sqlx::query!(
            "INSERT INTO access.admin_job_items (tenant_id, realm_id, job_id, item_index,
                    operation, resource_key)
             VALUES ($1, $2, $3, $4, $5, $6)",
            tenant,
            realm,
            id,
            index,
            operation,
            key.as_deref(),
        )
        .execute(&mut *t.tx)
        .await?;
    }
    Ok(*id.as_bytes())
}

/// Records what a pending item did; false when it was recorded before.
///
/// # Errors
/// [`StoreError`].
pub async fn record(t: &mut TenantTx, job: [u8; 16], item: &ItemRow) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let position = item.position.map(ms).transpose()?;
    let done = sqlx::query!(
        "UPDATE access.admin_job_items SET status = $5, http_status = $6, problem = $7,
                exercise_id = $8, decision_pos = $9
          WHERE tenant_id = $1 AND realm_id = $2 AND job_id = $3 AND item_index = $4
            AND status = 'pending'",
        tenant,
        realm,
        Uuid::from_bytes(job),
        i32::try_from(item.index).map_err(|_| StoreError::Range)?,
        item.status,
        item.http_status.map(i32::from),
        item.problem.as_deref(),
        item.exercise_id.as_deref(),
        position,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Finishes a running job with `status` at `now_ms`.
///
/// # Errors
/// [`StoreError`].
pub async fn finish(
    t: &mut TenantTx,
    job: [u8; 16],
    status: &str,
    now_ms: u64,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.admin_jobs SET status = $4, finished_ms = $5
          WHERE tenant_id = $1 AND realm_id = $2 AND job_id = $3 AND status = 'running'",
        tenant,
        realm,
        Uuid::from_bytes(job),
        status,
        ms(now_ms)?,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// The job `job` with its counts, unless it expired by `now_ms`.
///
/// # Errors
/// [`StoreError`].
pub async fn job(
    t: &mut TenantTx,
    job: [u8; 16],
    now_ms: u64,
) -> Result<Option<JobRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        r#"SELECT j.job_id, j.mode, j.status, j.item_count, j.created_ms, j.finished_ms,
                  j.expires_ms,
                  count(*) FILTER (WHERE i.status = 'committed') AS "committed!",
                  count(*) FILTER (WHERE i.status IN ('not_allowed', 'rejected',
                                   'failed_dependency', 'unavailable')) AS "failed!",
                  count(*) FILTER (WHERE i.status = 'throttled') AS "throttled!"
             FROM access.admin_jobs j
             JOIN access.admin_job_items i
               ON i.tenant_id = j.tenant_id AND i.realm_id = j.realm_id AND i.job_id = j.job_id
            WHERE j.tenant_id = $1 AND j.realm_id = $2 AND j.job_id = $3 AND j.expires_ms > $4
            GROUP BY j.tenant_id, j.realm_id, j.job_id"#,
        tenant,
        realm,
        Uuid::from_bytes(job),
        ms(now_ms)?,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    let count = |v: i64| u32::try_from(v).map_err(|_| StoreError::Corrupt);
    row.map(|r| {
        Ok(JobRow {
            id: *r.job_id.as_bytes(),
            mode: r.mode,
            status: r.status,
            items: u32::try_from(r.item_count).map_err(|_| StoreError::Corrupt)?,
            committed: count(r.committed)?,
            failed: count(r.failed)?,
            throttled: count(r.throttled)?,
            created_ms: unsigned(r.created_ms)?,
            finished_ms: r.finished_ms.map(unsigned).transpose()?,
            expires_ms: unsigned(r.expires_ms)?,
        })
    })
    .transpose()
}

/// Up to `limit` items of `job` after `after`, in order.
///
/// # Errors
/// [`StoreError`].
pub async fn items(
    t: &mut TenantTx,
    job: [u8; 16],
    after: Option<u32>,
    limit: u32,
) -> Result<Vec<ItemRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let after = after
        .map_or(Ok(-1), i32::try_from)
        .map_err(|_| StoreError::Range)?;
    let rows = sqlx::query!(
        "SELECT item_index, operation, resource_key, status, http_status, problem, exercise_id,
                decision_pos
           FROM access.admin_job_items
          WHERE tenant_id = $1 AND realm_id = $2 AND job_id = $3 AND item_index > $4
          ORDER BY item_index LIMIT $5",
        tenant,
        realm,
        Uuid::from_bytes(job),
        after,
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(ItemRow {
                index: u32::try_from(r.item_index).map_err(|_| StoreError::Corrupt)?,
                operation: r.operation,
                key: r.resource_key,
                status: r.status,
                http_status: r
                    .http_status
                    .map(|s| u16::try_from(s).map_err(|_| StoreError::Corrupt))
                    .transpose()?,
                problem: r.problem,
                exercise_id: r.exercise_id,
                position: r.decision_pos.map(unsigned).transpose()?,
            })
        })
        .collect()
}
