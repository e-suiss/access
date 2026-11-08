//! Management API `Idempotency-Key` answers (TN-126, OP-151 m.3 (c)): one row per scope digest
//! of (surface, caller, key), holding the digest of the request that first ran under it, its
//! state and, once done, the answer to replay. Rows expire softly and are reused in place for
//! the same scope; nothing is deleted (OP-73). Times are Unix milliseconds of the caller's clock.

use sqlx::PgPool;

use crate::StoreError;

/// What a request under a key does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Begun {
    /// Run it: the key was free, expired, released, or its runner's lease lapsed on the same
    /// request.
    Run,
    /// Answer with the stored answer.
    Replay(Vec<u8>),
    /// Another request ran under the key.
    Reused,
    /// The same request is still running.
    Running,
}

fn ms(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

/// Claims `scope` for `request` until `now_ms + lease_ms`, keeping the key until
/// `now_ms + retention_ms`, or tells what the key already holds.
///
/// # Errors
/// [`StoreError`].
pub async fn begin(
    app: &PgPool,
    scope: &[u8; 32],
    request: &[u8; 32],
    now_ms: u64,
    lease_ms: u64,
    retention_ms: u64,
) -> Result<Begun, StoreError> {
    let now = ms(now_ms)?;
    let lease = ms(now_ms.checked_add(lease_ms).ok_or(StoreError::Range)?)?;
    let expires = ms(now_ms.checked_add(retention_ms).ok_or(StoreError::Range)?)?;
    let claimed = sqlx::query_scalar!(
        r#"INSERT INTO access_ops.api_idempotency AS t
             (scope, request, state, lease_until_ms, expires_ms)
           VALUES ($1, $2, 'running', $4, $5)
           ON CONFLICT (scope) DO UPDATE
             SET request = EXCLUDED.request, state = 'running', answer = NULL,
                 lease_until_ms = EXCLUDED.lease_until_ms, expires_ms = EXCLUDED.expires_ms,
                 created_at = now()
           WHERE t.expires_ms <= $3
              OR t.state = 'released'
              OR (t.state = 'running' AND t.lease_until_ms <= $3 AND t.request = EXCLUDED.request)
           RETURNING true AS "claimed!""#,
        scope.as_slice(),
        request.as_slice(),
        now,
        lease,
        expires,
    )
    .fetch_optional(app)
    .await?;
    if claimed.is_some() {
        return Ok(Begun::Run);
    }
    let row = sqlx::query!(
        "SELECT request, state, answer FROM access_ops.api_idempotency WHERE scope = $1",
        scope.as_slice(),
    )
    .fetch_one(app)
    .await?;
    if row.request.as_slice() != request.as_slice() {
        return Ok(Begun::Reused);
    }
    match (row.state.as_str(), row.answer) {
        ("done", Some(answer)) => Ok(Begun::Replay(answer)),
        _ => Ok(Begun::Running),
    }
}

/// Releases up to `limit` keys whose answers are past their retention at `now_ms`: the answer
/// is cleared and the key released in place, so nothing is replayed after it and the row is
/// never deleted (TN-126, OP-73). Returns how many were released.
///
/// # Errors
/// [`StoreError`].
pub async fn release_expired(app: &PgPool, now_ms: u64, limit: u32) -> Result<u64, StoreError> {
    let n = sqlx::query!(
        "UPDATE access_ops.api_idempotency SET state = 'released', answer = NULL
          WHERE scope IN (SELECT scope FROM access_ops.api_idempotency
                           WHERE state = 'done' AND expires_ms <= $1
                           LIMIT $2 FOR UPDATE SKIP LOCKED)",
        ms(now_ms)?,
        i64::from(limit),
    )
    .execute(app)
    .await?
    .rows_affected();
    Ok(n)
}

/// Ends the run of `request` under `scope`: keeps `answer` for replay, or releases the key so
/// the next request runs again (a validation failure or a server error, TN-126).
///
/// # Errors
/// [`StoreError`]; [`StoreError::Stale`] when the run no longer holds the key.
pub async fn finish(
    app: &PgPool,
    scope: &[u8; 32],
    request: &[u8; 32],
    answer: Option<&[u8]>,
) -> Result<(), StoreError> {
    let n = sqlx::query!(
        "UPDATE access_ops.api_idempotency
            SET state = CASE WHEN $3::bytea IS NULL THEN 'released' ELSE 'done' END, answer = $3
          WHERE scope = $1 AND request = $2 AND state = 'running'",
        scope.as_slice(),
        request.as_slice(),
        answer,
    )
    .execute(app)
    .await?
    .rows_affected();
    if n == 1 {
        Ok(())
    } else {
        Err(StoreError::Stale)
    }
}
