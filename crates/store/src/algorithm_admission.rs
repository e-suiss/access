//! The CT3 time-lock of an algorithm joining a domain's allowlist (OP-159 m.3 (e), m.9 (h)):
//! each request is appended by the sequencer role, never changed (OP-73).

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

/// Appends a request of `domain` to admit the COSE algorithm `alg` at `at` (sequencer role);
/// `true` the first time.
///
/// # Errors
/// [`StoreError`].
pub async fn request(
    sequencer: &PgPool,
    domain: &DomainId,
    alg: i64,
    at: u64,
) -> Result<bool, StoreError> {
    let alg = i32::try_from(alg).map_err(|_| StoreError::Range)?;
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "INSERT INTO access.algorithm_admissions (domain_id, algorithm, requested_at)
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        alg,
        signed(at)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// The latest request of `domain` to admit `alg` made at or after `since`, Unix ms.
///
/// # Errors
/// [`StoreError`].
pub async fn latest(
    pool: &PgPool,
    domain: &DomainId,
    alg: i64,
    since: u64,
) -> Result<Option<u64>, StoreError> {
    let alg = i32::try_from(alg).map_err(|_| StoreError::Range)?;
    let mut t = DomainTx::begin(pool, domain).await?;
    let at = sqlx::query_scalar!(
        "SELECT max(requested_at) FROM access.algorithm_admissions
          WHERE domain_id = $1 AND algorithm = $2 AND requested_at >= $3",
        domain.as_bytes().as_slice(),
        alg,
        signed(since)?,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    t.commit().await?;
    at.map(|a| u64::try_from(a).map_err(|_| StoreError::Corrupt))
        .transpose()
}
