//! Layer B login counters (OP-35, OP-146 m.5 (d)-(f), SA-30): exact, in PostgreSQL, keyed by a
//! 32-byte digest and held under a row lock for the read-modify-write. Rows live in day
//! partitions; a key's latest state within the horizon is carried into today's row when it is
//! next touched.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

/// One key's counter state; times are Unix milliseconds of the caller's clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThrottleRow {
    /// GCRA theoretical arrival time.
    pub tat_ms: i64,
    /// Failures since the last reset.
    pub failures: i32,
    /// The latest failure.
    pub last_failure_ms: i64,
    /// No attempt before this.
    pub blocked_until_ms: i64,
    /// Hard lock (SA-30).
    pub locked: bool,
}

impl TenantTx {
    /// The state of `key` on `day` (days since the Unix epoch), locked for this transaction.
    /// A key not yet touched today starts from its latest state of the previous
    /// `horizon_days` days, or from zero.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn throttle(
        &mut self,
        key: &[u8; 32],
        day: i32,
        horizon_days: i32,
    ) -> Result<ThrottleRow, StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let tenant = Uuid::from_bytes(*self.tenant.as_bytes());
        let realm = Uuid::from_bytes(*realm.as_bytes());
        sqlx::query!(
            "INSERT INTO access.login_throttle
               (tenant_id, realm_id, day, key, tat_ms, failures, last_failure_ms, blocked_until_ms, locked)
             SELECT $1, $2, date '1970-01-01' + $3::int, $4,
                    coalesce(p.tat_ms, 0), coalesce(p.failures, 0), coalesce(p.last_failure_ms, 0),
                    coalesce(p.blocked_until_ms, 0), coalesce(p.locked, false)
               FROM (SELECT 1) AS one
               LEFT JOIN LATERAL (
                 SELECT tat_ms, failures, last_failure_ms, blocked_until_ms, locked
                   FROM access.login_throttle
                  WHERE tenant_id = $1 AND realm_id = $2 AND key = $4
                    AND day < date '1970-01-01' + $3::int
                    AND day >= date '1970-01-01' + $3::int - $5::int
                  ORDER BY day DESC LIMIT 1) AS p ON true
             ON CONFLICT (tenant_id, realm_id, key, day) DO NOTHING",
            tenant,
            realm,
            day,
            key.as_slice(),
            horizon_days,
        )
        .execute(&mut *self.tx)
        .await?;
        let r = sqlx::query!(
            "SELECT tat_ms, failures, last_failure_ms, blocked_until_ms, locked FROM access.login_throttle
              WHERE day = date '1970-01-01' + $3::int AND tenant_id = $1 AND realm_id = $2 AND key = $4
              FOR UPDATE",
            tenant,
            realm,
            day,
            key.as_slice(),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(ThrottleRow {
            tat_ms: r.tat_ms,
            failures: r.failures,
            last_failure_ms: r.last_failure_ms,
            blocked_until_ms: r.blocked_until_ms,
            locked: r.locked,
        })
    }

    /// Writes `key`'s state for `day`, read with [`TenantTx::throttle`] in this transaction.
    ///
    /// # Errors
    /// [`StoreError`]; [`StoreError::Stale`] when the row was not read first.
    pub async fn put_throttle(
        &mut self,
        key: &[u8; 32],
        day: i32,
        row: &ThrottleRow,
    ) -> Result<(), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let n = sqlx::query!(
            "UPDATE access.login_throttle
                SET tat_ms = $5, failures = $6, last_failure_ms = $7, blocked_until_ms = $8, locked = $9
              WHERE day = date '1970-01-01' + $3::int AND tenant_id = $1 AND realm_id = $2 AND key = $4",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            day,
            key.as_slice(),
            row.tat_ms,
            row.failures,
            row.last_failure_ms,
            row.blocked_until_ms,
            row.locked,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        if n == 1 {
            Ok(())
        } else {
            Err(StoreError::Stale)
        }
    }
}

/// Opens the partition of `day` (days since the Unix epoch); archive role (OP-146 m.5 (f)).
///
/// # Errors
/// [`StoreError`].
pub async fn open_day(archive: &PgPool, day: i32) -> Result<String, StoreError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT access.open_throttle_day(date '1970-01-01' + $1::int) AS "name!""#,
        day,
    )
    .fetch_one(archive)
    .await?)
}
