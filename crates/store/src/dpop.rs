//! DPoP replay cache (TN-30, MD-8, OP-146 m.5 (f)): fixed-length key hashes only, one
//! partition per day of the proof's `iat`. A replay of a proof carries the same `iat`, so it
//! lands in the same partition and the primary key catches it atomically.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

impl TenantTx {
    /// Records the replay key of a proof whose `iat` falls on `day` (days since the Unix
    /// epoch). `true` the first time, `false` for a replay. A day without an open partition
    /// is an error, and the caller rejects the proof (TN-30).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn dpop_first_use(&mut self, day: u32, key: &[u8; 32]) -> Result<bool, StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let done = sqlx::query!(
            "INSERT INTO access.dpop_replay (tenant_id, realm_id, day, key_hash)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            i32::try_from(day).map_err(|_| StoreError::Range)?,
            key.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }
}

/// Opens the replay partition of `day` (archive role); idempotent.
///
/// # Errors
/// [`StoreError`].
pub async fn open_dpop_replay_day(archive: &PgPool, day: u32) -> Result<String, StoreError> {
    let name = sqlx::query_scalar!(
        r#"SELECT access.open_dpop_replay_day($1) AS "name!""#,
        i32::try_from(day).map_err(|_| StoreError::Range)?,
    )
    .fetch_one(archive)
    .await?;
    Ok(name)
}
