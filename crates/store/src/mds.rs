//! The FIDO metadata blob cache (OP-148, OP-146 m.4 (d), OP-158 m.3 (y)): raw blobs by source and
//! serial under the cell's nil tenant id; a reader verifies the newest again against its root
//! and trusted time.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{TenantId, TenantTx};

/// The tenant id the cell's own rows sit under.
const CELL: TenantId = TenantId::from_bytes([0; 16]);

/// The newest cached blob of `source` (a digest of its URL): `(serial, blob)`.
///
/// # Errors
/// [`StoreError`].
pub async fn latest(
    pool: &PgPool,
    source: &[u8; 32],
) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
    let mut t = TenantTx::begin_tenant(pool, CELL).await?;
    let row = sqlx::query!(
        "SELECT serial, blob FROM access.mds_cache WHERE tenant_id = $1 AND source = $2
          ORDER BY serial DESC LIMIT 1",
        Uuid::nil(),
        source.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        u64::try_from(r.serial)
            .map(|s| (s, r.blob))
            .map_err(|_| StoreError::Corrupt)
    })
    .transpose()
}

/// Caches a verified blob of `source`, only when its serial is above every cached one; false
/// otherwise (rollback or a copy another process cached first).
///
/// # Errors
/// [`StoreError`].
pub async fn record(
    pool: &PgPool,
    source: &[u8; 32],
    serial: u64,
    next_update_s: u64,
    blob: &[u8],
) -> Result<bool, StoreError> {
    let serial = i64::try_from(serial).map_err(|_| StoreError::Range)?;
    let next = i64::try_from(next_update_s).map_err(|_| StoreError::Range)?;
    let mut t = TenantTx::begin_tenant(pool, CELL).await?;
    let n = sqlx::query!(
        "INSERT INTO access.mds_cache (tenant_id, source, serial, next_update_s, blob)
         SELECT $1, $2, $3, $4, $5
          WHERE NOT EXISTS (SELECT 1 FROM access.mds_cache
                             WHERE tenant_id = $1 AND source = $2 AND serial >= $3)
         ON CONFLICT DO NOTHING",
        Uuid::nil(),
        source.as_slice(),
        serial,
        next,
        blob,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    t.commit().await?;
    Ok(n == 1)
}
