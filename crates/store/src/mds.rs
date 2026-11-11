//! The FIDO metadata blob cache (OP-148, OP-146 m.4 (d), OP-158 m.3 (y)): raw blobs by source and
//! serial; a reader verifies the newest again against its root and trusted time.

use sqlx::PgPool;

use crate::StoreError;

/// The newest cached blob of `source` (a digest of its URL): `(serial, blob)`.
///
/// # Errors
/// [`StoreError`].
pub async fn latest(
    pool: &PgPool,
    source: &[u8; 32],
) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
    let row = sqlx::query!(
        "SELECT serial, blob FROM access.mds_cache WHERE source = $1 ORDER BY serial DESC LIMIT 1",
        source.as_slice(),
    )
    .fetch_optional(pool)
    .await?;
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
    let n = sqlx::query!(
        "INSERT INTO access.mds_cache (source, serial, next_update_s, blob)
         SELECT $1, $2, $3, $4
          WHERE NOT EXISTS (SELECT 1 FROM access.mds_cache WHERE source = $1 AND serial >= $2)
         ON CONFLICT DO NOTHING",
        source.as_slice(),
        serial,
        next,
        blob,
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n == 1)
}
