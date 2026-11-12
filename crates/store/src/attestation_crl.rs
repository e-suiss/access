//! The CRL cache of WebAuthn attestation chains (OP-159 m.3 (ll), §10.2.4): raw CRLs by the
//! digest of their distribution point URL and of their content, under the cell's nil tenant id;
//! a reader checks the newest again during path validation.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{TenantId, TenantTx};

/// The tenant id the cell's own rows sit under.
const CELL: TenantId = TenantId::from_bytes([0; 16]);

/// A cached CRL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedCrl {
    /// `nextUpdate`, Unix seconds.
    pub next_update_s: u64,
    /// The CRL, DER.
    pub crl: Vec<u8>,
}

/// The CRL of `source` (a digest of its URL) fetched last.
///
/// # Errors
/// [`StoreError`].
pub async fn latest(pool: &PgPool, source: &[u8; 32]) -> Result<Option<CachedCrl>, StoreError> {
    let mut t = TenantTx::begin_tenant(pool, CELL).await?;
    let row = sqlx::query!(
        "SELECT next_update_s, crl FROM access.attestation_crl_cache
          WHERE tenant_id = $1 AND source = $2
          ORDER BY fetched_at DESC LIMIT 1",
        Uuid::nil(),
        source.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        u64::try_from(r.next_update_s)
            .map(|next_update_s| CachedCrl {
                next_update_s,
                crl: r.crl,
            })
            .map_err(|_| StoreError::Corrupt)
    })
    .transpose()
}

/// Caches a fetched CRL of `source` at `url`; false when the same content is cached already.
///
/// # Errors
/// [`StoreError`].
pub async fn record(
    pool: &PgPool,
    source: &[u8; 32],
    url: &str,
    digest: &[u8; 32],
    next_update_s: u64,
    crl: &[u8],
) -> Result<bool, StoreError> {
    let next = i64::try_from(next_update_s).map_err(|_| StoreError::Range)?;
    let mut t = TenantTx::begin_tenant(pool, CELL).await?;
    let n = sqlx::query!(
        "INSERT INTO access.attestation_crl_cache
                (tenant_id, source, url, digest, next_update_s, crl)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT DO NOTHING",
        Uuid::nil(),
        source.as_slice(),
        url,
        digest.as_slice(),
        next,
        crl,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    t.commit().await?;
    Ok(n == 1)
}
