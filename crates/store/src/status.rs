//! Token Status List publications (OP-150 m.3 (a), (s), T24): each signed list with the
//! position and `recorded_at` it reflects, so a publisher never signs old content with a fresh
//! `iat` (G43).

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

/// One signed list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publication {
    /// The list's URI.
    pub uri: String,
    /// Publication number within the list.
    pub seq: u64,
    /// The position it reflects.
    pub applied_pos: u64,
    /// That position's `recorded_at`, milliseconds; the token's `iat`.
    pub iat_ms: u64,
    /// Number of entries.
    pub entries: u64,
    /// The signed token.
    pub token: Vec<u8>,
}

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// Records a publication (sequencer role): `true` the first time.
///
/// # Errors
/// [`StoreError`].
pub async fn publish(
    sequencer: &PgPool,
    domain: &DomainId,
    p: &Publication,
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "INSERT INTO access.status_list_publication
           (domain_id, list_uri, seq, applied_pos, iat_ms, entries, token)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        p.uri,
        signed(p.seq)?,
        signed(p.applied_pos)?,
        signed(p.iat_ms)?,
        signed(p.entries)?,
        p.token,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// The latest publication of the list at `uri`.
///
/// # Errors
/// [`StoreError`].
pub async fn latest(
    pool: &PgPool,
    domain: &DomainId,
    uri: &str,
) -> Result<Option<Publication>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT list_uri, seq, applied_pos, iat_ms, entries, token
           FROM access.status_list_publication
          WHERE domain_id = $1 AND list_uri = $2 ORDER BY seq DESC LIMIT 1",
        domain.as_bytes().as_slice(),
        uri,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        Ok(Publication {
            uri: r.list_uri,
            seq: unsigned(r.seq)?,
            applied_pos: unsigned(r.applied_pos)?,
            iat_ms: unsigned(r.iat_ms)?,
            entries: unsigned(r.entries)?,
            token: r.token,
        })
    })
    .transpose()
}
