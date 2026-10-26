//! Encrypted record bodies (§17.1.4, T39, OP-135): content-addressed by body commitment,
//! sealed under a per-body key the domain KEK wraps. Shredding removes the wrapped key and the
//! ciphertext and keeps the row (OP-73); copies in WAL and backups age out with their retention
//! (CR-32).

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

/// A stored body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    /// Body commitment.
    pub commit: [u8; 32],
    /// The KEK version that wraps the key.
    pub kek_id: String,
    /// Wrapped key, nonce and ciphertext; `None` once shredded.
    pub sealed: Option<(Vec<u8>, [u8; 12], Vec<u8>)>,
}

/// Stores a sealed body; storing the same commitment again is a no-op (content addressing).
///
/// # Errors
/// [`StoreError`].
pub async fn put(
    sequencer: &PgPool,
    domain: &DomainId,
    commit: &[u8; 32],
    kek_id: &str,
    wrapped: &[u8],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.body_store (domain_id, body_commit, kek_id, wrapped_dek, nonce, ciphertext)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (domain_id, body_commit) DO NOTHING",
        domain.as_bytes().as_slice(),
        commit.as_slice(),
        kek_id,
        wrapped,
        nonce.as_slice(),
        ciphertext,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await
}

/// Reads a body.
///
/// # Errors
/// [`StoreError`].
pub async fn get(
    pool: &PgPool,
    domain: &DomainId,
    commit: &[u8; 32],
) -> Result<Option<Body>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT kek_id, wrapped_dek, nonce, ciphertext FROM access.body_store WHERE domain_id = $1 AND body_commit = $2",
        domain.as_bytes().as_slice(),
        commit.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        let sealed = match (r.wrapped_dek, r.nonce, r.ciphertext) {
            (Some(w), Some(n), Some(c)) => Some((
                w,
                <[u8; 12]>::try_from(n).map_err(|_| StoreError::Corrupt)?,
                c,
            )),
            (None, None, None) => None,
            _ => return Err(StoreError::Corrupt),
        };
        Ok(Body {
            commit: *commit,
            kek_id: r.kek_id,
            sealed,
        })
    })
    .transpose()
}

/// Crypto-shreds a body (T39, OP-74): its wrapped key and ciphertext are removed for good.
/// Returns whether this call shredded it.
///
/// # Errors
/// [`StoreError`].
pub async fn shred(
    sequencer: &PgPool,
    domain: &DomainId,
    commit: &[u8; 32],
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "UPDATE access.body_store SET wrapped_dek = NULL, nonce = NULL, ciphertext = NULL, shredded_at = now()
          WHERE domain_id = $1 AND body_commit = $2 AND shredded_at IS NULL",
        domain.as_bytes().as_slice(),
        commit.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    t.commit().await?;
    Ok(done == 1)
}

/// Replaces a live body's wrapped key after a KEK rotation (§17.10.4).
///
/// # Errors
/// [`StoreError`].
pub async fn rewrap(
    sequencer: &PgPool,
    domain: &DomainId,
    commit: &[u8; 32],
    kek_id: &str,
    wrapped: &[u8],
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "UPDATE access.body_store SET kek_id = $3, wrapped_dek = $4
          WHERE domain_id = $1 AND body_commit = $2 AND shredded_at IS NULL",
        domain.as_bytes().as_slice(),
        commit.as_slice(),
        kek_id,
        wrapped,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    t.commit().await?;
    Ok(done == 1)
}

/// Live bodies still wrapped by `kek_id`, for the rotation job.
///
/// # Errors
/// [`StoreError`].
pub async fn wrapped_by(
    pool: &PgPool,
    domain: &DomainId,
    kek_id: &str,
    limit: u32,
) -> Result<Vec<[u8; 32]>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query_scalar!(
        "SELECT body_commit FROM access.body_store
          WHERE domain_id = $1 AND kek_id = $2 AND shredded_at IS NULL ORDER BY body_commit LIMIT $3",
        domain.as_bytes().as_slice(),
        kek_id,
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|c| <[u8; 32]>::try_from(c).map_err(|_| StoreError::Corrupt))
        .collect()
}
