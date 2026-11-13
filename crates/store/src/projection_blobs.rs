//! Projections served by reference (CR-43, OP-159 m.3 (q)): an artefact over the header budget,
//! sealed under its own data key that the domain's token key wraps. At expiry the data key is
//! destroyed and `expired_at` set; the row is never removed (OP-73).

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

/// A projection to keep by reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewBlob<'a> {
    /// SHA-256 of the artefact bytes.
    pub digest: [u8; 32],
    /// Length of the artefact bytes.
    pub size: u64,
    /// The PEPs the artefact's `aud` names.
    pub audience: &'a [String],
    /// When the artefact expires, Unix ms.
    pub expires_at: u64,
    /// The data key, wrapped by the domain's token key.
    pub wrapped_dek: &'a str,
    /// The AEAD nonce.
    pub nonce: [u8; 12],
    /// Ciphertext and tag.
    pub ciphertext: &'a [u8],
}

/// A kept projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blob {
    /// Length of the artefact bytes.
    pub size: u64,
    /// The PEPs the artefact's `aud` names.
    pub audience: Vec<String>,
    /// When the artefact expires, Unix ms.
    pub expires_at: u64,
    /// The wrapped data key, nonce and ciphertext; `None` once expired and shredded.
    pub sealed: Option<(String, [u8; 12], Vec<u8>)>,
}

fn i64_of(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// Keeps a projection; keeping the same digest again is a no-op (content addressing).
///
/// # Errors
/// [`StoreError`].
pub async fn put(
    sequencer: &PgPool,
    domain: &DomainId,
    blob: &NewBlob<'_>,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.projection_blobs
                (domain_id, digest, size, audience, expires_at, wrapped_dek, nonce, ciphertext)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (domain_id, digest) DO NOTHING",
        domain.as_bytes().as_slice(),
        blob.digest.as_slice(),
        i64_of(blob.size)?,
        blob.audience,
        i64_of(blob.expires_at)?,
        blob.wrapped_dek,
        blob.nonce.as_slice(),
        blob.ciphertext,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await
}

/// Reads a kept projection.
///
/// # Errors
/// [`StoreError`].
pub async fn get(
    pool: &PgPool,
    domain: &DomainId,
    digest: &[u8; 32],
) -> Result<Option<Blob>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT size, audience, expires_at, wrapped_dek, nonce, ciphertext
           FROM access.projection_blobs WHERE domain_id = $1 AND digest = $2",
        domain.as_bytes().as_slice(),
        digest.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        let nonce = <[u8; 12]>::try_from(r.nonce).map_err(|_| StoreError::Corrupt)?;
        Ok(Blob {
            size: u64::try_from(r.size).map_err(|_| StoreError::Corrupt)?,
            audience: r.audience,
            expires_at: u64::try_from(r.expires_at).map_err(|_| StoreError::Corrupt)?,
            sealed: r.wrapped_dek.map(|w| (w, nonce, r.ciphertext)),
        })
    })
    .transpose()
}

/// Expires a kept projection: its data key is destroyed and `expired_at` set (crypto-shredding,
/// OP-73). Returns whether this call expired it.
///
/// # Errors
/// [`StoreError`].
pub async fn expire(
    sequencer: &PgPool,
    domain: &DomainId,
    digest: &[u8; 32],
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "UPDATE access.projection_blobs SET wrapped_dek = NULL, expired_at = now()
          WHERE domain_id = $1 AND digest = $2 AND expired_at IS NULL",
        domain.as_bytes().as_slice(),
        digest.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    t.commit().await?;
    Ok(done == 1)
}

/// Expires up to `limit` kept projections of `domain` whose artefacts expired before `now`;
/// returns how many.
///
/// # Errors
/// [`StoreError`].
pub async fn expire_due(
    sequencer: &PgPool,
    domain: &DomainId,
    now: u64,
    limit: u32,
) -> Result<u64, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "UPDATE access.projection_blobs SET wrapped_dek = NULL, expired_at = now()
          WHERE (domain_id, digest) IN (
                SELECT domain_id, digest FROM access.projection_blobs
                 WHERE domain_id = $1 AND expired_at IS NULL AND expires_at < $2
                 ORDER BY expires_at LIMIT $3)",
        domain.as_bytes().as_slice(),
        i64_of(now)?,
        i64::from(limit),
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    t.commit().await?;
    Ok(done)
}
