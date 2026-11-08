//! Signed checkpoints of a domain's log (CMP-6, T16, T20, OP-143 m.10): the note over the
//! committed head and the binding-signed excerpt of the operational key that signed it, one row
//! per issue, appended by the sequencer role and never changed (OP-73).

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

/// One signed checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityCheckpoint {
    /// Signing time, Unix milliseconds; the key is resolved at it.
    pub issued_at: u64,
    /// Records the tree covers.
    pub size: u64,
    /// RFC 9162 root over them.
    pub root: [u8; 32],
    /// The C2SP signed note.
    pub note: String,
    /// The binding-signed excerpt of its key (CR-58 m.1).
    pub excerpt: Vec<u8>,
}

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// Appends a checkpoint (sequencer role): `true` the first time for its `issued_at`.
///
/// # Errors
/// [`StoreError`].
pub async fn append(
    sequencer: &PgPool,
    domain: &DomainId,
    c: &AuthorityCheckpoint,
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "INSERT INTO access.authority_checkpoint (domain_id, issued_at, size, root, note, excerpt)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        signed(c.issued_at)?,
        signed(c.size)?,
        c.root.as_slice(),
        c.note,
        c.excerpt,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// The latest checkpoint of `domain`.
///
/// # Errors
/// [`StoreError`].
pub async fn latest(
    pool: &PgPool,
    domain: &DomainId,
) -> Result<Option<AuthorityCheckpoint>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT issued_at, size, root, note, excerpt FROM access.authority_checkpoint
          WHERE domain_id = $1 ORDER BY issued_at DESC LIMIT 1",
        domain.as_bytes().as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        Ok(AuthorityCheckpoint {
            issued_at: unsigned(r.issued_at)?,
            size: unsigned(r.size)?,
            root: r.root.try_into().map_err(|_| StoreError::Corrupt)?,
            note: r.note,
            excerpt: r.excerpt,
        })
    })
    .transpose()
}
