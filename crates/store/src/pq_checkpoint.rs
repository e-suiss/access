//! Post-quantum re-anchor checkpoints and their witnesses' ML-DSA cosigns (CR-45 RA-2, RA-3,
//! RA-6, OP-159 m.3 (g)): appended by the sequencer role, never changed (OP-73).

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

/// What made a re-anchor (RA-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The first cadence checkpoint of a UTC day.
    Cadence,
    /// An operator request.
    Request,
    /// The step before a classical algorithm is retired.
    Retirement,
}

impl Reason {
    /// The stored word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cadence => "cadence",
            Self::Request => "request",
            Self::Retirement => "retirement",
        }
    }

    fn of(s: &str) -> Result<Self, StoreError> {
        match s {
            "cadence" => Ok(Self::Cadence),
            "request" => Ok(Self::Request),
            "retirement" => Ok(Self::Retirement),
            _ => Err(StoreError::Corrupt),
        }
    }
}

/// One witness's ML-DSA cosign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqCosignRow {
    /// The witness name.
    pub witness: String,
    /// The cosign time, Unix seconds.
    pub cosigned_at: u64,
    /// The tagged `COSE_Sign1`.
    pub sign1: Vec<u8>,
}

/// One post-quantum re-anchor checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqCheckpoint {
    /// When the signer signed it, Unix milliseconds.
    pub issued_at: u64,
    /// Records it covers.
    pub size: u64,
    /// RFC 9162 root.
    pub root: [u8; 32],
    /// The T16 note body, byte-identical to the payload.
    pub body: String,
    /// The tagged ML-DSA `COSE_Sign1`.
    pub sign1: Vec<u8>,
    /// The binding-signed excerpt of its key.
    pub excerpt: Vec<u8>,
    /// What made it.
    pub reason: Reason,
    /// Its cosigns.
    pub cosigns: Vec<PqCosignRow>,
}

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// Appends a re-anchor checkpoint and its cosigns (sequencer role); `true` the first time.
///
/// # Errors
/// [`StoreError`].
pub async fn append(
    sequencer: &PgPool,
    domain: &DomainId,
    c: &PqCheckpoint,
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "INSERT INTO access.pq_checkpoints
           (domain_id, issued_at, size, root, body, sign1, excerpt, reason)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        signed(c.issued_at)?,
        signed(c.size)?,
        c.root.as_slice(),
        c.body,
        c.sign1,
        c.excerpt,
        c.reason.as_str(),
    )
    .execute(&mut *t.tx)
    .await?;
    for w in &c.cosigns {
        sqlx::query!(
            "INSERT INTO access.witness_pq_cosign
               (domain_id, issued_at, witness, cosigned_at, sign1)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            domain.as_bytes().as_slice(),
            signed(c.issued_at)?,
            w.witness,
            signed(w.cosigned_at)?,
            w.sign1,
        )
        .execute(&mut *t.tx)
        .await?;
    }
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// The re-anchor checkpoints of `domain`, newest first, at most `limit`, each with its cosigns;
/// with `size`, only those of that size.
///
/// # Errors
/// [`StoreError`].
pub async fn list(
    pool: &PgPool,
    domain: &DomainId,
    size: Option<u64>,
    limit: u32,
) -> Result<Vec<PqCheckpoint>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let size = size.map(signed).transpose()?;
    let rows = sqlx::query!(
        "SELECT issued_at, size, root, body, sign1, excerpt, reason FROM access.pq_checkpoints
          WHERE domain_id = $1 AND ($2::bigint IS NULL OR size = $2)
          ORDER BY issued_at DESC LIMIT $3",
        domain.as_bytes().as_slice(),
        size,
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let cosigns = sqlx::query!(
            "SELECT witness, cosigned_at, sign1 FROM access.witness_pq_cosign
              WHERE domain_id = $1 AND issued_at = $2 ORDER BY witness",
            domain.as_bytes().as_slice(),
            r.issued_at,
        )
        .fetch_all(&mut *t.tx)
        .await?
        .into_iter()
        .map(|c| {
            Ok(PqCosignRow {
                witness: c.witness,
                cosigned_at: unsigned(c.cosigned_at)?,
                sign1: c.sign1,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
        out.push(PqCheckpoint {
            issued_at: unsigned(r.issued_at)?,
            size: unsigned(r.size)?,
            root: r.root.try_into().map_err(|_| StoreError::Corrupt)?,
            body: r.body,
            sign1: r.sign1,
            excerpt: r.excerpt,
            reason: Reason::of(&r.reason)?,
            cosigns,
        });
    }
    t.commit().await?;
    Ok(out)
}
