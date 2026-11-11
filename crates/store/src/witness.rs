//! Witness cosignatures of domain checkpoints and equivocation evidence (CMP-6, T17, SEC23, U9,
//! HL-7, OP-158 m.3 (c), (d)): appended by the sequencer role, never changed (OP-73). The
//! highest checkpoint with an independent cosignature is the domain's `witnessed_through`.

use sqlx::PgPool;

use crate::StoreError;
use crate::authority_checkpoint::AuthorityCheckpoint;
use crate::scope::{DomainId, DomainTx};

/// One witness cosignature of a checkpoint (`tlog-cosignature/v1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cosign {
    /// Tree size.
    pub size: u64,
    /// Root at that size.
    pub root: [u8; 32],
    /// The witness's key name.
    pub witness: String,
    /// The witness's verifier key (`vkey`).
    pub vkey: String,
    /// Whether its operator is not the provider's (SI-12, B13).
    pub independent: bool,
    /// The cosignature's time, seconds.
    pub cosigned_at: u64,
    /// The Ed25519 signature.
    pub signature: [u8; 64],
}

/// Two cosigned notes of one size with different roots (U9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Equivocation {
    /// The size both name.
    pub size: u64,
    /// One root and its note.
    pub a: ([u8; 32], String),
    /// The other root and its note.
    pub b: ([u8; 32], String),
    /// Where it was seen.
    pub source: String,
    /// When, Unix milliseconds.
    pub detected_at: u64,
}

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// Appends a cosignature (sequencer role): `true` the first time for its size and witness.
///
/// # Errors
/// [`StoreError`].
pub async fn record_cosign(
    sequencer: &PgPool,
    domain: &DomainId,
    c: &Cosign,
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "INSERT INTO access.witness_cosign
           (domain_id, size, root, witness, cosigned_at, signature, vkey, independent)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        signed(c.size)?,
        c.root.as_slice(),
        c.witness,
        signed(c.cosigned_at)?,
        c.signature.as_slice(),
        c.vkey,
        c.independent,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// The cosignatures of the checkpoint of `domain` with `size` and `root`.
///
/// # Errors
/// [`StoreError`].
pub async fn cosigns(
    pool: &PgPool,
    domain: &DomainId,
    size: u64,
    root: &[u8; 32],
) -> Result<Vec<Cosign>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT size, root, witness, vkey, independent, cosigned_at, signature
           FROM access.witness_cosign WHERE domain_id = $1 AND size = $2 AND root = $3
          ORDER BY witness",
        domain.as_bytes().as_slice(),
        signed(size)?,
        root.as_slice(),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(Cosign {
                size: unsigned(r.size)?,
                root: r.root.try_into().map_err(|_| StoreError::Corrupt)?,
                witness: r.witness,
                vkey: r.vkey,
                independent: r.independent,
                cosigned_at: unsigned(r.cosigned_at)?,
                signature: r.signature.try_into().map_err(|_| StoreError::Corrupt)?,
            })
        })
        .collect()
}

/// The largest size with an independent witness's cosignature (§9.5, §9.11, SEC23).
///
/// # Errors
/// [`StoreError`].
pub async fn witnessed_through(pool: &PgPool, domain: &DomainId) -> Result<u64, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let size = sqlx::query_scalar!(
        "SELECT max(size) FROM access.witness_cosign WHERE domain_id = $1 AND independent",
        domain.as_bytes().as_slice(),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    t.commit().await?;
    size.map_or(Ok(0), unsigned)
}

/// The largest size `witness` cosigned: the base the next request names.
///
/// # Errors
/// [`StoreError`].
pub async fn witness_base(
    pool: &PgPool,
    domain: &DomainId,
    witness: &str,
) -> Result<u64, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let size = sqlx::query_scalar!(
        "SELECT max(size) FROM access.witness_cosign WHERE domain_id = $1 AND vkey = $2",
        domain.as_bytes().as_slice(),
        witness,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    t.commit().await?;
    size.map_or(Ok(0), unsigned)
}

/// The leaf hashes at positions `from..to`, in order.
///
/// # Errors
/// [`StoreError`]; [`StoreError::Corrupt`] when a position is missing.
pub async fn leaf_hashes(
    pool: &PgPool,
    domain: &DomainId,
    from: u64,
    to: u64,
) -> Result<Vec<[u8; 32]>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT pos, leaf_hash FROM access.authority_log
          WHERE domain_id = $1 AND pos >= $2 AND pos < $3 ORDER BY pos",
        domain.as_bytes().as_slice(),
        signed(from)?,
        signed(to)?,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    let mut out = Vec::with_capacity(rows.len());
    for (expected, r) in (from..to).zip(rows.iter()) {
        if unsigned(r.pos)? != expected {
            return Err(StoreError::Corrupt);
        }
        out.push(<[u8; 32]>::try_from(r.leaf_hash.as_slice()).map_err(|_| StoreError::Corrupt)?);
    }
    if u64::try_from(out.len()).ok() != to.checked_sub(from) {
        return Err(StoreError::Corrupt);
    }
    Ok(out)
}

/// The newest checkpoint of `domain` with exactly `size` records.
///
/// # Errors
/// [`StoreError`].
pub async fn checkpoint_of_size(
    pool: &PgPool,
    domain: &DomainId,
    size: u64,
) -> Result<Option<AuthorityCheckpoint>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT issued_at, size, root, note, excerpt FROM access.authority_checkpoint
          WHERE domain_id = $1 AND size = $2 ORDER BY issued_at DESC LIMIT 1",
        domain.as_bytes().as_slice(),
        signed(size)?,
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

/// The newest `limit` checkpoints of `domain`, newest first.
///
/// # Errors
/// [`StoreError`].
pub async fn recent_checkpoints(
    pool: &PgPool,
    domain: &DomainId,
    limit: u32,
) -> Result<Vec<AuthorityCheckpoint>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT issued_at, size, root, note, excerpt FROM access.authority_checkpoint
          WHERE domain_id = $1 ORDER BY issued_at DESC LIMIT $2",
        domain.as_bytes().as_slice(),
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(AuthorityCheckpoint {
                issued_at: unsigned(r.issued_at)?,
                size: unsigned(r.size)?,
                root: r.root.try_into().map_err(|_| StoreError::Corrupt)?,
                note: r.note,
                excerpt: r.excerpt,
            })
        })
        .collect()
}

/// Keeps equivocation evidence (sequencer role): `true` the first time for its pair of roots.
///
/// # Errors
/// [`StoreError`].
pub async fn record_equivocation(
    sequencer: &PgPool,
    domain: &DomainId,
    e: &Equivocation,
) -> Result<bool, StoreError> {
    let (a, b) = if e.a.0 <= e.b.0 {
        (&e.a, &e.b)
    } else {
        (&e.b, &e.a)
    };
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "INSERT INTO access.equivocation_evidence
           (domain_id, size, root_a, root_b, note_a, note_b, source, detected_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        signed(e.size)?,
        a.0.as_slice(),
        b.0.as_slice(),
        a.1,
        b.1,
        e.source,
        signed(e.detected_at)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// How many pieces of equivocation evidence `domain` has.
///
/// # Errors
/// [`StoreError`].
pub async fn equivocations(pool: &PgPool, domain: &DomainId) -> Result<u64, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let n = sqlx::query_scalar!(
        "SELECT count(*) FROM access.equivocation_evidence WHERE domain_id = $1",
        domain.as_bytes().as_slice(),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    t.commit().await?;
    n.map_or(Ok(0), unsigned)
}

/// The newest checkpoint of `domain` an independent witness cosigned, the largest first; with
/// `size`, only one of exactly that size (T19: the bundle's checkpoint).
///
/// # Errors
/// [`StoreError`].
pub async fn latest_witnessed(
    pool: &PgPool,
    domain: &DomainId,
    size: Option<u64>,
) -> Result<Option<AuthorityCheckpoint>, StoreError> {
    let wanted = size.map(signed).transpose()?;
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT c.issued_at, c.size, c.root, c.note, c.excerpt FROM access.authority_checkpoint c
          WHERE c.domain_id = $1 AND ($2::bigint IS NULL OR c.size = $2)
            AND EXISTS (SELECT 1 FROM access.witness_cosign w
                         WHERE w.domain_id = c.domain_id AND w.size = c.size
                           AND w.root = c.root AND w.independent)
          ORDER BY c.size DESC, c.issued_at DESC LIMIT 1",
        domain.as_bytes().as_slice(),
        wanted,
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
