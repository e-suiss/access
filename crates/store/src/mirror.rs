//! The Replica Mirror and Record Export side of the store (OP-158 m.3 (e), (f), (g), TI-13,
//! AP-14): the runs an `access.audit.export` Exercise starts, the signed acknowledgements of
//! the domain's replicas, and the checkpoints a stream carries. Rows are appended, never changed
//! (OP-73).

use sqlx::PgPool;

use crate::StoreError;
use crate::authority_checkpoint::AuthorityCheckpoint;
use crate::scope::{DomainId, DomainTx};

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// What a run streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunKind {
    /// A Record Export Package of a fixed range.
    Package,
    /// The open-ended Replica Mirror.
    Mirror,
}

impl RunKind {
    const fn word(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::Mirror => "mirror",
        }
    }

    fn of(word: &str) -> Result<Self, StoreError> {
        match word {
            "package" => Ok(Self::Package),
            "mirror" => Ok(Self::Mirror),
            _ => Err(StoreError::Corrupt),
        }
    }
}

/// One export or mirror run (`access.export_runs`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportRun {
    /// The `ExerciseID` of the `access.audit.export` Exercise that started it.
    pub export: [u8; 32],
    /// Package or mirror.
    pub kind: RunKind,
    /// The exporting Party.
    pub party: [u8; 16],
    /// Its Instance.
    pub instance: [u8; 16],
    /// The PEP that committed the Exercise; only it reads the stream.
    pub pep: String,
    /// First position.
    pub from: u64,
    /// Last position of a package; `None` for a mirror.
    pub to: Option<u64>,
    /// Whether every field is opened.
    pub full: bool,
    /// Trusted time it started at, Unix milliseconds.
    pub started_at: u64,
}

/// Records a run (app role): `false` when the Exercise already started one.
///
/// # Errors
/// [`StoreError`].
pub async fn start_run(app: &PgPool, domain: &DomainId, r: &ExportRun) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(app, domain).await?;
    let done = sqlx::query!(
        "INSERT INTO access.export_runs
           (domain_id, export_id, kind, party, instance, pep, range_from, range_to, coverage, started_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        r.export.as_slice(),
        r.kind.word(),
        r.party.as_slice(),
        r.instance.as_slice(),
        r.pep,
        signed(r.from)?,
        r.to.map(signed).transpose()?,
        if r.full { "full" } else { "digest" },
        signed(r.started_at)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// The run `export` of `domain`.
///
/// # Errors
/// [`StoreError`].
pub async fn run(
    pool: &PgPool,
    domain: &DomainId,
    export: &[u8; 32],
) -> Result<Option<ExportRun>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT kind, party, instance, pep, range_from, range_to, coverage, started_at
           FROM access.export_runs WHERE domain_id = $1 AND export_id = $2",
        domain.as_bytes().as_slice(),
        export.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        Ok(ExportRun {
            export: *export,
            kind: RunKind::of(&r.kind)?,
            party: r.party.try_into().map_err(|_| StoreError::Corrupt)?,
            instance: r.instance.try_into().map_err(|_| StoreError::Corrupt)?,
            pep: r.pep,
            from: unsigned(r.range_from)?,
            to: r.range_to.map(unsigned).transpose()?,
            full: r.coverage == "full",
            started_at: unsigned(r.started_at)?,
        })
    })
    .transpose()
}

/// A replica's signed acknowledgement (`access.replica_ack`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaAckRow {
    /// The replica's declared name.
    pub replica: String,
    /// Records it holds.
    pub size: u64,
    /// Their root.
    pub root: [u8; 32],
    /// When it acknowledged, Unix milliseconds.
    pub acked_at: u64,
    /// Its Ed25519 signature.
    pub signature: [u8; 64],
}

/// Keeps a verified acknowledgement (sequencer role): `false` when the replica already
/// acknowledged that size.
///
/// # Errors
/// [`StoreError`].
pub async fn ack(
    sequencer: &PgPool,
    domain: &DomainId,
    a: &ReplicaAckRow,
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "INSERT INTO access.replica_ack (domain_id, replica, size, root, acked_at, signature)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        a.replica,
        signed(a.size)?,
        a.root.as_slice(),
        signed(a.acked_at)?,
        a.signature.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// The largest size each of `replicas` acknowledged for `domain` (0 for one that never did).
///
/// # Errors
/// [`StoreError`].
pub async fn acked(
    pool: &PgPool,
    domain: &DomainId,
    replicas: &[String],
) -> Result<Vec<(String, u64)>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        r#"SELECT replica AS "replica!", max(size) AS "size!" FROM access.replica_ack
            WHERE domain_id = $1 AND replica = ANY($2) GROUP BY replica"#,
        domain.as_bytes().as_slice(),
        replicas,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    replicas
        .iter()
        .map(|name| {
            let size = rows
                .iter()
                .find(|r| &r.replica == name)
                .map_or(Ok(0), |r| unsigned(r.size))?;
            Ok((name.clone(), size))
        })
        .collect()
}

/// The checkpoints of `domain` whose size is in `(after, upto]`, smallest first, the last
/// signed one of each size.
///
/// # Errors
/// [`StoreError`].
pub async fn checkpoints(
    pool: &PgPool,
    domain: &DomainId,
    after: u64,
    upto: u64,
) -> Result<Vec<AuthorityCheckpoint>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT DISTINCT ON (size) issued_at, size, root, note, excerpt
           FROM access.authority_checkpoint
          WHERE domain_id = $1 AND size > $2 AND size <= $3
          ORDER BY size, issued_at DESC",
        domain.as_bytes().as_slice(),
        signed(after)?,
        signed(upto)?,
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

/// Whether `domain` signed a checkpoint of exactly `size` and `root`.
///
/// # Errors
/// [`StoreError`].
pub async fn checkpoint_exists(
    pool: &PgPool,
    domain: &DomainId,
    size: u64,
    root: &[u8; 32],
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let found = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM access.authority_checkpoint
            WHERE domain_id = $1 AND size = $2 AND root = $3) AS "found!""#,
        domain.as_bytes().as_slice(),
        signed(size)?,
        root.as_slice(),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(found)
}

/// The leaf hashes of `domain`'s records `from..to` (exclusive), in order: the Merkle frontier
/// before an export's range.
///
/// # Errors
/// [`StoreError`]; [`StoreError::Corrupt`] when a position is missing.
pub async fn leaf_hashes(
    pool: &PgPool,
    domain: &DomainId,
    from: u64,
    to: u64,
) -> Result<Vec<[u8; 32]>, StoreError> {
    if to <= from {
        return Ok(Vec::new());
    }
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
    for (expected, r) in (from..).zip(rows) {
        if unsigned(r.pos)? != expected {
            return Err(StoreError::Corrupt);
        }
        out.push(r.leaf_hash.try_into().map_err(|_| StoreError::Corrupt)?);
    }
    if u64::try_from(out.len()).ok() != to.checked_sub(from) {
        return Err(StoreError::Corrupt);
    }
    Ok(out)
}
