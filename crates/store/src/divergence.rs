//! Divergence notices and verified snapshots (OP-158 m.3 (h), (i), TI-1, TI-RT1, TI-RT4, G32,
//! G33). A fold notice stops the domain's commits until the live state is rebuilt from the log;
//! a re-evaluation notice stops nothing. Notices and snapshots are appended, never removed
//! (OP-73); a notice's resolution and relay times are set once.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// A notice to declare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewNotice<'a> {
    /// `fold` or `re-evaluation`.
    pub kind: &'a str,
    /// `rebuild-diff`, `replica` or `verifier`.
    pub source: &'a str,
    /// The declaring replica's name.
    pub declared_by: Option<&'a str>,
    /// First and last position replayed.
    pub range: (u64, u64),
    /// How many records differ.
    pub items: u32,
    /// The first that differs.
    pub first_position: u64,
    /// The (signed) divergence set.
    pub set: &'a [u8],
    /// Its SHA-256.
    pub digest: [u8; 32],
}

/// A declared notice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// Its id in the domain.
    pub id: u64,
    /// `fold` or `re-evaluation`.
    pub kind: String,
    /// Who found it.
    pub source: String,
    /// The declaring replica's name.
    pub declared_by: Option<String>,
    /// First and last position replayed.
    pub range: (u64, u64),
    /// How many records differ.
    pub items: u32,
    /// The first that differs.
    pub first_position: u64,
    /// The (signed) divergence set.
    pub set: Vec<u8>,
    /// Its SHA-256.
    pub digest: [u8; 32],
    /// Whether a fold notice was resolved by a rebuild from the log.
    pub resolved: bool,
    /// Whether the root and Security Party were told.
    pub relayed: bool,
}

/// Declares a notice for `domain` of `tenant`; its id, or `None` when the same set was declared
/// before.
///
/// # Errors
/// [`StoreError`].
pub async fn declare(
    pool: &PgPool,
    domain: &DomainId,
    tenant: [u8; 16],
    n: &NewNotice<'_>,
) -> Result<Option<u64>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let id = sqlx::query_scalar!(
        "INSERT INTO access.divergence_notices
           (domain_id, tenant_id, kind, source, declared_by, range_from, range_to, items,
            first_position, set_bytes, set_digest)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (domain_id, set_digest) DO NOTHING
         RETURNING id",
        domain.as_bytes().as_slice(),
        Uuid::from_bytes(tenant),
        n.kind,
        n.source,
        n.declared_by,
        signed(n.range.0)?,
        signed(n.range.1)?,
        i32::try_from(n.items).map_err(|_| StoreError::Range)?,
        signed(n.first_position)?,
        n.set,
        n.digest.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    id.map(unsigned).transpose()
}

/// Every notice of `domain`, oldest first.
///
/// # Errors
/// [`StoreError`].
pub async fn notices(pool: &PgPool, domain: &DomainId) -> Result<Vec<Notice>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT id, kind, source, declared_by, range_from, range_to, items, first_position,
                set_bytes, set_digest, resolved_at IS NOT NULL AS \"resolved!\",
                relayed_at IS NOT NULL AS \"relayed!\"
           FROM access.divergence_notices WHERE domain_id = $1 ORDER BY id",
        domain.as_bytes().as_slice(),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(Notice {
                id: unsigned(r.id)?,
                kind: r.kind,
                source: r.source,
                declared_by: r.declared_by,
                range: (unsigned(r.range_from)?, unsigned(r.range_to)?),
                items: u32::try_from(r.items).map_err(|_| StoreError::Corrupt)?,
                first_position: unsigned(r.first_position)?,
                set: r.set_bytes,
                digest: r.set_digest.try_into().map_err(|_| StoreError::Corrupt)?,
                resolved: r.resolved,
                relayed: r.relayed,
            })
        })
        .collect()
}

/// Whether `domain` has a fold notice not yet resolved: its commits stay stopped (§16.5, RT9).
///
/// # Errors
/// [`StoreError`].
pub async fn fold_open(pool: &PgPool, domain: &DomainId) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let open = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM access.divergence_notices
           WHERE domain_id = $1 AND kind = 'fold' AND resolved_at IS NULL) AS \"open!\"",
        domain.as_bytes().as_slice(),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(open)
}

/// Marks notice `id` relayed to the root and Security Party.
///
/// # Errors
/// [`StoreError`].
pub async fn relayed(pool: &PgPool, domain: &DomainId, id: u64) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    sqlx::query!(
        "UPDATE access.divergence_notices SET relayed_at = now()
          WHERE domain_id = $1 AND id = $2 AND relayed_at IS NULL",
        domain.as_bytes().as_slice(),
        signed(id)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await
}

pub use crate::authority::{FoldedRow, rebuild_state};

/// A verified snapshot of a domain's folded state (`snapshot.cddl`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The last position folded in.
    pub pos: u64,
    /// The tree root after it.
    pub root: [u8; 32],
    /// SHA-256 of `state`.
    pub state_digest: [u8; 32],
    /// The state's deterministic CBOR.
    pub state: Vec<u8>,
    /// The checkpoint note of size `pos + 1` naming `state_digest`, signed by the domain.
    pub note: String,
}

/// Keeps snapshot `s` of `domain`; `false` when one at that position exists.
///
/// # Errors
/// [`StoreError`].
pub async fn keep_snapshot(
    pool: &PgPool,
    domain: &DomainId,
    tenant: [u8; 16],
    s: &Snapshot,
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let n = sqlx::query!(
        "INSERT INTO access.snapshots (domain_id, tenant_id, pos, root, state_digest, state, note)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (domain_id, pos) DO NOTHING",
        domain.as_bytes().as_slice(),
        Uuid::from_bytes(tenant),
        signed(s.pos)?,
        s.root.as_slice(),
        s.state_digest.as_slice(),
        s.state,
        s.note,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    t.commit().await?;
    Ok(n == 1)
}

/// The newest snapshot of `domain` at or before `pos`.
///
/// # Errors
/// [`StoreError`].
pub async fn snapshot_before(
    pool: &PgPool,
    domain: &DomainId,
    pos: u64,
) -> Result<Option<Snapshot>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT pos, root, state_digest, state, note FROM access.snapshots
          WHERE domain_id = $1 AND pos <= $2 ORDER BY pos DESC LIMIT 1",
        domain.as_bytes().as_slice(),
        signed(pos)?,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        Ok(Snapshot {
            pos: unsigned(r.pos)?,
            root: r.root.try_into().map_err(|_| StoreError::Corrupt)?,
            state_digest: r.state_digest.try_into().map_err(|_| StoreError::Corrupt)?,
            state: r.state,
            note: r.note,
        })
    })
    .transpose()
}
