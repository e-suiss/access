//! The derived index (CMP-9, OP-141 m.22 (g), (k)): Grants by holder and namespace, written by
//! the deriver from the domain log and read by the query side. Never a commit input (INV-33).

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

/// One Grant as the index keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRow {
    /// Grant.
    pub grant: [u8; 16],
    /// `party`, `pred`, `public` or `foreign`.
    pub holder_kind: &'static str,
    /// The holder Party, for `party`.
    pub holder: Option<[u8; 16]>,
    /// Namespace of the Grant's resource selector.
    pub namespace: String,
    /// Whether the Grant has ended.
    pub ended: bool,
    /// Position of the record that last changed it.
    pub pos: u64,
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn id16(v: &[u8]) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// The last log position the index has applied; 0 before the first.
///
/// # Errors
/// [`StoreError::Db`].
pub async fn cursor(pool: &PgPool, domain: &DomainId) -> Result<u64, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let pos = sqlx::query_scalar!(
        "SELECT pos FROM access_derived.cursor WHERE domain_id = $1",
        domain.as_bytes().as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    pos.map_or(Ok(0), unsigned)
}

/// Applies `rows` and moves the cursor from `from` to `to` in one transaction; a cursor that
/// moved meanwhile fails it (`Stale`), so two derivers never apply the same range twice.
///
/// # Errors
/// [`StoreError::Stale`]; [`StoreError::Db`].
pub async fn advance(
    deriver: &PgPool,
    domain: &DomainId,
    from: u64,
    to: u64,
    rows: &[GrantRow],
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(deriver, domain).await?;
    let id = domain.as_bytes().as_slice();
    let moved = if from == 0 {
        sqlx::query!(
            "INSERT INTO access_derived.cursor (domain_id, pos) VALUES ($1, $2)
             ON CONFLICT (domain_id) DO UPDATE SET pos = EXCLUDED.pos
              WHERE access_derived.cursor.pos = 0",
            id,
            signed(to)?,
        )
        .execute(&mut *t.tx)
        .await?
    } else {
        sqlx::query!(
            "UPDATE access_derived.cursor SET pos = $3 WHERE domain_id = $1 AND pos = $2",
            id,
            signed(from)?,
            signed(to)?,
        )
        .execute(&mut *t.tx)
        .await?
    }
    .rows_affected();
    if moved != 1 {
        return Err(StoreError::Stale);
    }
    for r in rows {
        sqlx::query!(
            "INSERT INTO access_derived.grant_index (domain_id, grant_id, holder_kind, holder, namespace, ended, pos)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (domain_id, grant_id) DO UPDATE
               SET holder_kind = EXCLUDED.holder_kind, holder = EXCLUDED.holder,
                   namespace = EXCLUDED.namespace, ended = EXCLUDED.ended, pos = EXCLUDED.pos",
            id,
            r.grant.as_slice(),
            r.holder_kind,
            r.holder.as_ref().map(<[u8; 16]>::as_slice),
            r.namespace,
            r.ended,
            signed(r.pos)?,
        )
        .execute(&mut *t.tx)
        .await?;
    }
    t.commit().await
}

/// The live Grants whose resource is in `namespace`, at most `limit`, in id order after
/// `after` (OP-141 m.22 (b)).
///
/// # Errors
/// [`StoreError::Db`].
pub async fn grants_in(
    pool: &PgPool,
    domain: &DomainId,
    namespace: &str,
    after: Option<[u8; 16]>,
    limit: u32,
) -> Result<Vec<[u8; 16]>, StoreError> {
    let after = after.unwrap_or([0; 16]);
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query_scalar!(
        "SELECT grant_id FROM access_derived.grant_index
          WHERE domain_id = $1 AND namespace = $2 AND NOT ended AND grant_id > $3
          ORDER BY grant_id LIMIT $4",
        domain.as_bytes().as_slice(),
        namespace,
        after.as_slice(),
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.iter().map(|g| id16(g)).collect()
}

/// The live Grants `party` may hold: held by it, by `Public`, or by a predicate, at most
/// `limit`, in id order after `after`.
///
/// # Errors
/// [`StoreError::Db`].
pub async fn grants_for(
    pool: &PgPool,
    domain: &DomainId,
    party: &[u8; 16],
    after: Option<[u8; 16]>,
    limit: u32,
) -> Result<Vec<[u8; 16]>, StoreError> {
    let after = after.unwrap_or([0; 16]);
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query_scalar!(
        "SELECT grant_id FROM access_derived.grant_index
          WHERE domain_id = $1 AND NOT ended AND grant_id > $3
            AND (holder = $2 OR holder_kind IN ('public', 'pred'))
          ORDER BY grant_id LIMIT $4",
        domain.as_bytes().as_slice(),
        party.as_slice(),
        after.as_slice(),
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.iter().map(|g| id16(g)).collect()
}
