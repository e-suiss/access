//! The derived index (CMP-9, OP-141 m.22 (g), (k)): Grants by holder and namespace, and Instance
//! keys by thumbprint (OP-149 m.5), written by the deriver from the domain log and read by the
//! query side. Never a commit input (INV-33).

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
    advance_with(deriver, domain, from, to, rows, &[]).await
}

/// One Instance key as the key index keeps it (OP-149 m.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRow {
    /// RFC 7638 thumbprint.
    pub kid: [u8; 32],
    /// The Instance holding it.
    pub instance: [u8; 16],
    /// The Instance's Party.
    pub party: [u8; 16],
    /// Canonical CBOR of the public key.
    pub public_key: Vec<u8>,
    /// Position from which the Instance holds the key.
    pub since_pos: u64,
    /// Trusted time of `since_pos`.
    pub since_at: u64,
    /// Position and trusted time at which it stopped holding it.
    pub ended: Option<(u64, u64)>,
    /// The recovery successor of the Instance.
    pub successor: Option<[u8; 16]>,
    /// Position of the record that last changed the row.
    pub pos: u64,
}

/// A change the deriver applies to the key index, in log order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyChange {
    /// The key's row as its Instance now stands; a row with the same `since_pos` or
    /// `ended_pos` keeps its `since_at` or `ended_at`.
    Put(KeyRow),
    /// The Instance stopped holding `kid` at `pos`, recorded at `at`; an end already set stays.
    End {
        /// Thumbprint.
        kid: [u8; 32],
        /// Position.
        pos: u64,
        /// Trusted time.
        at: u64,
    },
}

/// Like [`advance`], also applying `keys` to the key index in order (OP-149 m.5).
///
/// # Errors
/// [`StoreError::Stale`]; [`StoreError::Db`].
pub async fn advance_with(
    deriver: &PgPool,
    domain: &DomainId,
    from: u64,
    to: u64,
    rows: &[GrantRow],
    keys: &[KeyChange],
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
    apply_keys(&mut t, keys).await?;
    t.commit().await
}

async fn apply_keys(t: &mut DomainTx, keys: &[KeyChange]) -> Result<(), StoreError> {
    let domain = t.domain;
    let id = domain.as_bytes().as_slice();
    for change in keys {
        match change {
            KeyChange::Put(k) => {
                let (ended_pos, ended_at) = match k.ended {
                    Some((p, a)) => (Some(signed(p)?), Some(signed(a)?)),
                    None => (None, None),
                };
                sqlx::query!(
                    "INSERT INTO access_derived.key_index
                       (domain_id, kid, instance_id, party_id, public_key, since_pos, since_at,
                        ended_pos, ended_at, successor_id, pos)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                     ON CONFLICT (domain_id, kid) DO UPDATE
                       SET instance_id = EXCLUDED.instance_id, party_id = EXCLUDED.party_id,
                           public_key = EXCLUDED.public_key,
                           since_at = CASE WHEN access_derived.key_index.since_pos = EXCLUDED.since_pos
                                           THEN access_derived.key_index.since_at
                                           ELSE EXCLUDED.since_at END,
                           since_pos = EXCLUDED.since_pos,
                           ended_at = CASE WHEN access_derived.key_index.ended_pos = EXCLUDED.ended_pos
                                           THEN access_derived.key_index.ended_at
                                           ELSE EXCLUDED.ended_at END,
                           ended_pos = EXCLUDED.ended_pos,
                           successor_id = EXCLUDED.successor_id, pos = EXCLUDED.pos",
                    id,
                    k.kid.as_slice(),
                    k.instance.as_slice(),
                    k.party.as_slice(),
                    k.public_key.as_slice(),
                    signed(k.since_pos)?,
                    signed(k.since_at)?,
                    ended_pos,
                    ended_at,
                    k.successor.as_ref().map(<[u8; 16]>::as_slice),
                    signed(k.pos)?,
                )
                .execute(&mut *t.tx)
                .await?;
            }
            KeyChange::End { kid, pos, at } => {
                sqlx::query!(
                    "UPDATE access_derived.key_index
                        SET ended_pos = $3, ended_at = $4, pos = $3
                      WHERE domain_id = $1 AND kid = $2 AND ended_pos IS NULL",
                    id,
                    kid.as_slice(),
                    signed(*pos)?,
                    signed(*at)?,
                )
                .execute(&mut *t.tx)
                .await?;
            }
        }
    }
    Ok(())
}

fn id32(v: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// The key index rows of `kids` that exist, in no particular order (OP-149 m.5).
///
/// # Errors
/// [`StoreError::Db`]; [`StoreError::Corrupt`].
pub async fn keys_of(
    pool: &PgPool,
    domain: &DomainId,
    kids: &[[u8; 32]],
) -> Result<Vec<KeyRow>, StoreError> {
    let wanted: Vec<Vec<u8>> = kids.iter().map(|k| k.to_vec()).collect();
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT kid, instance_id, party_id, public_key, since_pos, since_at, ended_pos, ended_at,
                successor_id, pos
           FROM access_derived.key_index
          WHERE domain_id = $1 AND kid = ANY($2)",
        domain.as_bytes().as_slice(),
        &wanted,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(KeyRow {
                kid: id32(&r.kid)?,
                instance: id16(&r.instance_id)?,
                party: id16(&r.party_id)?,
                public_key: r.public_key,
                since_pos: unsigned(r.since_pos)?,
                since_at: unsigned(r.since_at)?,
                ended: match (r.ended_pos, r.ended_at) {
                    (Some(p), Some(a)) => Some((unsigned(p)?, unsigned(a)?)),
                    (None, None) => None,
                    _ => return Err(StoreError::Corrupt),
                },
                successor: r.successor_id.as_deref().map(id16).transpose()?,
                pos: unsigned(r.pos)?,
            })
        })
        .collect()
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
