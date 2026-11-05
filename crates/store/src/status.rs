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
    /// The binding-signed excerpt of its signing key (CR-58 m.1).
    pub excerpt: Option<Vec<u8>>,
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
           (domain_id, list_uri, seq, applied_pos, iat_ms, entries, token, excerpt)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        p.uri,
        signed(p.seq)?,
        signed(p.applied_pos)?,
        signed(p.iat_ms)?,
        signed(p.entries)?,
        p.token,
        p.excerpt.as_deref(),
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
        "SELECT list_uri, seq, applied_pos, iat_ms, entries, token, excerpt
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
            excerpt: r.excerpt,
        })
    })
    .transpose()
}

/// One list of a domain and how many of its entries are handed out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct List {
    /// Its number within the domain, from 0.
    pub list_no: u64,
    /// Its URI.
    pub uri: String,
    /// Entries it can hold.
    pub capacity: u64,
    /// Entries handed out.
    pub allocated: u64,
}

/// What a list reflects at the domain's head (T24): the head position, its `recorded_at`
/// and the entries of the families revoked at or before it, read in one statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The head position.
    pub pos: u64,
    /// Its `recorded_at`, milliseconds.
    pub recorded_at: u64,
    /// The set entries, ascending.
    pub revoked: Vec<u64>,
}

/// Opens a projection family with the next entry of the domain's newest list that has room
/// (sequencer role), opening list `n` as `uri_of(n)` with `capacity` entries when there is none
/// (OP-150 m.3 (a), §11.20). The entry and the family are written in one transaction, so an
/// entry is never handed out twice. `None` when the family is already open.
///
/// # Errors
/// [`StoreError`]; [`StoreError::Range`] for a capacity of 0.
pub async fn open_family_with_entry(
    sequencer: &PgPool,
    domain: &DomainId,
    family: &crate::projections::Family,
    capacity: u64,
    uri_of: impl Fn(u64) -> String + Send,
) -> Result<Option<(String, u64)>, StoreError> {
    if capacity == 0 {
        return Err(StoreError::Range);
    }
    let d = domain.as_bytes().as_slice();
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let open = sqlx::query_scalar!(
        "SELECT 1 AS \"one!\" FROM access.projection_family WHERE domain_id = $1 AND family_id = $2",
        d,
        family.family.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    if open.is_some() {
        t.commit().await?;
        return Ok(None);
    }
    let (uri, idx) = loop {
        let newest = sqlx::query!(
            "SELECT list_no, uri, capacity, allocated FROM access.status_list
              WHERE domain_id = $1 ORDER BY list_no DESC LIMIT 1 FOR UPDATE",
            d,
        )
        .fetch_optional(&mut *t.tx)
        .await?;
        match newest {
            Some(r) if r.allocated < r.capacity => {
                sqlx::query!(
                    "UPDATE access.status_list SET allocated = allocated + 1
                      WHERE domain_id = $1 AND list_no = $2",
                    d,
                    r.list_no,
                )
                .execute(&mut *t.tx)
                .await?;
                break (r.uri, unsigned(r.allocated)?);
            }
            newest => {
                let n = match newest {
                    Some(r) => unsigned(r.list_no)?
                        .checked_add(1)
                        .ok_or(StoreError::Range)?,
                    None => 0,
                };
                sqlx::query!(
                    "INSERT INTO access.status_list (domain_id, list_no, uri, capacity)
                     VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                    d,
                    signed(n)?,
                    uri_of(n),
                    signed(capacity)?,
                )
                .execute(&mut *t.tx)
                .await?;
            }
        }
    };
    sqlx::query!(
        "INSERT INTO access.projection_family
           (domain_id, family_id, client_id, holder_id, root_exercise, status_uri, status_idx)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        d,
        family.family.as_slice(),
        family.client_id,
        family.holder.as_slice(),
        family.root_exercise.as_slice(),
        uri,
        signed(idx)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(Some((uri, idx)))
}

fn list_row(list_no: i64, uri: String, capacity: i64, allocated: i64) -> Result<List, StoreError> {
    Ok(List {
        list_no: unsigned(list_no)?,
        uri,
        capacity: unsigned(capacity)?,
        allocated: unsigned(allocated)?,
    })
}

/// The lists of a domain, by number.
///
/// # Errors
/// [`StoreError`].
pub async fn lists(pool: &PgPool, domain: &DomainId) -> Result<Vec<List>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT list_no, uri, capacity, allocated FROM access.status_list
          WHERE domain_id = $1 ORDER BY list_no",
        domain.as_bytes().as_slice(),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| list_row(r.list_no, r.uri, r.capacity, r.allocated))
        .collect()
}

/// The list of a domain numbered `list_no`.
///
/// # Errors
/// [`StoreError`].
pub async fn list(
    pool: &PgPool,
    domain: &DomainId,
    list_no: u64,
) -> Result<Option<List>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT list_no, uri, capacity, allocated FROM access.status_list
          WHERE domain_id = $1 AND list_no = $2",
        domain.as_bytes().as_slice(),
        signed(list_no)?,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| list_row(r.list_no, r.uri, r.capacity, r.allocated))
        .transpose()
}

/// The list at `uri` at the domain's head (T24), in one statement so the position and the
/// entries agree. `None` for a domain without a head.
///
/// # Errors
/// [`StoreError`].
pub async fn snapshot(
    pool: &PgPool,
    domain: &DomainId,
    uri: &str,
) -> Result<Option<Snapshot>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT h.pos, h.recorded_at,
                array(SELECT f.status_idx FROM access.projection_family f
                       WHERE f.domain_id = $1 AND f.status_uri = $2
                         AND f.revoked_pos IS NOT NULL AND f.revoked_pos <= h.pos
                       ORDER BY f.status_idx) AS \"revoked!: Vec<Option<i64>>\"
           FROM access.domain_head h WHERE h.domain_id = $1",
        domain.as_bytes().as_slice(),
        uri,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        Ok(Snapshot {
            pos: unsigned(r.pos)?,
            recorded_at: unsigned(r.recorded_at)?,
            revoked: r
                .revoked
                .into_iter()
                .map(|i| i.ok_or(StoreError::Corrupt).and_then(unsigned))
                .collect::<Result<_, _>>()?,
        })
    })
    .transpose()
}

fn fixed<const N: usize>(v: &[u8]) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// The families of `holder` not yet revoked, with their entries: what ends when the holder
/// Instance ends (§9.9.3 k.6, P50).
///
/// # Errors
/// [`StoreError`].
pub async fn live_families(
    pool: &PgPool,
    domain: &DomainId,
    holder: &[u8; 16],
) -> Result<Vec<crate::projections::Family>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT family_id, client_id, holder_id, root_exercise, status_uri, status_idx
           FROM access.projection_family
          WHERE domain_id = $1 AND holder_id = $2 AND revoked_at IS NULL
          ORDER BY family_id",
        domain.as_bytes().as_slice(),
        holder.as_slice(),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            let status = match (r.status_uri, r.status_idx) {
                (Some(uri), Some(idx)) => Some((uri, unsigned(idx)?)),
                (None, None) => None,
                _ => return Err(StoreError::Corrupt),
            };
            Ok(crate::projections::Family {
                family: fixed(&r.family_id)?,
                client_id: r.client_id,
                holder: fixed(&r.holder_id)?,
                root_exercise: fixed(&r.root_exercise)?,
                status,
                revoked_pos: None,
            })
        })
        .collect()
}
