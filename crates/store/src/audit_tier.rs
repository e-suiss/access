//! The identity audit log's hot and cold tiers (OP-40, OP-73 m.4, OP-158 m.3 (w)): every month
//! is sub-partitioned by tenant; a partition past its hot window whose rows are all checkpointed
//! is copied to the cold tier, and once the copy is verified the archive role detaches it into
//! `access_audit_cold`. Nothing is dropped or deleted.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::audit::AuditRow;
use crate::identity::Cursor;

/// A partition the cold tier may take now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Due {
    /// `identity_audit_YYYYMM[_t<tenant>|_default]`.
    pub partition: String,
    /// The tenant of a tenant's own partition; `None` when several tenants' rows share it.
    pub tenant: Option<[u8; 16]>,
    /// The partition's month, as (year, month).
    pub month: (i32, u32),
    /// Its rows.
    pub rows: u64,
}

/// A partition moved to the cold tier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Moved {
    /// The partition.
    pub partition: String,
    /// Its tenant, as in [`Due`].
    pub tenant: Option<[u8; 16]>,
    /// Its rows.
    pub rows: u64,
    /// The RFC 9162 root of its rows' leaves in integration order.
    pub root: [u8; 32],
    /// The cold object holding the copy.
    pub object_key: String,
    /// SHA-256 of the object.
    pub object_sha256: [u8; 32],
    /// The last row, in integration order; `None` for an empty partition.
    pub last: Option<Cursor>,
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn month_of(text: &str) -> Result<(i32, u32), StoreError> {
    let (y, m) = text.split_once('-').ok_or(StoreError::Corrupt)?;
    Ok((
        y.parse().map_err(|_| StoreError::Corrupt)?,
        m.parse().map_err(|_| StoreError::Corrupt)?,
    ))
}

/// Opens `tenant`'s own partition of a sub-partitioned month (archive role).
///
/// # Errors
/// [`StoreError`], also while the month's default partition holds rows of the tenant.
pub async fn open_tenant(
    archive: &PgPool,
    (year, month): (i32, u32),
    tenant: [u8; 16],
) -> Result<String, StoreError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT access.open_audit_tenant(make_date($1, $2, 1), $3) AS "name!""#,
        year,
        i32::try_from(month).map_err(|_| StoreError::Range)?,
        Uuid::from_bytes(tenant),
    )
    .fetch_one(archive)
    .await?)
}

/// The partitions past their hot window whose rows the cell and realm checkpoints all cover
/// (archive role).
///
/// # Errors
/// [`StoreError`].
pub async fn due(archive: &PgPool) -> Result<Vec<Due>, StoreError> {
    let rows = sqlx::query!(
        r#"SELECT partition AS "partition!", tenant_id, to_char(month, 'YYYY-MM') AS "month!",
                  rows AS "rows!"
             FROM access.audit_partitions_due()"#
    )
    .fetch_all(archive)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(Due {
                partition: r.partition,
                tenant: r.tenant_id.map(|t| *t.as_bytes()),
                month: month_of(&r.month)?,
                rows: unsigned(r.rows)?,
            })
        })
        .collect()
}

/// Up to `limit` rows of `partition` after `after`, in integration order (archive role).
///
/// # Errors
/// [`StoreError`], also when `partition` is not an identity audit partition.
pub async fn rows(
    archive: &PgPool,
    partition: &str,
    after: Cursor,
    limit: u32,
) -> Result<Vec<AuditRow>, StoreError> {
    let rows = sqlx::query!(
        r#"SELECT tenant_id AS "tenant_id!", realm_id AS "realm_id!",
                  (extract(epoch FROM at) * 1000)::bigint AS "at_ms!", id AS "id!",
                  xid::text::bigint AS "xid!", event_type AS "event_type!", actor AS "actor!",
                  target AS "target!", correlation AS "correlation!"
             FROM access.audit_partition_rows($1, $2::bigint::text::xid8, $3, $4)"#,
        partition,
        signed(after.xid)?,
        after.id,
        i32::try_from(limit).map_err(|_| StoreError::Range)?,
    )
    .fetch_all(archive)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(AuditRow {
                tenant: *r.tenant_id.as_bytes(),
                realm: *r.realm_id.as_bytes(),
                at_ms: r.at_ms,
                id: r.id,
                xid: unsigned(r.xid)?,
                event_type: r.event_type,
                actor: r.actor,
                target: r.target,
                correlation: r.correlation,
            })
        })
        .collect()
}

/// Records `moved` and detaches its partition into `access_audit_cold` (archive role, OP-73
/// m.4). Call only once the cold copy is written and verified.
///
/// # Errors
/// [`StoreError`]; refused when the partition changed since it was copied or is no longer due,
/// and then nothing moves.
pub async fn detach(archive: &PgPool, moved: &Moved) -> Result<(), StoreError> {
    let (xid, id) = match moved.last {
        Some(c) => (Some(signed(c.xid)?), Some(c.id)),
        None => (None, None),
    };
    sqlx::query!(
        "SELECT access.move_audit_partition($1, $2, $3, $4, $5, $6::bigint::text::xid8, $7)",
        moved.partition,
        signed(moved.rows)?,
        moved.root.as_slice(),
        moved.object_key,
        moved.object_sha256.as_slice(),
        xid,
        id,
    )
    .execute(archive)
    .await?;
    Ok(())
}

/// Every partition moved, oldest month first (archive role).
///
/// # Errors
/// [`StoreError`].
pub async fn moves(archive: &PgPool) -> Result<Vec<Moved>, StoreError> {
    let rows = sqlx::query!(
        r#"SELECT partition, tenant_id, rows, root, object_key, object_sha256,
                  last_xid::text::bigint AS last_xid, last_id
             FROM access_ops.audit_tier_moves ORDER BY month, partition"#
    )
    .fetch_all(archive)
    .await?;
    rows.into_iter()
        .map(|r| {
            let last = match (r.last_xid, r.last_id) {
                (Some(x), Some(id)) => Some(Cursor {
                    xid: unsigned(x)?,
                    id,
                }),
                _ => None,
            };
            Ok(Moved {
                partition: r.partition,
                tenant: r.tenant_id.map(|t| *t.as_bytes()),
                rows: unsigned(r.rows)?,
                root: <[u8; 32]>::try_from(r.root).map_err(|_| StoreError::Corrupt)?,
                object_key: r.object_key,
                object_sha256: <[u8; 32]>::try_from(r.object_sha256)
                    .map_err(|_| StoreError::Corrupt)?,
                last,
            })
        })
        .collect()
}
