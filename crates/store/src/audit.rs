//! Identity plane audit log (OP-10, OP-37, OP-38, OP-134): one minimal row in the business
//! transaction, integrated into a Merkle tree later by the checkpointer, in xid8 watermark
//! order, so the request path never waits for it.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{Cursor, TenantTx};

/// The minimal audit row (OP-10): identifiers only, no personal data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent<'a> {
    /// Event type, `snake_case` with dots.
    pub event_type: &'a str,
    /// Who acted.
    pub actor: &'a str,
    /// What it acted on.
    pub target: &'a str,
    /// Request correlation id.
    pub correlation: &'a str,
}

/// An audit row as integrated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRow {
    /// Tenant.
    pub tenant: [u8; 16],
    /// Realm.
    pub realm: [u8; 16],
    /// Unix milliseconds.
    pub at_ms: i64,
    /// Row id.
    pub id: i64,
    /// Writing transaction id.
    pub xid: u64,
    /// Event type.
    pub event_type: String,
    /// Actor.
    pub actor: String,
    /// Target.
    pub target: String,
    /// Correlation.
    pub correlation: String,
}

/// A stored checkpoint (OP-38): the tree after `size` rows, ending at `cursor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointRow {
    /// Number of rows in the tree.
    pub size: u64,
    /// RFC 9162 tree head.
    pub root: [u8; 32],
    /// Merkle frontier, largest subtree first.
    pub frontier: Vec<[u8; 32]>,
    /// The last integrated row.
    pub cursor: Cursor,
}

impl TenantTx {
    /// Writes the audit row of this transaction's security change (OPI-6).
    ///
    /// # Errors
    /// [`StoreError`]; the business change fails with it.
    pub async fn audit(&mut self, event: &AuditEvent<'_>) -> Result<(), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        sqlx::query!(
            "INSERT INTO access.identity_audit (tenant_id, realm_id, event_type, actor, target, correlation)
             VALUES ($1, $2, $3, $4, $5, $6)",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            event.event_type,
            event.actor,
            event.target,
            event.correlation,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }
}

impl TenantTx {
    /// The realm's newest audit rows (OP-43), up to `limit`; the scope decides what is
    /// visible, so a tenant-only scope sees none.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn list_audit(&mut self, limit: u32) -> Result<Vec<AuditRow>, StoreError> {
        let rows = sqlx::query!(
            r#"SELECT tenant_id, realm_id, (extract(epoch FROM at) * 1000)::bigint AS "at_ms!", id,
                      xid::text::bigint AS "xid!", event_type, actor, target, correlation
                 FROM access.identity_audit ORDER BY at DESC, id DESC LIMIT $1"#,
            i64::from(limit),
        )
        .fetch_all(&mut *self.tx)
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
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn hash(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// Rows after `after` whose transactions have ended, in integration order (OQ-MD3's
/// watermark, OP-131).
///
/// # Errors
/// [`StoreError`].
pub async fn pending(
    checkpointer: &PgPool,
    after: Cursor,
    limit: u32,
) -> Result<Vec<AuditRow>, StoreError> {
    let rows = sqlx::query!(
        r#"SELECT tenant_id, realm_id, (extract(epoch FROM at) * 1000)::bigint AS "at_ms!", id,
                  xid::text::bigint AS "xid!", event_type, actor, target, correlation
             FROM access.identity_audit
            WHERE xid < pg_snapshot_xmin(pg_current_snapshot())
              AND (xid, id) > ($1::bigint::text::xid8, $2)
            ORDER BY xid, id
            LIMIT $3"#,
        i64::try_from(after.xid).map_err(|_| StoreError::Range)?,
        after.id,
        i64::from(limit),
    )
    .fetch_all(checkpointer)
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

/// The latest checkpoint, if any.
///
/// # Errors
/// [`StoreError`].
pub async fn last_checkpoint(checkpointer: &PgPool) -> Result<Option<CheckpointRow>, StoreError> {
    let row = sqlx::query!(
        r#"SELECT size, root, frontier, xid::text::bigint AS "xid!", id
             FROM access_ops.audit_checkpoint ORDER BY size DESC LIMIT 1"#
    )
    .fetch_optional(checkpointer)
    .await?;
    row.map(|r| {
        Ok(CheckpointRow {
            size: unsigned(r.size)?,
            root: hash(r.root)?,
            frontier: r.frontier.into_iter().map(hash).collect::<Result<_, _>>()?,
            cursor: Cursor {
                xid: unsigned(r.xid)?,
                id: r.id,
            },
        })
    })
    .transpose()
}

/// Appends a checkpoint; a second checkpoint of the same size fails, so two checkpointers
/// cannot fork the tree.
///
/// # Errors
/// [`StoreError`].
pub async fn append_checkpoint(checkpointer: &PgPool, c: &CheckpointRow) -> Result<(), StoreError> {
    let frontier: Vec<Vec<u8>> = c.frontier.iter().map(|h| h.to_vec()).collect();
    sqlx::query!(
        "INSERT INTO access_ops.audit_checkpoint (size, root, frontier, xid, id)
         VALUES ($1, $2, $3, $4::bigint::text::xid8, $5)",
        i64::try_from(c.size).map_err(|_| StoreError::Range)?,
        c.root.as_slice(),
        &frontier,
        i64::try_from(c.cursor.xid).map_err(|_| StoreError::Range)?,
        c.cursor.id,
    )
    .execute(checkpointer)
    .await?;
    Ok(())
}

/// Opens the monthly partition holding `day` (archive role; OP-13b).
///
/// # Errors
/// [`StoreError`].
pub async fn open_month(archive: &PgPool, year: i32, month: u32) -> Result<String, StoreError> {
    let name = sqlx::query_scalar!(
        r#"SELECT access.open_audit_month(make_date($1, $2, 1)) AS "name!""#,
        year,
        i32::try_from(month).map_err(|_| StoreError::Range)?,
    )
    .fetch_one(archive)
    .await?;
    Ok(name)
}
