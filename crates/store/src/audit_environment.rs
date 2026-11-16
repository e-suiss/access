//! Each environment's own audit tree (OP-152 m.7 (d), Ek B 2527): the environment's identity audit rows in
//! the cell's integration order, checkpointed by the checkpointer and signed by the cell key
//! under the environment's origin, so an environment proves inclusion of its events without the cell tree's
//! size. Append-only (OP-73).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::audit::AuditRow;
use crate::identity::{Cursor, TenantTx};

/// One environment tree checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentCheckpointRow {
    /// Tenant.
    pub tenant: [u8; 16],
    /// Environment.
    pub environment: [u8; 16],
    /// Rows in the environment's tree.
    pub size: u64,
    /// RFC 9162 tree head.
    pub root: [u8; 32],
    /// Merkle frontier, largest subtree first.
    pub frontier: Vec<[u8; 32]>,
    /// The environment's last integrated row.
    pub cursor: Cursor,
    /// Size of the cell checkpoint it follows; never shown to the environment.
    pub cell_size: u64,
    /// The C2SP signed note over the environment checkpoint.
    pub note: String,
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn hash(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// The latest checkpoint of the environment's tree (checkpointer role).
///
/// # Errors
/// [`StoreError`].
pub async fn last_environment_checkpoint(
    checkpointer: &PgPool,
    tenant: [u8; 16],
    environment: [u8; 16],
) -> Result<Option<EnvironmentCheckpointRow>, StoreError> {
    let row = sqlx::query!(
        r#"SELECT size, root, frontier, xid::text::bigint AS "xid!", id, cell_size, note
             FROM access_ops.audit_environment_checkpoint
            WHERE tenant_id = $1 AND environment_id = $2 ORDER BY size DESC LIMIT 1"#,
        Uuid::from_bytes(tenant),
        Uuid::from_bytes(environment),
    )
    .fetch_optional(checkpointer)
    .await?;
    row.map(|r| {
        Ok(EnvironmentCheckpointRow {
            tenant,
            environment,
            size: unsigned(r.size)?,
            root: hash(r.root)?,
            frontier: r.frontier.into_iter().map(hash).collect::<Result<_, _>>()?,
            cursor: Cursor {
                xid: unsigned(r.xid)?,
                id: r.id,
            },
            cell_size: unsigned(r.cell_size)?,
            note: r.note,
        })
    })
    .transpose()
}

/// The environment's rows after `after` up to and including `upto`, in integration order, at most
/// `limit` (checkpointer role).
///
/// # Errors
/// [`StoreError`].
pub async fn environment_pending(
    checkpointer: &PgPool,
    (tenant, environment): ([u8; 16], [u8; 16]),
    after: Cursor,
    upto: Cursor,
    limit: u32,
) -> Result<Vec<AuditRow>, StoreError> {
    let rows = sqlx::query_as!(
        EnvironmentRow,
        r#"SELECT tenant_id, environment_id, (extract(epoch FROM at) * 1000)::bigint AS "at_ms!", id,
                  xid::text::bigint AS "xid!", event_type, actor, target, correlation
             FROM access.identity_audit
            WHERE tenant_id = $1 AND environment_id = $2
              AND (xid, id) > ($3::bigint::text::xid8, $4)
              AND (xid, id) <= ($5::bigint::text::xid8, $6)
            ORDER BY xid, id
            LIMIT $7"#,
        Uuid::from_bytes(tenant),
        Uuid::from_bytes(environment),
        signed(after.xid)?,
        after.id,
        signed(upto.xid)?,
        upto.id,
        i64::from(limit),
    )
    .fetch_all(checkpointer)
    .await?;
    rows.into_iter().map(row).collect()
}

/// Appends an environment checkpoint; a second one of the same size fails, so the tree cannot fork.
///
/// # Errors
/// [`StoreError`].
pub async fn append_environment_checkpoint(
    checkpointer: &PgPool,
    c: &EnvironmentCheckpointRow,
) -> Result<(), StoreError> {
    let frontier: Vec<Vec<u8>> = c.frontier.iter().map(|h| h.to_vec()).collect();
    sqlx::query!(
        "INSERT INTO access_ops.audit_environment_checkpoint
           (tenant_id, environment_id, size, root, frontier, xid, id, cell_size, note)
         VALUES ($1, $2, $3, $4, $5, $6::bigint::text::xid8, $7, $8, $9)",
        Uuid::from_bytes(c.tenant),
        Uuid::from_bytes(c.environment),
        signed(c.size)?,
        c.root.as_slice(),
        &frontier,
        signed(c.cursor.xid)?,
        c.cursor.id,
        signed(c.cell_size)?,
        c.note,
    )
    .execute(checkpointer)
    .await?;
    Ok(())
}

fn row(r: EnvironmentRow) -> Result<AuditRow, StoreError> {
    Ok(AuditRow {
        tenant: *r.tenant_id.as_bytes(),
        environment: *r.environment_id.as_bytes(),
        at_ms: r.at_ms,
        id: r.id,
        xid: unsigned(r.xid)?,
        event_type: r.event_type,
        actor: r.actor,
        target: r.target,
        correlation: r.correlation,
    })
}

struct EnvironmentRow {
    tenant_id: Uuid,
    environment_id: Uuid,
    at_ms: i64,
    id: i64,
    xid: i64,
    event_type: String,
    actor: String,
    target: String,
    correlation: String,
}

impl TenantTx {
    /// The first `size` audit rows of this transaction's environment in integration order: the leaves
    /// of the environment's tree at that size (OP-152 m.7 (d)).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn environment_audit_leaves(
        &mut self,
        size: u64,
    ) -> Result<Vec<AuditRow>, StoreError> {
        let environment = self.environment().ok_or(StoreError::Range)?;
        let rows = sqlx::query_as!(
            EnvironmentRow,
            r#"SELECT tenant_id, environment_id, (extract(epoch FROM at) * 1000)::bigint AS "at_ms!", id,
                      xid::text::bigint AS "xid!", event_type, actor, target, correlation
                 FROM access.identity_audit
                WHERE environment_id = $1 ORDER BY xid, id LIMIT $2"#,
            Uuid::from_bytes(*environment.as_bytes()),
            signed(size)?,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter().map(row).collect()
    }
}
