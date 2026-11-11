//! The authority plane's operational audit stream (OP-39, OP-44, U53, PI-4): protocol
//! rejections and audit reads, which make no record, one row each and never sampled. It is a
//! second chain beside the identity audit log, of the same shape: rows sequenced by the database,
//! integrated into their own Merkle tree by the checkpointer, off the request path.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::audit::CheckpointRow;
use crate::identity::Cursor;

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn hash(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// One event of the authority plane's operational audit stream (OP-39, OP-44): a protocol
/// rejection or an audit read. Identifiers only, no personal data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalEvent<'a> {
    /// When it happened, Unix milliseconds of the decision point's trusted time.
    pub occurred_at_ms: u64,
    /// The tenant, when the domain is known.
    pub tenant: Option<[u8; 16]>,
    /// The domain, when the request named one that exists.
    pub domain: Option<[u8; 32]>,
    /// Event type from the audit taxonomy.
    pub event_type: &'a str,
    /// Who acted: the PEP, or the actor's Instance when the statement verified.
    pub actor: &'a str,
    /// What it was about.
    pub target: &'a str,
    /// The stable reason code; empty when there is none.
    pub reason: &'a str,
    /// Request correlation id, the common `txn` of both publication channels (OP-41).
    pub correlation: &'a str,
}

/// An operational audit row as integrated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalRow {
    /// When it was written, Unix milliseconds.
    pub at_ms: i64,
    /// Row id.
    pub id: i64,
    /// Writing transaction id.
    pub xid: u64,
    /// When it happened, Unix milliseconds.
    pub occurred_at_ms: u64,
    /// Tenant.
    pub tenant: Option<[u8; 16]>,
    /// Domain.
    pub domain: Option<[u8; 32]>,
    /// Event type.
    pub event_type: String,
    /// Actor.
    pub actor: String,
    /// Target.
    pub target: String,
    /// Reason code.
    pub reason: String,
    /// Correlation.
    pub correlation: String,
}

/// Appends one event to the operational audit stream, in its own transaction; the caller
/// answers only once it is in (OP-44: never sampled).
///
/// # Errors
/// [`StoreError`].
pub async fn record_operational(app: &PgPool, e: &OperationalEvent<'_>) -> Result<(), StoreError> {
    sqlx::query!(
        "INSERT INTO access_ops.authority_audit
           (occurred_at, tenant_id, domain_id, event_type, actor, target, reason, correlation)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        i64::try_from(e.occurred_at_ms).map_err(|_| StoreError::Range)?,
        e.tenant.map(Uuid::from_bytes),
        e.domain.as_ref().map(<[u8; 32]>::as_slice),
        e.event_type,
        e.actor,
        e.target,
        e.reason,
        e.correlation,
    )
    .execute(app)
    .await?;
    Ok(())
}

/// Operational rows after `after` whose transactions have ended, in integration order.
///
/// # Errors
/// [`StoreError`].
pub async fn pending_operational(
    checkpointer: &PgPool,
    after: Cursor,
    limit: u32,
) -> Result<Vec<OperationalRow>, StoreError> {
    let rows = sqlx::query!(
        r#"SELECT (extract(epoch FROM at) * 1000)::bigint AS "at_ms!", id,
                  xid::text::bigint AS "xid!", occurred_at, tenant_id, domain_id, event_type,
                  actor, target, reason, correlation
             FROM access_ops.authority_audit
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
            Ok(OperationalRow {
                at_ms: r.at_ms,
                id: r.id,
                xid: unsigned(r.xid)?,
                occurred_at_ms: unsigned(r.occurred_at)?,
                tenant: r.tenant_id.map(|t| *t.as_bytes()),
                domain: r.domain_id.map(hash).transpose()?,
                event_type: r.event_type,
                actor: r.actor,
                target: r.target,
                reason: r.reason,
                correlation: r.correlation,
            })
        })
        .collect()
}

/// Every operational row written so far, in id order, whether or not its transaction has ended
/// for every other session: what an auditor of the stream counts (OP-44).
///
/// # Errors
/// [`StoreError`].
pub async fn operational_rows(
    checkpointer: &PgPool,
    limit: u32,
) -> Result<Vec<OperationalRow>, StoreError> {
    let rows = sqlx::query!(
        r#"SELECT (extract(epoch FROM at) * 1000)::bigint AS "at_ms!", id,
                  xid::text::bigint AS "xid!", occurred_at, tenant_id, domain_id, event_type,
                  actor, target, reason, correlation
             FROM access_ops.authority_audit
            ORDER BY id
            LIMIT $1"#,
        i64::from(limit),
    )
    .fetch_all(checkpointer)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(OperationalRow {
                at_ms: r.at_ms,
                id: r.id,
                xid: unsigned(r.xid)?,
                occurred_at_ms: unsigned(r.occurred_at)?,
                tenant: r.tenant_id.map(|t| *t.as_bytes()),
                domain: r.domain_id.map(hash).transpose()?,
                event_type: r.event_type,
                actor: r.actor,
                target: r.target,
                reason: r.reason,
                correlation: r.correlation,
            })
        })
        .collect()
}

/// The latest checkpoint of the operational stream, if any.
///
/// # Errors
/// [`StoreError`].
pub async fn last_operational_checkpoint(
    checkpointer: &PgPool,
) -> Result<Option<CheckpointRow>, StoreError> {
    let row = sqlx::query!(
        r#"SELECT size, root, frontier, xid::text::bigint AS "xid!", id, note
             FROM access_ops.authority_audit_checkpoint ORDER BY size DESC LIMIT 1"#
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
            note: Some(r.note),
        })
    })
    .transpose()
}

/// Appends a signed checkpoint of the operational stream; one without its note, or a second
/// one of the same size, fails.
///
/// # Errors
/// [`StoreError`].
pub async fn append_operational_checkpoint(
    checkpointer: &PgPool,
    c: &CheckpointRow,
) -> Result<(), StoreError> {
    let frontier: Vec<Vec<u8>> = c.frontier.iter().map(|h| h.to_vec()).collect();
    let note = c.note.as_deref().ok_or(StoreError::Range)?;
    sqlx::query!(
        "INSERT INTO access_ops.authority_audit_checkpoint (size, root, frontier, xid, id, note)
         VALUES ($1, $2, $3, $4::bigint::text::xid8, $5, $6)",
        i64::try_from(c.size).map_err(|_| StoreError::Range)?,
        c.root.as_slice(),
        &frontier,
        i64::try_from(c.cursor.xid).map_err(|_| StoreError::Range)?,
        c.cursor.id,
        note,
    )
    .execute(checkpointer)
    .await?;
    Ok(())
}

/// A live client backend of a role in this database (SEC19, OP-157 m.3 (k)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RoleBackend {
    /// Backend process id.
    pub pid: i32,
    /// When the backend started, Unix milliseconds.
    pub started_ms: i64,
}

/// The client backends `role` has open in this database now, from `pg_stat_activity`.
///
/// # Errors
/// [`StoreError`].
pub async fn role_backends(pool: &PgPool, role: &str) -> Result<Vec<RoleBackend>, StoreError> {
    let rows = sqlx::query!(
        r#"SELECT pid AS "pid!", (extract(epoch FROM backend_start) * 1000)::bigint AS "started!"
             FROM pg_stat_activity
            WHERE usename = $1 AND datname = current_database() AND backend_type = 'client backend'
            ORDER BY pid"#,
        role,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| RoleBackend {
            pid: r.pid,
            started_ms: r.started,
        })
        .collect())
}
