//! One writer per cell audit chain (OP-152 m.5 (k)): the replica holding a chain's lease is the
//! only one whose checkpoints the chain accepts, as `access_checkpointer`.

use std::time::Duration;

use sqlx::PgPool;

use crate::StoreError;
use crate::audit::CheckpointRow;

/// A cell audit chain with a checkpoint lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditChain {
    /// The identity audit log (OP-38).
    Identity,
    /// The authority plane's operational stream (OP-39, OP-44).
    Operational,
}

impl AuditChain {
    /// The chain's name in the lease table.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Identity => "identity-audit",
            Self::Operational => "authority-operational",
        }
    }
}

/// Takes or renews `chain`'s lease for `holder` for `ttl`; `false` while another holder's lease
/// is live. The epoch grows when the holder changes.
///
/// # Errors
/// [`StoreError`].
pub async fn acquire_audit_lease(
    checkpointer: &PgPool,
    chain: AuditChain,
    holder: &str,
    ttl: Duration,
) -> Result<bool, StoreError> {
    let ms = i64::try_from(ttl.as_millis()).map_err(|_| StoreError::Range)?;
    let epoch = sqlx::query_scalar!(
        "INSERT INTO access_ops.audit_checkpoint_lease AS l (chain, holder, epoch, expires_at)
         VALUES ($1, $2, 1, now() + make_interval(secs => $3::bigint / 1000.0))
         ON CONFLICT (chain) DO UPDATE SET
           holder = EXCLUDED.holder,
           epoch = CASE WHEN l.holder = EXCLUDED.holder THEN l.epoch ELSE l.epoch + 1 END,
           expires_at = EXCLUDED.expires_at
         WHERE l.holder = EXCLUDED.holder OR l.expires_at <= now()
         RETURNING l.epoch",
        chain.name(),
        holder,
        ms,
    )
    .fetch_optional(checkpointer)
    .await?;
    Ok(epoch.is_some())
}

/// Appends a checkpoint to `chain` only while `holder` holds its live lease; a second checkpoint
/// of the same size fails as with the unleased append.
///
/// # Errors
/// [`StoreError::LeaseLost`] when the lease is not `holder`'s or has expired; [`StoreError`].
pub async fn append_held_checkpoint(
    checkpointer: &PgPool,
    chain: AuditChain,
    holder: &str,
    c: &CheckpointRow,
) -> Result<(), StoreError> {
    let frontier: Vec<Vec<u8>> = c.frontier.iter().map(|h| h.to_vec()).collect();
    let size = i64::try_from(c.size).map_err(|_| StoreError::Range)?;
    let xid = i64::try_from(c.cursor.xid).map_err(|_| StoreError::Range)?;
    let done = match chain {
        AuditChain::Identity => sqlx::query!(
            "INSERT INTO access_ops.audit_checkpoint (size, root, frontier, xid, id, note)
             SELECT $1, $2, $3, $4::bigint::text::xid8, $5, $6
              WHERE EXISTS (SELECT 1 FROM access_ops.audit_checkpoint_lease
                             WHERE chain = $7 AND holder = $8 AND expires_at > now())",
            size,
            c.root.as_slice(),
            &frontier,
            xid,
            c.cursor.id,
            c.note.as_deref(),
            chain.name(),
            holder,
        )
        .execute(checkpointer)
        .await?
        .rows_affected(),
        AuditChain::Operational => sqlx::query!(
            "INSERT INTO access_ops.authority_audit_checkpoint (size, root, frontier, xid, id, note)
             SELECT $1, $2, $3, $4::bigint::text::xid8, $5, $6
              WHERE EXISTS (SELECT 1 FROM access_ops.audit_checkpoint_lease
                             WHERE chain = $7 AND holder = $8 AND expires_at > now())",
            size,
            c.root.as_slice(),
            &frontier,
            xid,
            c.cursor.id,
            c.note.as_deref().ok_or(StoreError::Range)?,
            chain.name(),
            holder,
        )
        .execute(checkpointer)
        .await?
        .rows_affected(),
    };
    if done == 1 {
        Ok(())
    } else {
        Err(StoreError::LeaseLost)
    }
}
