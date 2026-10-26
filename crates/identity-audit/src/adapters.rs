//! PostgreSQL adapter of the [`AuditLog`] port, as `access_checkpointer`.

use access_store::Pool;
use access_store::audit::{AuditRow, CheckpointRow, append_checkpoint, last_checkpoint, pending};
use access_store::identity::Cursor;

use crate::AuditError;
use crate::ports::AuditLog;

/// The audit log in PostgreSQL.
pub struct PgAudit(pub Pool);

impl AuditLog for PgAudit {
    async fn last(&self) -> Result<Option<CheckpointRow>, AuditError> {
        Ok(last_checkpoint(&self.0).await?)
    }

    async fn pending(&self, after: Cursor, limit: u32) -> Result<Vec<AuditRow>, AuditError> {
        Ok(pending(&self.0, after, limit).await?)
    }

    async fn append(&self, checkpoint: &CheckpointRow) -> Result<(), AuditError> {
        Ok(append_checkpoint(&self.0, checkpoint).await?)
    }
}
