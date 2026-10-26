//! What the checkpointer needs from storage (OP-63).

use std::future::Future;

use access_store::audit::{AuditRow, CheckpointRow};
use access_store::identity::Cursor;

use crate::AuditError;

/// The audit log as the checkpointer sees it.
pub trait AuditLog {
    /// The latest checkpoint.
    fn last(&self) -> impl Future<Output = Result<Option<CheckpointRow>, AuditError>> + Send;
    /// Ended rows after `after`, in integration order.
    fn pending(
        &self,
        after: Cursor,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<AuditRow>, AuditError>> + Send;
    /// Appends a checkpoint; fails if one of that size exists.
    fn append(
        &self,
        checkpoint: &CheckpointRow,
    ) -> impl Future<Output = Result<(), AuditError>> + Send;
}
