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

/// The cell's `audit-checkpoint` key in the identity signer (OP-150 m.3 (h)).
pub trait NoteSigner {
    /// The audit log's origin and the key's C2SP verifier key.
    fn key(&self) -> impl Future<Output = Result<(String, String), AuditError>> + Send;
    /// The note signature line over a checkpoint body.
    fn sign(&self, body: String) -> impl Future<Output = Result<String, AuditError>> + Send;
}
