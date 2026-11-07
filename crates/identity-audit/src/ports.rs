//! What the checkpointer needs from storage (OP-63).

use std::future::Future;

use access_store::audit::CheckpointRow;
use access_store::identity::Cursor;

use crate::AuditError;
use crate::domain::Leaf;

/// One audit chain as the checkpointer sees it: the identity audit log, or the authority
/// plane's operational stream (OP-44).
pub trait AuditLog {
    /// The rows this chain integrates.
    type Row: Leaf + Send;
    /// The chain's name under the cell, `None` for the identity audit log; its checkpoints carry
    /// the origin of that chain.
    fn chain(&self) -> Option<&'static str> {
        None
    }
    /// The latest checkpoint.
    fn last(&self) -> impl Future<Output = Result<Option<CheckpointRow>, AuditError>> + Send;
    /// Ended rows after `after`, in integration order.
    fn pending(
        &self,
        after: Cursor,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Self::Row>, AuditError>> + Send;
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
