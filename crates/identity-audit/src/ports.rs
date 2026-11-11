//! What the checkpointer needs from storage (OP-63).

use std::future::Future;

use access_store::audit::{AuditRow, CheckpointRow};
use access_store::audit_realm::RealmCheckpointRow;
use access_store::audit_tier::{Due, Moved};
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

/// The realms' own audit trees of the identity audit log (OP-152 m.7 (d)).
pub trait RealmTrees {
    /// The latest checkpoint of a realm's tree.
    fn realm_last(
        &self,
        scope: ([u8; 16], [u8; 16]),
    ) -> impl Future<Output = Result<Option<RealmCheckpointRow>, AuditError>> + Send;
    /// The realm's rows after `after` up to and including `upto`, in integration order.
    fn realm_pending(
        &self,
        scope: ([u8; 16], [u8; 16]),
        after: Cursor,
        upto: Cursor,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<AuditRow>, AuditError>> + Send;
    /// Appends a realm checkpoint; fails if one of that size exists.
    fn realm_append(
        &self,
        checkpoint: &RealmCheckpointRow,
    ) -> impl Future<Output = Result<(), AuditError>> + Send;
}

/// The cell's `audit-checkpoint` key in the identity signer (OP-150 m.3 (h)).
pub trait NoteSigner {
    /// The audit log's origin and the key's C2SP verifier key.
    fn key(&self) -> impl Future<Output = Result<(String, String), AuditError>> + Send;
    /// The note signature line over a checkpoint body.
    fn sign(&self, body: String) -> impl Future<Output = Result<String, AuditError>> + Send;
}

/// The hot partitions of the identity audit log as the archive role sees them (OP-73 m.4).
pub trait Tiers {
    /// The partitions the cold tier may take now.
    fn due(&self) -> impl Future<Output = Result<Vec<Due>, AuditError>> + Send;
    /// Up to `limit` rows of `partition` after `after`, in integration order.
    fn rows(
        &self,
        partition: &str,
        after: Cursor,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<AuditRow>, AuditError>> + Send;
    /// Records the verified copy and detaches the partition; refused if it changed.
    fn detach(&self, moved: &Moved) -> impl Future<Output = Result<(), AuditError>> + Send;
}

/// The cold tier's object store: write once, never overwritten (OP-40, OP-73 m.4).
pub trait ColdStore {
    /// Stores `bytes` under `key`; an object already there is kept and the call fails unless it
    /// holds the same bytes.
    fn put(&self, key: &str, bytes: &[u8]) -> impl Future<Output = Result<(), AuditError>> + Send;
    /// The object under `key`, `None` when there is none.
    fn get(&self, key: &str) -> impl Future<Output = Result<Option<Vec<u8>>, AuditError>> + Send;
}

/// The cold tier's file format: OCSF Parquet with the rows' own fields (OP-41, OP-158 m.3 (w)).
pub trait ColdCodec {
    /// The file of `rows`.
    ///
    /// # Errors
    /// [`AuditError::Cold`].
    fn encode(&self, rows: &[AuditRow]) -> Result<Vec<u8>, AuditError>;
    /// The rows of a file, in its order.
    ///
    /// # Errors
    /// [`AuditError::Cold`].
    fn decode(&self, file: &[u8]) -> Result<Vec<AuditRow>, AuditError>;
}
