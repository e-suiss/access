//! Identity plane audit checkpoints (OP-37, OP-38, OP-134): rows are sequenced by the database
//! and integrated here into an RFC 9162 tree, so the request path never waits for it. Each
//! checkpoint is a C2SP signed note of the cell's `audit-checkpoint` key (OP-150 m.3 (h)).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

use access_store::StoreError;
use suiss_ledger::merkle::FrontierError;

/// Why a checkpoint step failed.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// Storage refused; another checkpointer may have written the same size.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// The stored frontier does not match its size.
    #[error("frontier: {0}")]
    Frontier(#[from] FrontierError),
    /// A row could not be encoded.
    #[error("row encoding")]
    Encode,
    /// The signer is unreachable or refused; the checkpoint waits (CR-23, G42).
    #[error("unsigned: {0}")]
    Unsigned(String),
    /// The note does not verify under the cell key or does not state the checkpoint.
    #[error("note: {0}")]
    Note(#[from] suiss_crypto::note::NoteError),
    /// An inclusion path does not show its leaf under the checkpoint's root.
    #[error("inclusion proof")]
    Proof,
    /// The cold tier refused or is unreachable; the partition stays hot (OP-73 m.4).
    #[error("cold tier: {0}")]
    Cold(String),
    /// The cold copy does not match the hot partition; nothing is detached (OP-73 m.4).
    #[error("cold copy does not match its partition")]
    ColdMismatch,
}
