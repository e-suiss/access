//! Identity plane audit checkpoints (OP-37, OP-38, OP-134): rows are sequenced by the database
//! and integrated here into an RFC 9162 tree, so the request path never waits for it.

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
}
