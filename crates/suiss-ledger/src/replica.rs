//! A replica that follows a log: it rebuilds the tree from the mirrored leaves and accepts a
//! checkpoint only when its own tree has the same size and root, and a newer one only when it
//! is consistent with the last (T21, TI-13, RFC 9162 §2.1.4, OP-140 m.5).

use suiss_crypto::digest::{ProofError, verify_consistency};
use suiss_crypto::note::Checkpoint;

use crate::Hash;
use crate::merkle::{Frontier, FrontierError};

/// Why a mirrored record or checkpoint is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReplicaError {
    /// The tree would overflow.
    #[error("tree overflow")]
    Overflow,
    /// The checkpoint is for another log.
    #[error("checkpoint of another log")]
    Origin,
    /// The checkpoint's size differs from the leaves mirrored.
    #[error("checkpoint size differs from the mirrored log")]
    Size,
    /// The checkpoint's root differs from the root of the mirrored leaves: the log forked or a
    /// record changed.
    #[error("checkpoint root differs from the mirrored log")]
    Root,
    /// A newer checkpoint is not an extension of the last accepted one.
    #[error("inconsistent checkpoint: {0}")]
    Inconsistent(ProofError),
}

/// The state of one replica.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Follower {
    origin: alloc::string::String,
    tree: Frontier,
    accepted: Option<(u64, Hash)>,
}

impl Follower {
    /// A replica of the log `origin`, starting empty.
    #[must_use]
    pub fn new(origin: &str) -> Self {
        Self {
            origin: alloc::string::String::from(origin),
            tree: Frontier::default(),
            accepted: None,
        }
    }

    /// Leaves mirrored so far.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.tree.size()
    }

    /// Appends the next mirrored leaf hash, in position order.
    ///
    /// # Errors
    /// [`ReplicaError::Overflow`].
    pub fn append(&mut self, leaf: Hash) -> Result<(), ReplicaError> {
        self.tree
            .push(leaf)
            .map_err(|FrontierError| ReplicaError::Overflow)
    }

    /// Accepts a verified checkpoint when the mirrored leaves give exactly its size and root,
    /// and `proof` shows it extends the last accepted checkpoint.
    ///
    /// # Errors
    /// [`ReplicaError`].
    pub fn accept(&mut self, cp: &Checkpoint, proof: &[Hash]) -> Result<(), ReplicaError> {
        if cp.origin != self.origin {
            return Err(ReplicaError::Origin);
        }
        if cp.size != self.tree.size() {
            return Err(ReplicaError::Size);
        }
        if cp.root != self.tree.root() {
            return Err(ReplicaError::Root);
        }
        if let Some((size, root)) = self.accepted {
            verify_consistency(size, cp.size, &root, &cp.root, proof)
                .map_err(ReplicaError::Inconsistent)?;
        }
        self.accepted = Some((cp.size, cp.root));
        Ok(())
    }

    /// The last accepted checkpoint's size and root.
    #[must_use]
    pub const fn accepted(&self) -> Option<(u64, Hash)> {
        self.accepted
    }
}

#[cfg(test)]
mod tests;
