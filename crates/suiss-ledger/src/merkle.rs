//! RFC 9162 Merkle frontier: the roots of the perfect subtrees on the right edge of the tree.

use alloc::vec::Vec;

use sha2::{Digest as _, Sha256};

use crate::Hash;

// L0-ENC-24
const NODE: u8 = 0x01;

/// RFC 9162 interior node hash.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([NODE]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The frontier of a tree of `size` leaves: one subtree root per set bit of `size`, largest
/// first, so the next root follows without reading the leaves again (OP-130 m.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frontier {
    size: u64,
    nodes: Vec<Hash>,
}

/// A frontier whose node count does not match its size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("frontier does not match its size")]
pub struct FrontierError;

impl Frontier {
    /// Rebuilds a frontier from stored parts.
    ///
    /// # Errors
    /// [`FrontierError`] when `nodes` does not have one entry per set bit of `size`.
    pub fn from_parts(size: u64, nodes: Vec<Hash>) -> Result<Self, FrontierError> {
        if usize::try_from(size.count_ones()).ok() != Some(nodes.len()) {
            return Err(FrontierError);
        }
        Ok(Self { size, nodes })
    }

    /// Number of leaves.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Subtree roots, largest first.
    #[must_use]
    pub fn nodes(&self) -> &[Hash] {
        &self.nodes
    }

    /// Appends a leaf hash.
    ///
    /// # Errors
    /// [`FrontierError`] when the tree already holds `u64::MAX` leaves.
    pub fn push(&mut self, leaf: Hash) -> Result<(), FrontierError> {
        let size = self.size.checked_add(1).ok_or(FrontierError)?;
        let mut node = leaf;
        for _ in 0..self.size.trailing_ones() {
            let left = self.nodes.pop().ok_or(FrontierError)?;
            node = node_hash(&left, &node);
        }
        self.nodes.push(node);
        self.size = size;
        Ok(())
    }

    /// The RFC 9162 tree head; the hash of the empty string for an empty tree.
    #[must_use]
    pub fn root(&self) -> Hash {
        let mut nodes = self.nodes.iter().rev();
        let Some(last) = nodes.next() else {
            return Sha256::digest([]).into();
        };
        nodes.fold(*last, |acc, left| node_hash(left, &acc))
    }
}

#[cfg(test)]
mod tests;
