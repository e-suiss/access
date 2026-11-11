//! RFC 9162 §2.1.3.1 and §2.1.4.1 proofs from a log's leaf hashes: the inclusion path of one
//! record and the consistency proof between two checkpoints (T19, CMP-6). The verifiers are
//! `suiss_crypto::digest::{verify_inclusion, verify_consistency}`.

use alloc::vec::Vec;

use suiss_crypto::digest::node_hash;

use crate::Hash;

/// Why a proof could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError<E> {
    /// Index or sizes out of range.
    #[error("index or size out of range")]
    Range,
    /// The leaf source failed.
    #[error("leaves: {0}")]
    Leaves(E),
}

/// A log's leaf hashes, read by position. [`Leaves::subtree`] may be overridden by a source
/// that keeps interior hashes (tiles).
pub trait Leaves {
    /// The error of the source.
    type Error;

    /// The leaf hash at `index`.
    ///
    /// # Errors
    /// The source's error, or `Ok(None)` past its end.
    fn leaf(&self, index: u64) -> Result<Option<Hash>, Self::Error>;

    /// The RFC 9162 tree hash of the leaves `lo..hi`, `lo < hi`.
    ///
    /// # Errors
    /// [`BuildError`].
    fn subtree(&self, lo: u64, hi: u64) -> Result<Hash, BuildError<Self::Error>> {
        let width = hi.checked_sub(lo).ok_or(BuildError::Range)?;
        if width == 1 {
            return self
                .leaf(lo)
                .map_err(BuildError::Leaves)?
                .ok_or(BuildError::Range);
        }
        let k = split(width).ok_or(BuildError::Range)?;
        let mid = lo.checked_add(k).ok_or(BuildError::Range)?;
        Ok(node_hash(&self.subtree(lo, mid)?, &self.subtree(mid, hi)?))
    }
}

impl Leaves for [Hash] {
    type Error = core::convert::Infallible;

    fn leaf(&self, index: u64) -> Result<Option<Hash>, Self::Error> {
        Ok(usize::try_from(index)
            .ok()
            .and_then(|i| self.get(i))
            .copied())
    }
}

/// The largest power of two below `n`, for `n > 1`.
fn split(n: u64) -> Option<u64> {
    if n < 2 {
        return None;
    }
    let below = n.checked_sub(1)?;
    1_u64.checked_shl(63_u32.checked_sub(below.leading_zeros())?)
}

/// The inclusion path of the leaf at `index` in the tree of `size` leaves.
///
/// # Errors
/// [`BuildError`].
pub fn inclusion<L: Leaves + ?Sized>(
    leaves: &L,
    index: u64,
    size: u64,
) -> Result<Vec<Hash>, BuildError<L::Error>> {
    if index >= size {
        return Err(BuildError::Range);
    }
    let mut out = Vec::new();
    path(leaves, index, 0, size, &mut out)?;
    Ok(out)
}

fn path<L: Leaves + ?Sized>(
    leaves: &L,
    m: u64,
    lo: u64,
    hi: u64,
    out: &mut Vec<Hash>,
) -> Result<(), BuildError<L::Error>> {
    let n = hi.checked_sub(lo).ok_or(BuildError::Range)?;
    if n <= 1 {
        return Ok(());
    }
    let k = split(n).ok_or(BuildError::Range)?;
    let mid = lo.checked_add(k).ok_or(BuildError::Range)?;
    if m < k {
        path(leaves, m, lo, mid, out)?;
        out.push(leaves.subtree(mid, hi)?);
    } else {
        let rest = m.checked_sub(k).ok_or(BuildError::Range)?;
        path(leaves, rest, mid, hi, out)?;
        out.push(leaves.subtree(lo, mid)?);
    }
    Ok(())
}

/// The consistency proof from the tree of `first` leaves to the tree of `second`; empty when
/// `first` is 0 or equals `second`.
///
/// # Errors
/// [`BuildError`].
pub fn consistency<L: Leaves + ?Sized>(
    leaves: &L,
    first: u64,
    second: u64,
) -> Result<Vec<Hash>, BuildError<L::Error>> {
    if first > second {
        return Err(BuildError::Range);
    }
    let mut out = Vec::new();
    if first == 0 || first == second {
        return Ok(out);
    }
    subproof(leaves, first, 0, second, true, &mut out)?;
    Ok(out)
}

fn subproof<L: Leaves + ?Sized>(
    leaves: &L,
    m: u64,
    lo: u64,
    hi: u64,
    whole: bool,
    out: &mut Vec<Hash>,
) -> Result<(), BuildError<L::Error>> {
    let n = hi.checked_sub(lo).ok_or(BuildError::Range)?;
    if m == n {
        if !whole {
            out.push(leaves.subtree(lo, hi)?);
        }
        return Ok(());
    }
    let k = split(n).ok_or(BuildError::Range)?;
    let mid = lo.checked_add(k).ok_or(BuildError::Range)?;
    if m <= k {
        subproof(leaves, m, lo, mid, whole, out)?;
        out.push(leaves.subtree(mid, hi)?);
    } else {
        let rest = m.checked_sub(k).ok_or(BuildError::Range)?;
        subproof(leaves, rest, mid, hi, false, out)?;
        out.push(leaves.subtree(lo, mid)?);
    }
    Ok(())
}
