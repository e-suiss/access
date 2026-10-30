//! Algorithm-tagged digests, domain-separated hashes and RFC 9162 Merkle proofs (OP-106, OP-140 m.2).

use alloc::vec::Vec;

use crate::dcbor::Value;
use sha2::{Digest as _, Sha256};

/// COSE algorithm identifier of SHA-256 (OP-106 m.20).
pub const SHA256_ALG: i64 = -16;

/// A 32-byte SHA-256 output.
pub type Hash = [u8; 32];

// OP-106 m.12
/// Prefix of an RFC 9162 leaf hash.
pub const LEAF: u8 = 0x00;
/// Prefix of an RFC 9162 interior node hash.
pub const NODE: u8 = 0x01;
/// Prefix of a salted field commitment.
pub const FIELD: u8 = 0x02;
/// Prefix of a salted body commitment.
pub const BODY: u8 = 0x03;

/// Longest Merkle proof accepted: a tree of `u64` size is at most 64 levels deep.
pub const MAX_PROOF: usize = 64;

/// `SHA-256(label ‖ 0x00 ‖ canonical bytes)`: a digest under a product's context label
/// (OP-106 m.22). The labels belong to the product.
#[must_use]
pub fn context_digest(label: &str, canonical: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    h.update([0x00]);
    h.update(canonical);
    Digest(h.finalize().into())
}

/// An algorithm-tagged digest, encoded as `[-16, bstr .size 32]` (OP-106 m.20).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(pub Hash);

impl Digest {
    /// The CBOR form.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Array(alloc::vec![
            Value::int(SHA256_ALG),
            Value::Bytes(self.0.to_vec())
        ])
    }

    /// Reads the CBOR form; any other algorithm or length is rejected.
    #[must_use]
    pub fn from_value(v: &Value) -> Option<Self> {
        match v {
            Value::Array(items) => match items.as_slice() {
                [alg, Value::Bytes(b)] if alg.as_i64() == Some(SHA256_ALG) => {
                    Hash::try_from(b.as_slice()).ok().map(Self)
                }
                _ => None,
            },
            _ => None,
        }
    }
}

fn prefixed(prefix: u8, parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update([prefix]);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// RFC 9162 leaf hash.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> Hash {
    prefixed(LEAF, &[data])
}

/// RFC 9162 interior node hash.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    prefixed(NODE, &[left, right])
}

/// Field commitment over `dCBOR([name, value])` (§17.6.1, OP-106 m.12).
#[must_use]
pub fn field_commit(salt: &[u8; 32], name_value_cbor: &[u8]) -> Hash {
    prefixed(FIELD, &[salt, name_value_cbor])
}

/// Body commitment over `dCBOR(body)` (OP-106 m.14).
#[must_use]
pub fn body_commit(salt: &[u8; 32], body_cbor: &[u8]) -> Hash {
    prefixed(BODY, &[salt, body_cbor])
}

/// RFC 9162 Merkle tree hash over leaf inputs. The empty tree is `SHA-256("")`.
#[must_use]
pub fn root(leaves: &[&[u8]]) -> Hash {
    match leaves {
        [] => Sha256::digest([]).into(),
        [one] => leaf_hash(one),
        _ => {
            let k = split(leaves.len());
            let (l, r) = leaves.split_at(k);
            node_hash(&root(l), &root(r))
        }
    }
}

fn split(n: usize) -> usize {
    let mut k = 1_usize;
    while let Some(next) = k.checked_mul(2) {
        if next >= n {
            break;
        }
        k = next;
    }
    k
}

/// Why a Merkle proof does not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofError {
    /// Index or sizes are out of range.
    #[error("index or size out of range")]
    Range,
    /// The proof has the wrong number of entries.
    #[error("proof has the wrong length")]
    Length,
    /// The recomputed root does not match.
    #[error("root mismatch")]
    Mismatch,
}

impl ProofError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Range => "proof-range",
            Self::Length => "proof-length",
            Self::Mismatch => "proof-mismatch",
        }
    }
}

/// RFC 9162 §2.1.3.2.
///
/// # Errors
/// The proof does not show `leaf` at `index` in the tree of `size` with `root`.
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf: &Hash,
    path: &[Hash],
    root: &Hash,
) -> Result<(), ProofError> {
    if index >= size {
        return Err(ProofError::Range);
    }
    if path.len() > MAX_PROOF {
        return Err(ProofError::Length);
    }
    let mut f = index;
    let mut s = size.checked_sub(1).ok_or(ProofError::Range)?;
    let mut r = *leaf;
    for p in path {
        if s == 0 {
            return Err(ProofError::Length);
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 {
        return Err(ProofError::Length);
    }
    if r == *root {
        Ok(())
    } else {
        Err(ProofError::Mismatch)
    }
}

/// RFC 9162 §2.1.4.2. Equal sizes need an empty proof and equal roots; size 0 is consistent with anything.
///
/// # Errors
/// The proof does not show that the tree of `first` is a prefix of the tree of `second`.
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &Hash,
    second_root: &Hash,
    path: &[Hash],
) -> Result<(), ProofError> {
    if first > second {
        return Err(ProofError::Range);
    }
    if path.len() > MAX_PROOF {
        return Err(ProofError::Length);
    }
    if first == 0 || first == second {
        if !path.is_empty() {
            return Err(ProofError::Length);
        }
        return if first == 0 || first_root == second_root {
            Ok(())
        } else {
            Err(ProofError::Mismatch)
        };
    }
    let mut nodes: Vec<Hash> = Vec::new();
    if first.is_power_of_two() {
        nodes.push(*first_root);
    }
    nodes.extend_from_slice(path);
    let (start, rest) = nodes.split_first().ok_or(ProofError::Length)?;
    let mut f = first.checked_sub(1).ok_or(ProofError::Range)?;
    let mut s = second.checked_sub(1).ok_or(ProofError::Range)?;
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let mut fr = *start;
    let mut sr = *start;
    for c in rest {
        if s == 0 {
            return Err(ProofError::Length);
        }
        if f & 1 == 1 || f == s {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 {
        return Err(ProofError::Length);
    }
    if fr == *first_root && sr == *second_root {
        Ok(())
    } else {
        Err(ProofError::Mismatch)
    }
}

#[cfg(test)]
mod tests;
