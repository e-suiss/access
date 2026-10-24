//! Algorithm-tagged digests, domain-separated hashes and RFC 9162 Merkle proofs (OP-106).

use alloc::vec::Vec;

use sha2::{Digest as _, Sha256};
use suiss_crypto::dcbor::Value;

/// COSE algorithm identifier of SHA-256 (OP-106 m.20).
pub const SHA256_ALG: i64 = -16;

/// A 32-byte SHA-256 output.
pub type Hash = [u8; 32];

// OP-106 m.12
const LEAF: u8 = 0x00;
const NODE: u8 = 0x01;
const FIELD: u8 = 0x02;
const BODY: u8 = 0x03;

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

/// What a digest is of; each kind hashes under its own context string (OP-106 m.22).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    /// `IntentEnvelope`.
    Intent,
    /// Genesis record without `domain`; the result is the `DomainID` (OP-106 m.10).
    Genesis,
}

impl Context {
    /// The context string.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Intent => "access/intent/v1",
            Self::Genesis => "access/genesis/v1",
        }
    }
}

/// `SHA-256(context ‖ 0x00 ‖ canonical bytes)`.
#[must_use]
pub fn digest(context: Context, canonical: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(context.label().as_bytes());
    h.update([0x00]);
    h.update(canonical);
    Digest(h.finalize().into())
}

/// Domain identifier: the `access/genesis/v1` digest of the Genesis `record-envelope`, which has no
/// `domain` field (OP-106 m.10, OP-117 m.2).
#[must_use]
pub fn domain_id(genesis_envelope: &[u8]) -> Digest {
    digest(Context::Genesis, genesis_envelope)
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
