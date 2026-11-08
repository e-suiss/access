//! Each realm's own audit tree (OP-152 m.7 (d), Ek B 2527): pure. A realm's identity audit
//! rows, in the cell's integration order, form an RFC 9162 tree of their own whose checkpoint
//! the cell key signs under the realm's origin. The checkpoint names the cell checkpoint it
//! follows by the digest of its body only, so a realm's proof never shows the cell tree's size,
//! and with it no other tenant's volume.

use access_kernel::json::b64url_encode;
use suiss_crypto::digest::{node_hash, verify_inclusion};
use suiss_crypto::note::{Checkpoint, NoteError, Verifier, verify_checkpoint};
use suiss_crypto::sig::Backend;
use suiss_ledger::Hash;

use crate::AuditError;

/// The extension line naming the cell checkpoint a realm checkpoint follows.
pub const CELL: &str = "cell sha-256:";

/// The `tlog-checkpoint` body of a realm tree of `size` rows with `root`, following the cell
/// checkpoint whose body is `cell_body`, issued at `issued_at`.
///
/// # Errors
/// [`AuditError::Note`] for an origin that cannot name a log.
pub fn body(
    origin: &str,
    (size, root): (u64, Hash),
    cell_body: &str,
    issued_at: u64,
) -> Result<String, AuditError> {
    let cell = suiss_crypto::digest::sha256(cell_body.as_bytes());
    Ok(Checkpoint {
        origin: origin.to_owned(),
        size,
        root,
        extensions: vec![
            format!("{}{issued_at}", super::ISSUED_AT),
            format!("{CELL}{}", b64url_encode(&cell)),
        ],
    }
    .to_body()?)
}

/// RFC 9162 §2.1.1 `MTH` over `leaves`.
#[must_use]
pub fn tree_hash(leaves: &[Hash]) -> Hash {
    match leaves {
        [] => suiss_crypto::digest::sha256(&[]),
        [one] => *one,
        _ => {
            let k = split(leaves.len());
            let (l, r) = leaves.split_at(k);
            node_hash(&tree_hash(l), &tree_hash(r))
        }
    }
}

/// The largest power of two below `n` (`n` ≥ 2).
fn split(n: usize) -> usize {
    let mut k: usize = 1;
    while k.saturating_mul(2) < n {
        k = k.saturating_mul(2);
    }
    k
}

/// RFC 9162 §2.1.3.1 `PATH(m, D[n])`: the inclusion proof of leaf `index` among `leaves`;
/// `None` when `index` is out of range.
#[must_use]
pub fn inclusion_path(leaves: &[Hash], index: usize) -> Option<Vec<Hash>> {
    if index >= leaves.len() {
        return None;
    }
    let mut path = Vec::new();
    let mut slice = leaves;
    let mut m = index;
    let mut levels = Vec::new();
    while slice.len() > 1 {
        let k = split(slice.len());
        let (l, r) = slice.split_at(k);
        if m < k {
            levels.push(tree_hash(r));
            slice = l;
        } else {
            levels.push(tree_hash(l));
            slice = r;
            m = m.saturating_sub(k);
        }
    }
    while let Some(h) = levels.pop() {
        path.push(h);
    }
    Some(path)
}

/// What a realm proves about one of its events (OP-152 m.7 (d)): the leaf, where it sits, the
/// path to the realm tree's head and the signed realm checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmProof {
    /// The event's leaf hash.
    pub leaf: Hash,
    /// Its index in the realm tree.
    pub index: u64,
    /// The RFC 9162 inclusion path.
    pub path: Vec<Hash>,
    /// The signed note over the realm checkpoint.
    pub note: String,
}

/// Verifies a realm proof under the cell key `vkey` for the realm origin `origin` (L2-CKP-3,
/// RFC 9162 §2.1.3.2): the note verifies, names `origin`, carries `issued_at` and the cell
/// digest, and the path shows the leaf at its index under the note's root. Returns the realm
/// tree's size and root.
///
/// # Errors
/// [`AuditError::Note`] for a note that does not verify or does not have the realm form;
/// [`AuditError::Proof`] for a path that does not show the leaf.
pub fn verify(
    backend: &impl Backend,
    proof: &RealmProof,
    origin: &str,
    vkey: &str,
) -> Result<(u64, Hash), AuditError> {
    let key = Verifier::parse(vkey)?;
    let (cp, _) = verify_checkpoint(backend, &proof.note, origin, &key, &[])?;
    let [issued, cell] = cp.extensions.as_slice() else {
        return Err(NoteError::Checkpoint.into());
    };
    if !issued.starts_with(super::ISSUED_AT) || !cell.starts_with(CELL) {
        return Err(NoteError::Checkpoint.into());
    }
    verify_inclusion(proof.index, cp.size, &proof.leaf, &proof.path, &cp.root)
        .map_err(|_| AuditError::Proof)?;
    Ok((cp.size, cp.root))
}

#[cfg(test)]
mod tests;
