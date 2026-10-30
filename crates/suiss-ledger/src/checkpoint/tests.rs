use alloc::string::String;
use alloc::vec;

use suiss_crypto::digest::{leaf_hash, root};

use super::*;
use crate::merkle::Frontier;

fn head(leaves: &[&[u8]]) -> Head {
    let mut frontier = Frontier::default();
    for l in leaves {
        frontier.push(leaf_hash(l)).unwrap();
    }
    Head {
        pos: u64::try_from(leaves.len()).unwrap().checked_sub(1).unwrap(),
        leaf: leaf_hash(leaves.last().unwrap()),
        recorded_at: 9,
        frontier,
    }
}

// OP-86, L2-CKP-1: the checkpoint names the size and the RFC 9162 root of the head
#[test]
fn checkpoint_of_the_head() {
    let leaves: [&[u8]; 3] = [b"a", b"b", b"c"];
    let cp = of_head("example.com/log", &head(&leaves), vec![String::from("t 9")]).unwrap();
    assert_eq!((cp.size, cp.root), (3, root(&leaves)));
    assert_eq!(
        cp.to_body().unwrap(),
        alloc::format!(
            "example.com/log\n3\n{}\nt 9\n",
            suiss_crypto::note::base64_encode(&root(&leaves))
        )
    );
    assert!(of_head("bad origin", &head(&leaves), vec![]).is_err());
    assert!(of_head("example.com/log", &head(&leaves), vec![String::new()]).is_err());
    let mut wrong = head(&leaves);
    wrong.pos = 7;
    assert!(of_head("example.com/log", &wrong, vec![]).is_err());
}

// T21, TI-13: a checkpoint goes to witnesses only after the replica holds it
#[test]
fn mirror_before_witness() {
    let mut p = Publication::default();
    p.built(10).unwrap();
    assert_eq!(p.may_witness(10), Err(OrderError::NotMirrored));
    p.mirrored(8).unwrap();
    assert_eq!(p.witnessed(10), Err(OrderError::NotMirrored));
    p.mirrored(10).unwrap();
    p.witnessed(10).unwrap();
    assert_eq!(p.may_witness(11), Err(OrderError::Unknown));
    assert_eq!(p.mirrored(9), Err(OrderError::Backwards));
    p.built(12).unwrap();
    p.mirrored(12).unwrap();
    p.witnessed(12).unwrap();
    assert_eq!(p.witnessed(10), Err(OrderError::Backwards));
    assert_eq!(p.witnessed_size(), 12);
    assert_eq!(Publication::resume(5, 4, 5), Err(OrderError::NotMirrored));
}
