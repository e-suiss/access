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

// OP-86, L2-CKP-1
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

// T21, TI-13
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

fn leaves(n: u64) -> alloc::vec::Vec<crate::Hash> {
    (0..n).map(|i| leaf_hash(&i.to_be_bytes())).collect()
}

fn tree_root(l: &[crate::Hash]) -> crate::Hash {
    let mut f = Frontier::default();
    for h in l {
        f.push(*h).unwrap();
    }
    f.root()
}

// T19, CMP-6, RFC 9162 §2.1.3.1
#[test]
fn inclusion_paths_verify_for_every_leaf() {
    use suiss_crypto::digest::verify_inclusion;
    for n in 1..=33_u64 {
        let l = leaves(n);
        let root = tree_root(&l);
        for i in 0..n {
            let p = proof::inclusion(l.as_slice(), i, n).unwrap();
            verify_inclusion(i, n, &l[usize::try_from(i).unwrap()], &p, &root).unwrap();
        }
        assert_eq!(
            proof::inclusion(l.as_slice(), n, n),
            Err(proof::BuildError::Range)
        );
    }
}

// CMP-6, T17, RFC 9162 §2.1.4.1
#[test]
fn consistency_proofs_verify_for_every_pair() {
    use suiss_crypto::digest::verify_consistency;
    let all = leaves(40);
    for n in 1..=40_usize {
        let second = tree_root(&all[..n]);
        for m in 0..=n {
            let first = tree_root(&all[..m]);
            let p = proof::consistency(&all[..n], m as u64, n as u64).unwrap();
            verify_consistency(m as u64, n as u64, &first, &second, &p).unwrap();
        }
    }
}

// T16, OP-38, OP-158 m.3 (c)
#[test]
fn the_cadence_is_interval_or_records_and_coalesces_requests() {
    use cadence::{Cadence, Due};
    let mut c = Cadence::new(60_000, 1_000);
    assert_eq!(c.due(1, 0), Some(Due::First));
    c.issued(1, 0);
    assert_eq!(c.due(1, 59_999), None);
    assert_eq!(c.due(1, 60_000), Some(Due::Heartbeat));
    assert_eq!(c.due(2, 60_000), Some(Due::Interval));
    assert_eq!(c.due(1_001, 10), Some(Due::Records));
    c.want(5);
    c.want(9);
    c.want(7);
    assert_eq!(c.due(8, 10), None);
    assert_eq!(c.due(9, 10), Some(Due::OutOfCycle));
    c.issued(12, 10);
    assert_eq!(c.due(12, 20), None);
    c.want(12);
    assert_eq!(c.due(12, 20), None);
    assert_eq!(c.last(), Some((12, 10)));
}

fn body(size: u64, root: crate::Hash) -> Checkpoint {
    Checkpoint {
        origin: String::from("example.com/log"),
        size,
        root,
        extensions: vec![],
    }
}

// CMP-6, T17, U11, OP-158 m.3 (d)
#[test]
fn a_witness_cosigns_only_consistent_extensions_of_its_base() {
    use witness::{LogState, Refusal};
    let l = leaves(10);
    let mut w = LogState::default();
    let c4 = body(4, tree_root(&l[..4]));
    assert_eq!(w.check(3, &[], &c4), Err(Refusal::Conflict(0)));
    w.check(0, &[], &c4).unwrap();
    w.cosigned(&c4).unwrap();
    let c7 = body(7, tree_root(&l[..7]));
    let p = proof::consistency(l.as_slice(), 4, 7).unwrap();
    assert_eq!(w.check(0, &p, &c7), Err(Refusal::Conflict(4)));
    w.check(4, &p, &c7).unwrap();
    let forked = body(7, tree_root(&leaves(7)[..6]));
    assert!(matches!(
        w.check(4, &p, &forked),
        Err(Refusal::Inconsistent(_))
    ));
    w.cosigned(&c7).unwrap();
    assert_eq!(w.check(7, &[], &c7), Ok(()));
    assert_eq!(
        w.check(7, &[], &body(7, [9; 32])),
        Err(Refusal::Equivocation)
    );
    assert_eq!(w.check(7, &[], &c4), Err(Refusal::Backwards));
    w.fence_at(8);
    let c9 = body(9, tree_root(&l[..9]));
    let p9 = proof::consistency(l.as_slice(), 7, 9).unwrap();
    assert_eq!(w.check(7, &p9, &c9), Err(Refusal::Fenced(8)));
    w.rebind();
    w.check(7, &p9, &c9).unwrap();
}

// U9, HL-7
#[test]
fn same_size_other_root_is_equivocation() {
    use witness::equivocates;
    let a = body(5, [1; 32]);
    assert!(equivocates(&a, &body(5, [2; 32])));
    assert!(!equivocates(&a, &body(6, [2; 32])));
    assert!(!equivocates(&a, &a.clone()));
}

// CMP-6, T17, OP-158 m.3 (d)
#[test]
fn witness_messages_round_trip_in_deterministic_cbor() {
    use witness::{
        BindingChange, CosignRequest, CosignResponse, Cosignature, GossipEntry, Refused,
        StateEntry, WireError,
    };
    let req = CosignRequest {
        domain: [7; 32],
        note: String::from("o\n2\nAAAA\n\n\u{2014} o abcd\n"),
        excerpt: vec![1, 2],
        base: Some((1, [3; 32])),
        consistency: vec![[4; 32]],
        binding_change: Some(BindingChange {
            position: 5,
            record: vec![9],
            inclusion: vec![[6; 32]],
        }),
    };
    assert_eq!(
        CosignRequest::from_bytes(&req.to_bytes().unwrap()).unwrap(),
        req
    );
    let bare = CosignRequest {
        base: None,
        binding_change: None,
        ..req.clone()
    };
    assert_eq!(
        CosignRequest::from_bytes(&bare.to_bytes().unwrap()).unwrap(),
        bare
    );
    let c = Cosignature {
        name: String::from("w.example"),
        timestamp: 1_767_225_000,
        signature: [0x5c; 64],
    };
    let ok = CosignResponse::Cosigned(c.clone());
    assert_eq!(
        CosignResponse::from_bytes(&ok.to_bytes().unwrap()).unwrap(),
        ok
    );
    let refused = CosignResponse::Refused(Refused::Fenced);
    let bytes = refused.to_bytes().unwrap();
    assert_eq!(
        bytes,
        [
            0xa1, 0x67, b'r', b'e', b'f', b'u', b's', b'e', b'd', 0x66, b'f', b'e', b'n', b'c',
            b'e', b'd'
        ]
    );
    assert_eq!(CosignResponse::from_bytes(&bytes).unwrap(), refused);
    assert_eq!(
        Cosignature::from_line(&c.line(77)).unwrap(),
        (c.clone(), 77)
    );
    let g = GossipEntry {
        witness: String::from("w.example"),
        domain: [7; 32],
        size: 2,
        root: [8; 32],
        cosignature: c,
        note: Some(String::from("n\n")),
    };
    assert_eq!(GossipEntry::from_bytes(&g.to_bytes().unwrap()).unwrap(), g);
    let e = StateEntry {
        seq: 0,
        domain: [7; 32],
        size: 2,
        root: [8; 32],
        binding: [9; 32],
        at: 3,
        prev: [0; 32],
        note: None,
        fence: Some(4),
        keys: Some(vec![[1; 32]]),
    };
    assert_eq!(StateEntry::from_bytes(&e.to_bytes().unwrap()).unwrap(), e);
    assert_ne!(
        e.hash().unwrap(),
        StateEntry { at: 4, ..e.clone() }.hash().unwrap()
    );
    assert_eq!(CosignResponse::from_bytes(&[0xa0]), Err(WireError));
}

// K15
#[test]
fn tiles_hold_complete_subtree_hashes() {
    let l = leaves(70_000);
    assert_eq!(proof::tile_width(70_000, 0, 0), 256);
    assert_eq!(proof::tile_width(70_000, 0, 273), 112);
    assert_eq!(proof::tile_width(70_000, 0, 274), 0);
    assert_eq!(proof::tile_width(70_000, 1, 1), 17);
    assert_eq!(proof::tile_width(70_000, 2, 0), 1);
    let t0 = proof::tile(l.as_slice(), 0, 1, 3).unwrap();
    assert_eq!(t0, l[256..259].to_vec());
    let t1 = proof::tile(l.as_slice(), 1, 0, 2).unwrap();
    assert_eq!(t1[1], tree_root(&l[256..512]));
    let t2 = proof::tile(l.as_slice(), 2, 0, 1).unwrap();
    assert_eq!(t2[0], tree_root(&l[..65_536]));
    assert_eq!(
        proof::tile(l.as_slice(), 0, 0, 257),
        Err(proof::BuildError::Range)
    );
}
