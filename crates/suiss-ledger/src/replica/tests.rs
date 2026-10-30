use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::digest::{leaf_hash, node_hash, root};

use super::*;

fn cp(size: u64, root: Hash) -> Checkpoint {
    Checkpoint {
        origin: String::from("example.com/log"),
        size,
        root,
        extensions: Vec::new(),
    }
}

// T21, TI-13: the replica accepts only what its own copy of the leaves proves
#[test]
fn the_replica_checks_size_root_and_consistency() {
    let data: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];
    let mut f = Follower::new("example.com/log");
    for d in &data[..3] {
        f.append(leaf_hash(d)).unwrap();
    }
    assert_eq!(f.accept(&cp(4, root(&data)), &[]), Err(ReplicaError::Size));
    assert_eq!(f.accept(&cp(3, [0; 32]), &[]), Err(ReplicaError::Root));
    let mut other = cp(3, root(&data[..3]));
    other.origin = String::from("other.example/log");
    assert_eq!(f.accept(&other, &[]), Err(ReplicaError::Origin));
    f.accept(&cp(3, root(&data[..3])), &[]).unwrap();
    f.append(leaf_hash(data[3])).unwrap();
    // RFC 9162 §2.1.4 proof from 3 to 4: [c, ab, d] reduced to the nodes the verifier needs
    let proof = [
        leaf_hash(data[2]),
        leaf_hash(data[3]),
        node_hash(&leaf_hash(data[0]), &leaf_hash(data[1])),
    ];
    assert!(matches!(
        f.accept(&cp(4, root(&data)), &proof[..1]),
        Err(ReplicaError::Inconsistent(_))
    ));
    f.accept(&cp(4, root(&data)), &proof).unwrap();
    assert_eq!(f.accepted(), Some((4, root(&data))));
}
