use alloc::vec::Vec;

use proptest::prelude::*;
use sha2::{Digest as _, Sha256};

use super::{Frontier, FrontierError, node_hash};
use crate::Hash;

fn naive(leaves: &[Hash]) -> Hash {
    match leaves {
        [] => Sha256::digest([]).into(),
        [one] => *one,
        _ => {
            let mut k = 1_usize;
            while let Some(next) = k.checked_mul(2) {
                if next >= leaves.len() {
                    break;
                }
                k = next;
            }
            let (l, r) = leaves.split_at(k);
            node_hash(&naive(l), &naive(r))
        }
    }
}

proptest! {
    #[test]
    fn root_matches_rfc_9162(leaves in proptest::collection::vec(any::<[u8; 32]>(), 0..80)) {
        let mut f = Frontier::default();
        for (i, leaf) in leaves.iter().enumerate() {
            prop_assert_eq!(f.root(), naive(&leaves[..i]));
            f.push(*leaf).unwrap();
        }
        prop_assert_eq!(f.root(), naive(&leaves));
        prop_assert_eq!(f.nodes().len(), leaves.len().count_ones() as usize);
    }
}

#[test]
fn parts_must_match_size() {
    assert_eq!(
        Frontier::from_parts(3, Vec::from([[0; 32]])),
        Err(FrontierError)
    );
    assert!(Frontier::from_parts(3, Vec::from([[0; 32], [1; 32]])).is_ok());
}
