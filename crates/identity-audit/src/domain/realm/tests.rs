#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use suiss_ledger::merkle::Frontier;

use super::*;

fn leaves(n: u8) -> Vec<Hash> {
    (0..n).map(|i| [i; 32]).collect()
}

// OP-152 m.7 (d), RFC 9162 §2.1.3
#[test]
fn every_leaf_has_a_path_to_the_frontiers_root() {
    for n in 1..=33_u8 {
        let all = leaves(n);
        let mut frontier = Frontier::default();
        for l in &all {
            frontier.push(*l).unwrap();
        }
        assert_eq!(tree_hash(&all), frontier.root(), "size {n}");
        for (i, l) in all.iter().enumerate() {
            let path = inclusion_path(&all, i).unwrap();
            verify_inclusion(i as u64, u64::from(n), l, &path, &frontier.root()).unwrap();
            if n > 1 {
                assert!(
                    verify_inclusion(i as u64, u64::from(n), &[0xee; 32], &path, &frontier.root())
                        .is_err()
                );
            }
        }
        assert_eq!(inclusion_path(&all, usize::from(n)), None);
    }
}
