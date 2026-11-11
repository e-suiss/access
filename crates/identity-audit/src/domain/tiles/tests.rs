#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test code"
)]

use suiss_ledger::merkle::Frontier;

use super::*;

fn leaf(i: u64) -> Hash {
    suiss_crypto::digest::leaf_hash(&i.to_be_bytes())
}

// OP-37, OP-158 m.3 (w)
#[test]
fn tile_paths_follow_c2sp() {
    assert_eq!(path(0, 5, None), "tile/0/005");
    assert_eq!(path(1, 1_234_067, None), "tile/1/x001/x234/067");
    assert_eq!(path(0, 1000, Some(17)), "tile/0/x001/000.p/17");
    assert_eq!(path(2, 0, Some(1)), "tile/2/000.p/1");
}

// OP-37
#[test]
fn the_tree_head_follows_from_the_partial_tiles() {
    for size in [1_u64, 255, 256, 257, 511, 65_535, 65_536, 65_537, 70_001] {
        let mut f = Frontier::default();
        let leaves: Vec<Hash> = (0..size).map(leaf).collect();
        for l in &leaves {
            f.push(*l).unwrap();
        }
        let tile0: Vec<Hash> = leaves
            .chunks(256)
            .filter(|c| c.len() == 256)
            .map(|c| tile_root(c).unwrap())
            .collect();
        let tile1: Vec<Hash> = tile0
            .chunks(256)
            .filter(|c| c.len() == 256)
            .map(|c| tile_root(c).unwrap())
            .collect();
        let w0 = (size % 256) as usize;
        let mut partials = vec![leaves[leaves.len() - w0..].to_vec()];
        if levels(size) > 1 {
            let w1 = (entries(size, 1) % 256) as usize;
            partials.push(tile0[tile0.len() - w1..].to_vec());
        }
        if levels(size) > 2 {
            let w2 = (entries(size, 2) % 256) as usize;
            partials.push(tile1[tile1.len() - w2..].to_vec());
        }
        assert_eq!(
            root_from_partials(size, &partials).unwrap(),
            f.root(),
            "{size}"
        );
    }
    assert!(root_from_partials(300, &[vec![leaf(0)], vec![leaf(1)]]).is_err());
}
