#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;

const D: Digest = Digest([4; 32]);

// T29, TI-RT5, Ek B 5785
#[test]
fn foreign_metadata_is_fresh_by_an_independent_cosign_or_for_an_hour() {
    let c = ForeignMetadata::new();
    c.verified(D, vec![1], 1_000);
    assert_eq!(c.fresh(&D, 1_000 + UNWITNESSED_MS, 500), Some(vec![1]));
    assert_eq!(c.fresh(&D, 1_001 + UNWITNESSED_MS, 500), None);
    c.cosigned(D, 2_000 + UNWITNESSED_MS, false);
    assert_eq!(
        c.fresh(&D, 2_100 + UNWITNESSED_MS, 500),
        None,
        "a pinned witness proves nothing"
    );
    c.cosigned(D, 2_000 + UNWITNESSED_MS, true);
    assert_eq!(c.fresh(&D, 2_500 + UNWITNESSED_MS, 500), Some(vec![1]));
    assert_eq!(c.fresh(&D, 2_501 + UNWITNESSED_MS, 500), None);
    assert_eq!(c.fresh(&Digest([5; 32]), 0, 500), None);
}

// T30, SI-15, Ek B 5786
#[test]
fn a_hub_snapshot_is_the_viewers_own_and_never_a_consequential_read() {
    let hub: HubCache<&str> = HubCache::default();
    let (alice, bob) = (Id([1; 16]), Id([2; 16]));
    hub.keep(
        alice,
        D,
        vec![Row {
            value: "grant",
            as_of: 7,
        }],
        100,
    );
    let rows = hub.get(&alice, &D, Read::View, 150, 60).unwrap();
    assert_eq!(rows[0].as_of, 7);
    assert!(hub.get(&bob, &D, Read::View, 150, 60).is_none());
    assert!(hub.get(&alice, &D, Read::Consequential, 150, 60).is_none());
    assert!(hub.get(&alice, &D, Read::View, 161, 60).is_none());
}

// §9.15A.5, Ek B 6149
#[test]
fn a_foreign_record_is_read_only_with_its_inclusion_proof() {
    let records: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 3]).collect();
    let leaves: Vec<&[u8]> = records.iter().map(Vec::as_slice).collect();
    let root = suiss_crypto::digest::root(&leaves);
    let leaf = |i: usize| suiss_crypto::digest::leaf_hash(&records[i]);
    let n = |a: [u8; 32], b: [u8; 32]| suiss_crypto::digest::node_hash(&a, &b);
    let path = vec![leaf(3), n(leaf(0), leaf(1)), leaf(4)];
    assert!(read_record(&records[2], 3, (5, &root), &path).is_ok());
    assert_eq!(
        read_record(&records[1], 3, (5, &root), &path),
        Err(ReadError::NotIncluded)
    );
    assert_eq!(
        read_record(&records[2], 0, (5, &root), &path),
        Err(ReadError::NotIncluded)
    );
}

// §5.13, INV-21, Ek B 6150
#[test]
fn a_target_draws_within_the_slice_and_reports_what_it_drew() {
    let mut s = Slice {
        allowance: 10,
        ..Slice::default()
    };
    assert_eq!(s.draw(4), Ok(6));
    assert_eq!(s.draw(7), Err(SliceError::Exhausted));
    assert_eq!(s.drawn, 4, "a refused draw draws nothing");
    assert_eq!(s.draw(6), Ok(0));
    assert_eq!(s.unreported(), 10);
    s.acknowledge(25);
    assert_eq!(s.acknowledged, 10, "never more than was drawn");
    assert_eq!(s.unreported(), 0);
}
