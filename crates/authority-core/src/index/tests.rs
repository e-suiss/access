#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;

fn with(class: &str, n: u8, base: u8) -> Pending {
    let mut p = Pending::default();
    p.members
        .entry(String::from(class))
        .or_default()
        .extend((0..n).map(|i| {
            let mut party = [i; 16];
            party[0] = base;
            party
        }));
    p
}

// §9.7A.5, OP-158 m.3 (u), Ek B 6133
#[test]
fn ingest_batches_stay_within_the_tuple_quota() {
    let records: Vec<(u64, Pending)> = (1..=40u64)
        .map(|pos| {
            (
                pos,
                with(&format!("c{}", pos % 3), 90, u8::try_from(pos).unwrap()),
            )
        })
        .collect();
    let out = batches(records);
    assert!(out.len() > 1);
    let mut last = 0;
    for (pos, b) in &out {
        assert!(b.tuples() <= quota::TUPLES_PER_WRITE, "{}", b.tuples());
        assert!(*pos > last);
        last = *pos;
    }
    assert_eq!(last, 40);
}

// §9.7A.5
#[test]
fn a_record_past_the_quota_is_its_own_batch() {
    let mut bigger = with("all", 255, 0);
    for c in ["b", "c", "d"] {
        bigger.merge(with(c, 255, 0));
    }
    let out = batches(vec![
        (1, with("a", 3, 1)),
        (2, bigger),
        (3, with("a", 3, 2)),
    ]);
    let sizes: Vec<usize> = out.iter().map(|(_, b)| b.tuples()).collect();
    assert_eq!(sizes, vec![3, 1_020, 3]);
}

// §9.7A.1, OP-141 m.20 (b)
#[test]
fn only_a_set_membership_key_adds_a_member() {
    let subject = Id([9; 16]);
    let claim = Id([3; 16]);
    let key = |kind: &str| {
        vec![
            Value::text(kind),
            Value::text("staff"),
            subject.to_value(),
            claim.to_value(),
        ]
    };
    let mut p = Pending::default();
    assert!(!p.member(&key("grant"), Some(&claim.to_value())));
    assert!(p.member(&key(access_kernel::claim::MEMBER), None));
    assert!(p.is_empty());
    assert!(p.member(&key(access_kernel::claim::MEMBER), Some(&claim.to_value())));
    assert_eq!(p.members["staff"], BTreeSet::from([subject.0]));
}

// P46
#[test]
fn the_quotas_are_the_spec_values() {
    assert_eq!(quota::DEPTH, 25);
    assert_eq!(quota::WIDTH, 10);
    assert_eq!(quota::CHECK.as_millis(), 100);
    assert_eq!(quota::SEARCH.as_millis(), 1_000);
    assert_eq!(quota::SEARCH_RESULTS, 1_000);
    assert_eq!(quota::TUPLES_PER_WRITE, 1_000);
    assert_eq!(quota::TYPES_PER_STORE, 200);
}
