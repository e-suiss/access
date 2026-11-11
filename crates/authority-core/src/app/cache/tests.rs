#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::HashMap;

use access_kernel::combinator::{Decision, Outcome};

use super::*;

fn answer(outcome: Outcome) -> Response {
    Response {
        decision: Decision {
            outcome,
            blockers: Vec::new(),
            unmet: Vec::new(),
            relied_on: Vec::new(),
        },
        exercise: None,
        record: None,
        replayed: false,
        basis_ref: None,
        consistency: None,
        receipt: None,
        signed_receipt: None,
        pap: None,
        signed_pap: None,
        ended: Vec::new(),
        explained: None,
        causal: None,
    }
}

// P45, §9.7A.4, Ek B 6130
#[test]
fn concatenations_that_read_alike_get_different_keys() {
    type Parts<'a> = &'a [&'a [u8]];
    let pairs: [(Parts<'_>, Parts<'_>); 4] = [
        (&[b"ab", b"c"], &[b"a", b"bc"]),
        (&[b"tenant", b""], &[b"", b"tenant"]),
        (&[b"x"], &[b"x", b""]),
        (&[b"\x00\x00\x00\x00\x00\x00\x00\x01a"], &[b"a"]),
    ];
    for (a, b) in pairs {
        assert_ne!(key(a), key(b), "{a:?} / {b:?}");
    }
}

// P45, §9.7A.4, Ek B 6130
#[test]
fn two_different_part_lists_never_share_a_key() {
    let mut state = access_crypto::random::bytes::<8>().unwrap();
    let mut next = move || {
        let mut v = u64::from_le_bytes(state);
        v ^= v << 13;
        v ^= v >> 7;
        v ^= v << 17;
        state = v.to_le_bytes();
        v
    };
    let mut seen: HashMap<Key, Vec<Vec<u8>>> = HashMap::new();
    for _ in 0..20_000 {
        let parts: Vec<Vec<u8>> = (0..next() % 5)
            .map(|_| {
                (0..next() % 4)
                    .map(|_| u8::try_from(next() % 3).unwrap())
                    .collect()
            })
            .collect();
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let k = key(&refs);
        if let Some(before) = seen.get(&k) {
            assert_eq!(before, &parts, "one key for two part lists");
        }
        seen.insert(k, parts);
    }
}

// U61, §9.7A.4, Ek B 6125
#[test]
fn allow_lives_ten_seconds_and_everything_else_one() {
    let c = AdvisoryCache::new();
    let (yes, no) = (key(&[b"allow"]), key(&[b"deny"]));
    c.put(yes, 7, 1_000, u64::MAX, &answer(Outcome::Allow));
    c.put(no, 7, 1_000, u64::MAX, &answer(Outcome::Deny));
    assert!(c.get(&yes, 1_000 + POSITIVE_TTL_MS - 1).is_some());
    assert!(c.get(&yes, 1_000 + POSITIVE_TTL_MS).is_none());
    assert!(c.get(&no, 1_000 + NEGATIVE_TTL_MS - 1).is_some());
    assert!(c.get(&no, 1_000 + NEGATIVE_TTL_MS).is_none());
    const { assert!(NEGATIVE_TTL_MS <= 1_000 && POSITIVE_TTL_MS == 10_000) };
}

// U61, §9.7A.4
#[test]
fn nothing_outlives_the_intent_validity() {
    let c = AdvisoryCache::new();
    let k = key(&[b"short"]);
    c.put(k, 1, 1_000, 1_500, &answer(Outcome::Allow));
    assert!(c.get(&k, 1_500).is_some());
    assert!(c.get(&k, 1_501).is_none());
    let late = key(&[b"late"]);
    c.put(late, 1, 2_000, 1_500, &answer(Outcome::Allow));
    assert!(c.get(&late, 2_000).is_none());
}

// MD-7, U61
#[test]
fn unseen_keys_miss_and_a_commit_drops_older_positions() {
    let c = AdvisoryCache::new();
    assert!(c.get(&key(&[b"never"]), 0).is_none());
    let k = key(&[b"at-3"]);
    c.put(k, 3, 0, u64::MAX, &answer(Outcome::Allow));
    c.advance(4);
    assert!(c.get(&k, 1).is_none());
    assert_eq!(
        c.counts(),
        Counts {
            lookups: 2,
            hits: 0,
            stored: 1
        }
    );
}
