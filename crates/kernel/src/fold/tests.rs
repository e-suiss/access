extern crate std;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;
use crate::codec::Canonical;

#[derive(serde::Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    id: String,
    records: Vec<String>,
    state: Option<Vec<(String, Option<String>, u64)>>,
    rejection: Option<String>,
}

fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    use core::fmt::Write as _;
    b.iter().fold(String::new(), |mut h, x| {
        let _ = write!(h, "{x:02x}");
        h
    })
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!(
        "../../../../conformance/vectors/core/1/record-fold.json"
    ))
    .unwrap()
}

fn records(c: &Case) -> Vec<RecordEnvelope> {
    c.records
        .iter()
        .map(|r| RecordEnvelope::from_bytes(&bytes(r)).unwrap())
        .collect()
}

fn triples(state: &State) -> Vec<(String, Option<String>, u64)> {
    state
        .iter()
        .map(|(k, e)| {
            let v = e.value.as_ref().map(|v| {
                hex(&suiss_crypto::dcbor::encode(v, suiss_crypto::dcbor::Limits::CEILING).unwrap())
            });
            (hex(k), v, e.version)
        })
        .collect()
}

// L2-REC-2, L2-REC-3
#[test]
fn fold_matches_vectors() {
    let v = vectors();
    assert!(v.cases.len() >= 20);
    for c in &v.cases {
        let got = fold(&records(c));
        match (&c.state, &c.rejection) {
            (Some(want), None) => assert_eq!(&triples(&got.unwrap()), want, "{}", c.id),
            (None, Some(want)) => assert_eq!(got.unwrap_err().to_string(), *want, "{}", c.id),
            _ => panic!("{}: needs state or rejection", c.id),
        }
    }
}

// L2-REC-3, TI-16: applying records one by one gives the fold of every prefix
#[test]
fn apply_is_the_incremental_fold() {
    for c in vectors().cases.iter().filter(|c| c.state.is_some()) {
        let recs = records(c);
        let mut state = State::new();
        for (n, r) in recs.iter().enumerate() {
            apply(&mut state, r).unwrap();
            assert_eq!(state, fold(&recs[..=n]).unwrap(), "{} at {n}", c.id);
        }
    }
}

// L2-REC-2: a rejected record leaves the state as it was
#[test]
fn a_rejected_record_changes_nothing() {
    let v = vectors();
    let good = records(
        v.cases
            .iter()
            .find(|c| c.id == "set-overwrite-remove")
            .unwrap(),
    );
    let bad = records(v.cases.iter().find(|c| c.id == "duplicate-key").unwrap());
    let mut state = fold(&good[..1]).unwrap();
    let before = state.clone();
    assert_eq!(apply(&mut state, &bad[0]), Err(FoldError::Duplicate));
    assert_eq!(state, before);
}
