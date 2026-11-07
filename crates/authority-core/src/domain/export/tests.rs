#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;

use access_kernel::record::{Header, Opened};

use super::*;

const D: Digest = Digest([0xd0; 32]);
const EXPORT: Digest = Digest([0xee; 32]);

fn field(v: Value, salt: u8) -> Opened {
    Opened {
        value: v,
        salt: [salt; 32],
    }
}

/// A synthetic log of `n` records: Genesis, then decisions and a Claim, chained.
fn log(n: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut prev: Option<Digest> = None;
    for pos in 0..n {
        let kind = match pos {
            0 => RecordKind::Genesis,
            3 => RecordKind::Claim,
            _ => RecordKind::Decision,
        };
        let mut fields = BTreeMap::from([
            (
                "body".to_owned(),
                field(Value::text(&format!("secret-{pos}")), 1),
            ),
            (
                "versions".to_owned(),
                field(
                    Value::Map(vec![
                        (Value::text("core"), Value::Unsigned(1)),
                        (Value::text("meta_schema"), Value::Unsigned(1)),
                    ]),
                    2,
                ),
            ),
        ]);
        if kind == RecordKind::Claim {
            fields.insert("claim".to_owned(), field(Digest([0xc1; 32]).to_value(), 3));
        }
        let r = RecordEnvelope {
            header: Header {
                domain: (pos > 0).then_some(D),
                pos,
                kind,
                recorded_at: 1_000 + pos,
                prev,
            },
            fields,
        };
        prev = Some(Digest(r.leaf_hash().unwrap()));
        out.push(r.to_bytes().unwrap());
    }
    out
}

fn root_of(log: &[Vec<u8>], size: usize) -> Hash {
    let mut f = Frontier::default();
    for b in &log[..size] {
        f.push(RecordEnvelope::from_bytes(b).unwrap().leaf_hash().unwrap())
            .unwrap();
    }
    f.root()
}

// AP-14, INV-27, PI-6: a package re-folds to the log's root from its own content, for a range
// inside the log and for one from Genesis, and its bytes round-trip deterministically
#[test]
fn ap_14_inv_27_a_package_refolds_its_checkpoint_root() {
    let l = log(8);
    for (from, to) in [(2, 5), (0, 7), (7, 7)] {
        let p = build(D, &l, (from, to), Coverage::Digest, EXPORT).unwrap();
        let v = verify(&p).unwrap();
        assert_eq!(v.root, root_of(&l, usize::try_from(to + 1).unwrap()));
        assert_eq!(v.size, to + 1);
        assert!(!v.folded);
        let bytes = p.to_bytes().unwrap();
        let again = Package::from_bytes(&bytes).unwrap();
        assert_eq!(again, p);
        assert_eq!(again.to_bytes().unwrap(), bytes);
        assert_eq!(p.export_exercise, EXPORT);
    }
}

// AP-14, §9.16: a redacted package opens nothing but the version vectors and declares
// digest-level replay; a full one opens every field
#[test]
fn ap_14_redacted_records_are_digests_and_declared() {
    let l = log(6);
    let redacted = build(D, &l, (1, 5), Coverage::Digest, EXPORT).unwrap();
    assert_eq!(redacted.replay_coverage.word(), "digest");
    for r in &redacted.records {
        assert!(r.withheld.contains_key("body"));
        assert!(r.opened.keys().all(|k| k == "versions"));
    }
    let bytes = redacted.to_bytes().unwrap();
    assert!(!bytes.windows(8).any(|w| w == b"secret-2"));
    assert_eq!(redacted.versions.len(), 1);
    assert_eq!(
        redacted.claims,
        vec![Digest(redacted.records[2].leaf_hash().unwrap())]
    );
    let full = build(D, &l, (1, 5), Coverage::Full, EXPORT).unwrap();
    assert_eq!(full.replay_coverage.word(), "full");
    assert!(full.records.iter().all(|r| r.withheld.is_empty()));
    assert_eq!(full.claims, vec![Digest([0xc1; 32])]);
    assert_eq!(verify(&full).unwrap().root, verify(&redacted).unwrap().root);
}

// INV-27, G32: any change to a package is caught by re-folding it
#[test]
fn inv_27_a_changed_package_does_not_verify() {
    let l = log(6);
    let p = build(D, &l, (1, 4), Coverage::Full, EXPORT).unwrap();
    let mut body = p.clone();
    body.records[1]
        .opened
        .insert("body".to_owned(), field(Value::text("other"), 1));
    assert_eq!(verify(&body), Err(ExportError::Chain));
    let mut last = p.clone();
    last.records[3]
        .opened
        .insert("body".to_owned(), field(Value::text("other"), 1));
    assert_eq!(verify(&last), Err(ExportError::Root));
    let mut dropped = p.clone();
    dropped.records.remove(1);
    assert_eq!(verify(&dropped), Err(ExportError::Range));
    let mut swapped = p.clone();
    swapped.records.swap(1, 2);
    assert_eq!(verify(&swapped), Err(ExportError::Chain));
    let mut prefix = p.clone();
    prefix.prefix[0] = [0; 32];
    assert_eq!(verify(&prefix), Err(ExportError::Root));
    let mut domain = p;
    domain.domain = Digest([1; 32]);
    assert_eq!(verify(&domain), Err(ExportError::Chain));
}

// AP-14: a range outside the log, reversed or over the ceiling is refused; trailing bytes are not
// a package
#[test]
fn ap_14_ranges_and_bytes_are_checked() {
    let l = log(4);
    assert_eq!(
        build(D, &l, (2, 4), Coverage::Digest, EXPORT).err(),
        Some(ExportError::Range)
    );
    assert_eq!(
        build(D, &l, (3, 2), Coverage::Digest, EXPORT).err(),
        Some(ExportError::Range)
    );
    let mut bytes = build(D, &l, (0, 3), Coverage::Digest, EXPORT)
        .unwrap()
        .to_bytes()
        .unwrap();
    bytes.push(0);
    assert!(Package::from_bytes(&bytes).is_err());
}
