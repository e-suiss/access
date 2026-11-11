//! The divergence set's wire form, its signature and the sampler (OP-158 m.3 (h), (i),
//! recovery.cddl). Replay over real records runs on the real server path in `access-server`'s
//! durability tests.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::hash::{BuildHasher as _, Hasher as _};

use access_kernel::digest::Digest;
use access_kernel::record::{Disclosure, Header, RecordKind};
use access_verifier::replay::{
    DivergenceSet, Item, Kind, Reason, Replay, ReplayError, SignedSet, Word, sampled,
};
use suiss_crypto::sig::PureBackend;

fn example() -> DivergenceSet {
    DivergenceSet {
        domain: Digest([0x0a; 32]),
        range: (0, 9),
        items: vec![Item {
            position: 4,
            exercise: Digest([0x0b; 32]),
            kind: Kind::ReEvaluation,
            recorded: Word::Allow,
            replayed: Word::Deny,
            reason: Reason::Basis,
        }],
        evaluator: String::from("f0-python"),
        at: 1_767_225_000_000,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}")).unwrap();
        s
    })
}

fn runtime_seed() -> [u8; 32] {
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        );
        chunk.copy_from_slice(&h.finish().to_be_bytes());
    }
    out
}

// INV-27, PI-6, OP-158 m.3 (h)
#[test]
fn the_set_is_the_cddl_example_and_reads_back() {
    let text = include_str!("../../../../conformance/cddl/examples/divergence.json");
    let v: serde_json::Value = serde_json::from_str(text).unwrap();
    let cbor = v["cases"][0]["cbor"].as_str().unwrap();
    let set = example();
    let bytes = set.to_bytes().unwrap();
    assert_eq!(hex(&bytes), cbor);
    let value = suiss_crypto::dcbor::decode(&bytes, suiss_crypto::dcbor::Limits::CEILING).unwrap();
    assert_eq!(DivergenceSet::from_value(&value).unwrap(), set);
    let mut empty = set;
    empty.items.clear();
    assert_eq!(
        DivergenceSet::from_value(&empty.to_value()),
        Err(ReplayError::Set)
    );
}

// G32, U13, OP-158 m.3 (h)
#[test]
fn a_signed_set_verifies_under_its_key_and_a_changed_one_does_not() {
    let key = ed25519_dalek::SigningKey::from_bytes(&runtime_seed());
    let set = example();
    let sig = ed25519_dalek::Signer::sign(&key, &set.to_bytes().unwrap()).to_bytes();
    let signed = SignedSet {
        set,
        key: key.verifying_key().to_bytes(),
        sig,
    };
    let bytes = signed.to_bytes().unwrap();
    assert_eq!(SignedSet::verify(&PureBackend, &bytes).unwrap(), signed);
    let mut other = signed.clone();
    other.set.items[0].replayed = Word::Allow;
    assert_eq!(
        SignedSet::verify(&PureBackend, &other.to_bytes().unwrap()),
        Err(ReplayError::Set)
    );
}

// OP-158 m.3 (h)
#[test]
fn the_ct2_sample_is_one_in_a_hundred() {
    let mut hits = 0u32;
    for i in 0u32..20_000 {
        let d = suiss_crypto::digest::sha256(&i.to_be_bytes());
        hits += u32::from(sampled(&d));
    }
    assert!((100..=300).contains(&hits), "{hits}");
}

fn bare(pos: u64) -> Disclosure {
    Disclosure {
        header: Header {
            domain: Some(Digest([0x0a; 32])),
            pos,
            kind: RecordKind::Opening,
            recorded_at: 1,
            prev: None,
        },
        opened: std::collections::BTreeMap::new(),
        withheld: std::collections::BTreeMap::from([(String::from("nonce"), [1; 32])]),
    }
}

// TI-RT4, T19
#[test]
fn a_range_not_from_genesis_is_digest_coverage_and_must_follow_in_order() {
    let mut r = Replay::new();
    r.push(&bare(5), true).unwrap();
    r.push(&bare(6), true).unwrap();
    assert_eq!(r.push(&bare(8), true), Err(ReplayError::Order));
    let c = r.coverage();
    assert_eq!((c.records, c.digest_only, c.reevaluated), (2, 2, 0));
    assert!(r.state().is_none() && r.items().is_empty());
    assert!(r.set((5, 6), "x", 1).is_none());
}
