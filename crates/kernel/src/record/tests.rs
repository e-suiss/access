extern crate std;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::codec::Canonical;

#[derive(serde::Deserialize)]
struct Vectors {
    log: Log,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Log {
    size: u64,
    root: String,
}

#[derive(serde::Deserialize)]
struct Case {
    id: String,
    cbor: Option<String>,
    data: Option<String>,
    record_disclosure: Option<String>,
    commitments: Option<BTreeMap<String, String>>,
    field_root: Option<String>,
    leaf_core: Option<String>,
    leaf_hash: Option<String>,
    domain: Option<String>,
    size: Option<u64>,
    root: Option<String>,
    path: Option<Vec<String>>,
    error: Option<String>,
}

fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn hash(s: &str) -> Hash {
    Hash::try_from(bytes(s).as_slice()).unwrap()
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!(
        "../../../../conformance/vectors/core/1/record.json"
    ))
    .unwrap()
}

fn reason(e: ModelError) -> &'static str {
    match e {
        ModelError::Cbor(_) => "cbor",
        ModelError::Shape => "shape",
        ModelError::Missing => "missing",
        ModelError::Unknown => "unknown",
        ModelError::SetOrder => "set-order",
        ModelError::Range => "range",
    }
}

fn envelopes(v: &Vectors) -> Vec<RecordEnvelope> {
    v.cases
        .iter()
        .filter(|c| c.leaf_core.is_some())
        .map(|c| RecordEnvelope::from_bytes(&bytes(c.cbor.as_deref().unwrap())).unwrap())
        .collect()
}

// OP-106 m.10–m.15, §17.6.1
#[test]
fn envelopes_match_vectors() {
    let v = vectors();
    let mut checked = 0;
    for case in v.cases.iter().filter(|c| c.leaf_core.is_some()) {
        let cbor = bytes(case.cbor.as_deref().unwrap());
        let env = RecordEnvelope::from_bytes(&cbor).unwrap();
        assert_eq!(env.to_bytes().unwrap(), cbor, "{}", case.id);
        let commitments: BTreeMap<String, String> = env
            .commitments()
            .unwrap()
            .into_iter()
            .map(|(n, c)| (n, hex(&c)))
            .collect();
        assert_eq!(Some(&commitments), case.commitments.as_ref(), "{}", case.id);
        let core = env.leaf_core().unwrap();
        assert_eq!(hex(&core.field_root), *case.field_root.as_ref().unwrap());
        let core_bytes = bytes(case.leaf_core.as_deref().unwrap());
        assert_eq!(core.to_bytes().unwrap(), core_bytes, "{}", case.id);
        assert_eq!(LeafCore::from_bytes(&core_bytes).unwrap(), core);
        assert_eq!(
            env.leaf_hash().unwrap(),
            hash(case.leaf_hash.as_deref().unwrap())
        );
        assert_eq!(
            env.domain().unwrap().to_value(),
            suiss_crypto::dcbor::decode(
                &bytes(case.domain.as_deref().unwrap()),
                suiss_crypto::dcbor::Limits::CEILING
            )
            .unwrap()
        );
        checked += 1;
    }
    assert_eq!(checked, 4);
}

// OP-106 m.13: commitments are ordered by UTF-8 name bytes, not by CBOR map order
#[test]
fn field_root_orders_names_by_utf8_bytes() {
    let v = vectors();
    let env = &envelopes(&v)[1];
    let c = env.commitments().unwrap();
    let ab = c["ab"];
    let z = c["z"];
    assert_eq!(
        env.leaf_core().unwrap().field_root,
        digest::root(&[&ab[..], &z[..]])
    );
    assert_ne!(
        env.leaf_core().unwrap().field_root,
        digest::root(&[&z[..], &ab[..]])
    );
}

// OP-117 m.2
#[test]
fn domain_id_is_the_genesis_digest() {
    let v = vectors();
    let records = envelopes(&v);
    let genesis = &records[0];
    let id = digest::domain_id(&genesis.to_bytes().unwrap());
    assert_eq!(genesis.domain().unwrap(), id);
    for r in &records[1..] {
        assert_eq!(r.header.domain, Some(id));
    }
}

// §17.6.1 rule 1, rule 5; TI-11
#[test]
fn disclosures_match_vectors_and_prove_inclusion() {
    let v = vectors();
    let root = hash(&v.log.root);
    let mut checked = 0;
    for case in v.cases.iter().filter(|c| c.error.is_none()) {
        let Some(d) = &case.record_disclosure else {
            continue;
        };
        let raw = bytes(d);
        let disclosure = Disclosure::from_bytes(&raw).unwrap();
        assert_eq!(disclosure.to_bytes().unwrap(), raw, "{}", case.id);
        assert_eq!(
            disclosure.leaf_hash().unwrap(),
            hash(case.leaf_hash.as_deref().unwrap()),
            "{}",
            case.id
        );
        assert_eq!(hash(case.root.as_deref().unwrap()), root);
        assert_eq!(case.size, Some(v.log.size));
        let path: Vec<Hash> = case
            .path
            .as_ref()
            .unwrap()
            .iter()
            .map(|p| hash(p))
            .collect();
        assert_eq!(
            disclosure.verify_inclusion(v.log.size, &path, &root),
            Ok(())
        );
        checked += 1;
    }
    assert_eq!(checked, 3);
}

#[test]
fn rejections_match_vectors() {
    let v = vectors();
    let mut checked = 0;
    for case in &v.cases {
        let Some(want) = &case.error else {
            continue;
        };
        let got = match (&case.cbor, &case.data, &case.record_disclosure) {
            (Some(c), None, None) | (None, Some(c), None) => {
                RecordEnvelope::from_bytes(&bytes(c)).map(|_| ())
            }
            (None, None, Some(d)) => Disclosure::from_bytes(&bytes(d)).map(|_| ()),
            _ => panic!("{}", case.id),
        };
        assert_eq!(got.map_err(reason), Err(want.as_str()), "{}", case.id);
        checked += 1;
    }
    assert_eq!(checked, 20);
}

// OP-108 m.4: an unknown kind in a stored record is not understood, not an error
#[test]
fn unknown_kind_in_stored_record_is_not_understood() {
    let v = vectors();
    let case = v.cases.iter().find(|c| c.id == "kind-unknown").unwrap();
    assert_eq!(
        crate::codec::decode_stored::<RecordEnvelope>(&bytes(case.cbor.as_deref().unwrap())),
        Ok(crate::codec::Stored::NotUnderstood)
    );
}

// §17.6.1 rule 1
#[test]
fn withholding_or_redacting_keeps_the_leaf() {
    let v = vectors();
    let decision = &envelopes(&v)[2];
    let leaf = decision.leaf_hash().unwrap();
    let names: Vec<&String> = decision.fields.keys().collect();
    for mask in 0..(1_u32 << names.len()) {
        let open = |n: &str| {
            names
                .iter()
                .position(|m| *m == n)
                .is_some_and(|i| mask & (1 << i) != 0)
        };
        let d = decision.disclose(open).unwrap();
        assert_eq!(d.leaf_hash().unwrap(), leaf);
        let back = Disclosure::from_bytes(&d.to_bytes().unwrap()).unwrap();
        assert_eq!(back, d);
    }
}

// §17.6.1 rule 1: an opened field is recomputed, so a changed value or salt changes the leaf
#[test]
fn tampered_disclosure_does_not_verify() {
    let v = vectors();
    let decision = &envelopes(&v)[2];
    let leaf = decision.leaf_hash().unwrap();
    let mut d = decision.disclose(|n| n == "artifacts").unwrap();
    d.opened.get_mut("artifacts").unwrap().value = Value::Array(vec![]);
    assert_ne!(d.leaf_hash().unwrap(), leaf);

    let mut d = decision.disclose(|n| n == "artifacts").unwrap();
    d.opened.get_mut("artifacts").unwrap().salt[0] ^= 1;
    assert_ne!(d.leaf_hash().unwrap(), leaf);

    let mut d = decision.disclose(|n| n == "artifacts").unwrap();
    d.withheld.get_mut("basis").unwrap()[0] ^= 1;
    assert_ne!(d.leaf_hash().unwrap(), leaf);

    let mut d = decision.disclose(|_| false).unwrap();
    let c = d.withheld.remove("outcome").unwrap();
    d.withheld.insert("aaa".to_string(), c);
    assert_ne!(d.leaf_hash().unwrap(), leaf);

    let root = hash(&v.log.root);
    let case = v
        .cases
        .iter()
        .find(|c| c.id == "decision-artifacts-only")
        .unwrap();
    let path: Vec<Hash> = case
        .path
        .as_ref()
        .unwrap()
        .iter()
        .map(|p| hash(p))
        .collect();
    let mut d = decision.disclose(|n| n == "artifacts").unwrap();
    d.header.recorded_at = d.header.recorded_at.checked_add(1).unwrap();
    assert_eq!(
        d.verify_inclusion(v.log.size, &path, &root),
        Err(RecordError::Proof(ProofError::Mismatch))
    );
}

// §17.6.1 rule 1: a withheld field's name only orders its commitment; it is not authenticated
#[test]
fn withheld_names_are_only_ordering_hints() {
    let v = vectors();
    let decision = &envelopes(&v)[2];
    let mut d = decision.disclose(|_| false).unwrap();
    let c = d.withheld.remove("outcome").unwrap();
    d.withheld.insert("outcomes".to_string(), c);
    assert_eq!(d.leaf_hash().unwrap(), decision.leaf_hash().unwrap());
}

// OP-106 m.11, TI-19
#[test]
fn records_link_into_a_hash_chain() {
    let v = vectors();
    let records = envelopes(&v);
    let domain = records[0].domain().unwrap();
    let cores: Vec<LeafCore> = records.iter().map(|r| r.leaf_core().unwrap()).collect();
    for pair in cores.windows(2) {
        assert_eq!(check_link(&pair[0], &pair[1], &domain), Ok(()));
    }
    let leaves: Vec<Vec<u8>> = cores.iter().map(|c| c.to_bytes().unwrap()).collect();
    let refs: Vec<&[u8]> = leaves.iter().map(Vec::as_slice).collect();
    assert_eq!(digest::root(&refs), hash(&v.log.root));

    let (a, b) = (&cores[1], &cores[2]);
    assert_eq!(check_link(b, a, &domain), Err(LinkError::Position));
    assert_eq!(check_link(&cores[0], b, &domain), Err(LinkError::Position));
    let mut c = b.clone();
    c.header.prev = cores[0].header.prev;
    assert_eq!(check_link(a, &c, &domain), Err(LinkError::Prev));
    let mut c = b.clone();
    c.header.recorded_at = 0;
    assert_eq!(check_link(a, &c, &domain), Err(LinkError::Time));
    assert_eq!(check_link(a, b, &Digest([0; 32])), Err(LinkError::Domain));
}

#[test]
fn envelope_and_leaf_core_round_trip_in_memory() {
    let mut fields = BTreeMap::new();
    fields.insert(
        "outcome".to_string(),
        Opened {
            value: Value::text("deny"),
            salt: [7; 32],
        },
    );
    let env = RecordEnvelope {
        header: Header {
            domain: Some(Digest([1; 32])),
            pos: 9,
            kind: RecordKind::Decision,
            recorded_at: 5,
            prev: Some(Digest([2; 32])),
        },
        fields,
    };
    let back = RecordEnvelope::from_bytes(&env.to_bytes().unwrap()).unwrap();
    assert_eq!(back, env);
    let core = env.leaf_core().unwrap();
    assert_eq!(
        LeafCore::from_bytes(&core.to_bytes().unwrap()).unwrap(),
        core
    );
    let only = field_commitment("outcome", &env.fields["outcome"]).unwrap();
    assert_eq!(core.field_root, digest::leaf_hash(&only));
}

fn hex(b: &[u8]) -> String {
    use core::fmt::Write as _;
    b.iter().fold(String::new(), |mut h, x| {
        let _ = write!(h, "{x:02x}");
        h
    })
}
