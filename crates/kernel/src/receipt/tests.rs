#![allow(clippy::arithmetic_side_effects, reason = "test fixtures")]

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

use super::*;
use crate::vector_rules::{field, golden, hex};
use crate::verify::PureBackend;
use crate::verify::cose::{Algorithm, PublicKey, to_be_signed};
use crate::verify::key_scope::{
    BindingKey, BindingScope, EXCERPT_CONTENT_TYPE, KeyExcerpt, OperationalKey, SpecVersions,
    thumbprint,
};

const HOUR: u64 = 3_600_000;

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

fn ed(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn ed_pub(seed: u8) -> PublicKey {
    PublicKey::Ed25519(ed(seed).verifying_key().to_bytes())
}

fn sign1(seed: u8, content_type: &str, payload: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    let kid = thumbprint(&ed_pub(seed));
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(1), Value::int(Algorithm::Ed25519.cose())),
            (Value::Unsigned(3), Value::text(content_type)),
            (Value::Unsigned(4), Value::Bytes(kid.to_vec())),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let sig = ed(seed)
        .sign(&to_be_signed(&prot, payload).unwrap())
        .to_bytes()
        .to_vec();
    let body = Value::Array(vec![
        Value::Bytes(prot),
        Value::Map(vec![]),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig),
    ]);
    [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
}

fn op_key(usage: KeyUsage) -> OperationalKey {
    let key = ed_pub(2);
    OperationalKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        valid_from: 10 * HOUR,
        valid_until: 11 * HOUR,
        usage: BTreeSet::from([usage]),
    }
}

fn metadata() -> DomainMetadata {
    let key = ed_pub(1);
    let b = BindingKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        scope: BindingScope::Domain,
        superseded: None,
    };
    DomainMetadata {
        domain: d(1),
        genesis: d(9),
        issued_at: 10 * HOUR,
        binding: BTreeMap::from([(b.kid, b)]),
        algorithms: BTreeSet::from([Algorithm::Ed25519]),
        operational_window_max_ms: HOUR,
        operational_keys: vec![op_key(KeyUsage::Receipt)],
        min_versions: SpecVersions::default(),
        adopted: SpecVersions::default(),
        caps: None,
        hybrid: None,
        discovery: None,
        declared: crate::verify::key_scope::Declarations::default(),
    }
}

fn excerpt(usage: KeyUsage) -> Vec<u8> {
    let e = KeyExcerpt {
        domain: d(1),
        key: op_key(usage),
    };
    sign1(1, EXCERPT_CONTENT_TYPE, &e.to_bytes().unwrap())
}

fn receipt() -> Receipt {
    Receipt {
        domain: d(1),
        exercise: d(3),
        record: 5,
        intent: d(4),
        instance: Some(Id([6; 16])),
        ais: Some(d(5)),
        capacity: Capacity::Own,
        basis: ExerciseBasis::Anchor(Id([7; 16])),
        audience: "pep.example".to_string(),
        iat: 10 * HOUR + HOUR / 2,
        drawn: false,
        agency: Vec::new(),
    }
}

fn delegated() -> Receipt {
    Receipt {
        capacity: Capacity::For(Id([8; 16])),
        agency: vec![
            AgencyLink {
                mandate: Id([10; 16]),
                principal: Id([8; 16]),
                agent: Id([11; 16]),
            },
            AgencyLink {
                mandate: Id([12; 16]),
                principal: Id([11; 16]),
                agent: Id([13; 16]),
            },
        ],
        ..receipt()
    }
}

struct Case {
    excerpt: Vec<u8>,
    receipt: Vec<u8>,
    domain: Digest,
    audience: &'static str,
    intent: Digest,
    now: u64,
}

impl Case {
    fn of(r: &Receipt) -> Self {
        Self {
            excerpt: excerpt(KeyUsage::Receipt),
            receipt: sign1(2, CONTENT_TYPE, &r.to_bytes().unwrap()),
            domain: d(1),
            audience: "pep.example",
            intent: d(4),
            now: r.iat,
        }
    }

    fn run(&self) -> Result<Receipt, ReceiptError> {
        verify(
            &PureBackend,
            &metadata(),
            &self.receipt,
            &self.excerpt,
            &Expected {
                domain: &self.domain,
                audience: self.audience,
                intent: &self.intent,
                now: self.now,
            },
        )
    }
}

fn cases() -> Vec<(&'static str, Case)> {
    let mut out = vec![("valid", Case::of(&receipt()))];
    let anonymous = Receipt {
        instance: None,
        ais: None,
        drawn: true,
        ..receipt()
    };
    out.push(("valid-anonymous-drawn", Case::of(&anonymous)));
    let mut c = Case::of(&receipt());
    c.audience = "other.example";
    out.push(("other-audience", c));
    let mut c = Case::of(&receipt());
    c.intent = d(8);
    out.push(("other-intent", c));
    let mut c = Case::of(&receipt());
    c.domain = d(2);
    out.push(("other-domain", c));
    let mut c = Case::of(&receipt());
    c.now = receipt().iat - 2 * crate::ais::SKEW_MS;
    out.push(("signed-in-the-future", c));
    let mut c = Case::of(&receipt());
    let last = c.receipt.len() - 1;
    c.receipt[last] ^= 1;
    out.push(("signature-tampered", c));
    let mut c = Case::of(&receipt());
    c.excerpt = excerpt(KeyUsage::Pap);
    out.push(("key-not-for-receipts", c));
    let late = Receipt {
        iat: 12 * HOUR,
        ..receipt()
    };
    out.push(("signed-outside-the-window", Case::of(&late)));
    let mut c = Case::of(&receipt());
    let mut v = receipt().to_value();
    if let Value::Map(entries) = &mut v {
        entries.retain(|(k, _)| *k != Value::text("drawn"));
    }
    c.receipt = sign1(
        2,
        CONTENT_TYPE,
        &dcbor::encode(&v, Limits::CEILING).unwrap(),
    );
    out.push(("payload-without-drawn", c));
    out.push(("valid-agency-chain", Case::of(&delegated())));
    let mut c = Case::of(&receipt());
    let mut v = receipt().to_value();
    if let Value::Map(entries) = &mut v {
        entries.push((Value::text("agency"), Value::Array(Vec::new())));
    }
    c.receipt = sign1(
        2,
        CONTENT_TYPE,
        &dcbor::encode(&v, Limits::CEILING).unwrap(),
    );
    out.push(("agency-empty", c));
    out
}

// OP-149 m.11
#[test]
fn the_agency_chain_round_trips_in_order() {
    let r = delegated();
    let back = Receipt::from_value(&r.to_value()).unwrap();
    assert_eq!(back, r);
    assert_eq!(back.agency[0].principal, Id([8; 16]));
    assert_eq!(back.agency[0].agent, back.agency[1].principal);
    let Value::Map(plain) = receipt().to_value() else {
        panic!("a receipt is a map");
    };
    assert!(!plain.iter().any(|(k, _)| *k == Value::text("agency")));
}

// L2-RCP-3
#[test]
fn receipts_verify_or_name_their_failure() {
    let got: Vec<(&str, Result<Receipt, &str>)> = cases()
        .iter()
        .map(|(id, c)| (*id, c.run().map_err(ReceiptError::code)))
        .collect();
    assert_eq!(got[0].1, Ok(receipt()));
    assert!(got[1].1.is_ok());
    assert_eq!(got[10].1, Ok(delegated()));
    assert_eq!(got[11].1, Err("receipt-malformed"));
    let errors: Vec<&str> = got[2..10]
        .iter()
        .map(|(_, r)| r.clone().unwrap_err())
        .collect();
    assert_eq!(
        errors,
        [
            "receipt-audience",
            "receipt-intent",
            "receipt-domain",
            "receipt-future",
            "receipt-signature",
            "receipt-key",
            "receipt-key",
            "receipt-malformed",
        ]
    );
    assert_eq!(
        digest(&receipt()).unwrap(),
        Digest(
            suiss_crypto::digest::context_digest(
                "access/receipt/v1",
                &receipt().to_bytes().unwrap()
            )
            .0
        )
    );
}

// L2-RCP-3
#[test]
fn a_receipt_without_audience_is_malformed() {
    let r = Receipt {
        audience: String::new(),
        ..receipt()
    };
    assert_eq!(Receipt::from_value(&r.to_value()), Err(ModelError::Shape));
}

// L2-RCP-3
#[test]
fn a_receipt_at_the_skew_edge_verifies() {
    let mut c = Case::of(&receipt());
    c.now = receipt().iat - crate::ais::SKEW_MS;
    assert_eq!(c.run(), Ok(receipt()));
    c.now -= 1;
    assert_eq!(c.run(), Err(ReceiptError::Future));
}

// §9.8, CR-58 m.5
#[test]
fn the_metadata_must_be_the_expected_domains() {
    let mut m = metadata();
    m.domain = d(2);
    for b in m.binding.values_mut() {
        b.scope = BindingScope::Provider(BTreeSet::from([d(1)]));
    }
    let c = Case::of(&receipt());
    let run = |m: &DomainMetadata| {
        verify(
            &PureBackend,
            m,
            &c.receipt,
            &c.excerpt,
            &Expected {
                domain: &c.domain,
                audience: c.audience,
                intent: &c.intent,
                now: c.now,
            },
        )
    };
    assert_eq!(run(&m), Err(ReceiptError::Domain));
    m.domain = d(1);
    assert_eq!(run(&m), Ok(receipt()));
}

// L2-RCP-3
#[test]
fn receipt_vectors_match() {
    let m = metadata();
    let lines: Vec<String> = cases()
        .iter()
        .map(|(id, c)| {
            let result = match c.run() {
                Ok(r) => format!("\"receipt\": \"{}\"", hex(&r.to_bytes().unwrap())),
                Err(e) => format!("\"error\": \"{}\"", e.code()),
            };
            format!(
                "  {{\"id\": \"{id}\", {}, \"excerpt\": \"{}\", \"sign1\": \"{}\", \"domain\": \"{}\", \"audience\": \"{}\", \"intent\": \"{}\", \"now\": {}, {result}}}",
                field(&["L2-RCP-3"]),
                hex(&c.excerpt),
                hex(&c.receipt),
                hex(&dcbor::encode(&c.domain.to_value(), Limits::CEILING).unwrap()),
                c.audience,
                hex(&dcbor::encode(&c.intent.to_value(), Limits::CEILING).unwrap()),
                c.now
            )
        })
        .collect();
    let json = format!(
        "{{\n \"rule\": \"L2-RCP-3\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"receipt.verify\",\n \"metadata\": \"{}\",\n \"cases\": [\n{}\n ]\n}}\n",
        hex(&m.to_bytes().unwrap()),
        lines.join(",\n")
    );
    golden(
        "receipt.json",
        include_str!("../../../../conformance/vectors/core/1/receipt.json"),
        &json,
    );
}

mod evidence;
