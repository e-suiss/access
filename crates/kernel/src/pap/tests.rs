#![allow(clippy::arithmetic_side_effects, reason = "test fixtures")]

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

use super::*;
use crate::intent::ContextRefs;
use crate::model::{
    ActionRef, ActionSet, Binding, Bound, Consumption, Independence, ProofKind, ResourceRef,
    ResourceSelector, Structural, Window,
};
use crate::validity::{OfflineSlice, ProfileVariant, Revalidation};
use crate::vector_rules::{field, golden, hex};
use crate::verify::PureBackend;
use crate::verify::cose::{Algorithm, to_be_signed};
use crate::verify::key_scope::{
    BindingKey, BindingScope, EXCERPT_CONTENT_TYPE, KeyExcerpt, OperationalKey, SpecVersions,
};

const HOUR: u64 = 3_600_000;
const IAT: u64 = 10 * HOUR + HOUR / 2;
const NOW: u64 = 12 * HOUR;
const VERIFIER: &str = "verifier.example";

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
        .sign(&to_be_signed(&prot, payload))
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
        operational_keys: vec![op_key(KeyUsage::Pap)],
        min_versions: SpecVersions::default(),
        adopted: SpecVersions::default(),
        caps: None,
        hybrid: None,
        discovery: None,
    }
}

fn excerpt(usage: KeyUsage) -> Vec<u8> {
    let e = KeyExcerpt {
        domain: d(1),
        key: op_key(usage),
    };
    sign1(1, EXCERPT_CONTENT_TYPE, &e.to_bytes().unwrap())
}

fn action(namespace: &str, name: &str) -> ActionRef {
    ActionRef {
        namespace: namespace.to_string(),
        name: name.to_string(),
        major: 1,
        schema: d(9),
    }
}

fn catalog() -> Catalog {
    Catalog {
        catalogs: BTreeMap::from([(d(20), BTreeSet::from([action("pay", "refund")]))]),
        ..Catalog::default()
    }
}

fn bounds() -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: BTreeSet::new(),
            prefix: BTreeSet::from([("pay".to_string(), d(20))]),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: "shop".to_string(),
            prefix: vec!["orders".to_string()],
            kind: None,
            attrs: BTreeMap::new(),
        }),
        params: BTreeMap::from([(
            "amount".to_string(),
            Bound::Range {
                min: None,
                max: Some(100),
                unit: "eur".to_string(),
            },
        )]),
        recipient: None,
        purpose: None,
    }
}

fn term(class: &str) -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Authentication,
        class: class.to_string(),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: Some(300_000),
        independence: Independence::None,
        consumption: Consumption::SingleUse,
        source: None,
        assurance: BTreeMap::new(),
    }
}

fn holder() -> Holder {
    Holder {
        instance: Id([6; 16]),
        key: ed_pub(3),
    }
}

fn contract() -> ValidityContract {
    ValidityContract {
        issuing_exercise: d(3),
        basis_ref: vec![9, 9],
        holder: holder_digest(&holder()).unwrap(),
        audience: BTreeSet::from([VERIFIER.to_string()]),
        bounds: bounds(),
        class: ProfileVariant::CheckpointedOffline.class(),
        variant: ProfileVariant::CheckpointedOffline,
        profile_version: 1,
        params: BTreeMap::new(),
        horizon: 14 * HOUR,
        max_staleness_ms: None,
        freshness_sources: BTreeSet::new(),
        revalidation: Revalidation::default(),
        offline_slice: BTreeSet::from([
            OfflineSlice {
                budget_term: d(5),
                amount: 100,
                unit: "eur".to_string(),
            },
            OfflineSlice {
                budget_term: d(6),
                amount: 10,
                unit: "count".to_string(),
            },
        ]),
        local_requirements: BTreeSet::from([term("phishing_resistant")]),
        verifier_profile_ref: d(7),
        clock_source: "ntp".to_string(),
        clock_skew_ms: 60_000,
        must_understand: BTreeSet::new(),
        status: None,
    }
}

fn pap() -> Pap {
    Pap {
        domain: d(1),
        projection_exercise: d(3),
        holder: holder(),
        capacity: Capacity::Own,
        bounds: bounds(),
        local_requirements: BTreeSet::new(),
        validity: contract(),
        lineage_commitment: d(4),
        iat: IAT,
    }
}

fn intent(namespace: &str, amount: i64) -> IntentEnvelope {
    IntentEnvelope {
        action: action(namespace, "refund"),
        resources: vec![ResourceRef {
            namespace: "shop".to_string(),
            path: vec!["orders".to_string(), "o1".to_string()],
            incarnation: 0,
        }],
        params: BTreeMap::from([(
            "amount".to_string(),
            ParamValue::Amount {
                value: amount,
                unit: "eur".to_string(),
            },
        )]),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 11 * HOUR,
            until: 13 * HOUR,
        },
    }
}

struct Case {
    excerpt: Vec<u8>,
    pap: Vec<u8>,
    presentation: Vec<u8>,
    domain: Digest,
    intent: IntentEnvelope,
    audience: &'static str,
    nonce: Vec<u8>,
    now: u64,
    satisfied: BTreeSet<RequirementTerm>,
    remaining: BTreeMap<Digest, u64>,
    fresh: bool,
    understood: BTreeSet<String>,
    online: bool,
    skew_ms: u64,
    horizon_cap_ms: u64,
}

impl Case {
    fn of(p: &Pap) -> Self {
        let mut c = Self {
            excerpt: excerpt(KeyUsage::Pap),
            pap: sign1(2, CONTENT_TYPE, &p.to_bytes().unwrap()),
            presentation: Vec::new(),
            domain: d(1),
            intent: intent("pay", 40),
            audience: VERIFIER,
            nonce: vec![7; 16],
            now: NOW,
            satisfied: BTreeSet::from([term("phishing_resistant")]),
            remaining: BTreeMap::from([(d(5), 100), (d(6), 3)]),
            fresh: true,
            understood: BTreeSet::new(),
            online: false,
            skew_ms: 60_000,
            horizon_cap_ms: 24 * HOUR,
        };
        c.present(|_| {});
        c
    }

    fn present(&mut self, change: impl FnOnce(&mut Presentation)) {
        self.present_as(3, change);
    }

    fn present_as(&mut self, seed: u8, change: impl FnOnce(&mut Presentation)) {
        let mut p = Presentation {
            pap: pap_digest(&self.pap),
            intent: intent_digest(&self.intent).unwrap(),
            audience: self.audience.to_string(),
            nonce: self.nonce.clone(),
            iat: self.now,
        };
        change(&mut p);
        self.presentation = sign1(seed, PRESENTATION_CONTENT_TYPE, &p.to_bytes().unwrap());
    }

    fn run(&self) -> Result<Pap, PapError> {
        verify(
            &PureBackend,
            &metadata(),
            &self.pap,
            &self.excerpt,
            &self.presentation,
            &Expected {
                domain: &self.domain,
                intent: &self.intent,
                audience: self.audience,
                nonce: &self.nonce,
                now: self.now,
                catalog: &catalog(),
                satisfied: &self.satisfied,
                remaining: &self.remaining,
                metadata_fresh: self.fresh,
                understood: &self.understood,
                last_refresh: None,
                online: self.online,
                skew_ms: self.skew_ms,
                horizon_cap_ms: self.horizon_cap_ms,
            },
        )
    }
}

fn with_contract(change: impl FnOnce(&mut ValidityContract)) -> Pap {
    let mut p = pap();
    change(&mut p.validity);
    p
}

fn cases() -> Vec<(&'static str, Case)> {
    let mut out = vec![("valid", Case::of(&pap()))];
    out.push((
        "valid-without-offline-slice",
        Case::of(&with_contract(|v| v.offline_slice.clear())),
    ));
    let mut c = Case::of(&pap());
    let mut v = pap().to_value();
    if let Value::Map(entries) = &mut v {
        entries.retain(|(k, _)| *k != Value::text("iat"));
    }
    c.pap = sign1(
        2,
        CONTENT_TYPE,
        &dcbor::encode(&v, Limits::CEILING).unwrap(),
    );
    c.present(|_| {});
    out.push(("payload-without-iat", c));
    let mut c = Case::of(&pap());
    c.excerpt = excerpt(KeyUsage::Receipt);
    out.push(("key-not-for-paps", c));
    let late = Pap {
        iat: 12 * HOUR,
        ..pap()
    };
    out.push(("signed-outside-the-window", Case::of(&late)));
    let mut c = Case::of(&pap());
    let last = c.pap.len() - 1;
    c.pap[last] ^= 1;
    c.present(|_| {});
    out.push(("signature-tampered", c));
    let mut c = Case::of(&pap());
    c.domain = d(2);
    out.push(("other-domain", c));
    let mut c = Case::of(&pap());
    c.audience = "other.example";
    c.present(|_| {});
    out.push(("verifier-not-in-the-audience", c));
    let mut c = Case::of(&pap());
    c.now = 15 * HOUR;
    c.present(|_| {});
    out.push(("past-the-horizon", c));
    let mut c = Case::of(&with_contract(|v| {
        v.must_understand.insert("ext_geo".to_string());
    }));
    c.present(|_| {});
    out.push(("must-understand-not-understood", c));
    out.push((
        "other-holder",
        Case::of(&with_contract(|v| v.holder = d(8))),
    ));
    let mut c = Case::of(&pap());
    c.present(|p| p.nonce = vec![8; 16]);
    out.push(("presentation-other-nonce", c));
    let mut c = Case::of(&pap());
    c.present(|p| p.intent = d(8));
    out.push(("presentation-other-intent", c));
    let mut c = Case::of(&pap());
    c.present(|p| p.pap = d(8));
    out.push(("presentation-other-pap", c));
    let mut c = Case::of(&pap());
    c.present(|p| p.audience = "other.example".to_string());
    out.push(("presentation-other-audience", c));
    let mut c = Case::of(&pap());
    c.present(|p| p.iat = NOW - 2 * crate::ais::SKEW_MS);
    out.push(("presentation-too-old", c));
    let mut c = Case::of(&pap());
    c.present(|p| p.iat = NOW + 2 * crate::ais::SKEW_MS);
    out.push(("presentation-from-the-future", c));
    let mut c = Case::of(&pap());
    c.present_as(4, |_| {});
    out.push(("presentation-not-by-the-holder", c));
    let mut c = Case::of(&pap());
    c.intent = intent("ship", 40);
    c.present(|_| {});
    out.push(("intent-outside-the-bounds", c));
    let mut c = Case::of(&pap());
    c.intent = intent("pay", 150);
    c.present(|_| {});
    out.push(("amount-outside-the-bounds", c));
    let mut c = Case::of(&pap());
    c.satisfied.clear();
    out.push(("contract-requirement-not-satisfied", c));
    let own = Pap {
        local_requirements: BTreeSet::from([term("device_posture")]),
        ..pap()
    };
    out.push(("pap-requirement-not-satisfied", Case::of(&own)));
    let mut c = Case::of(&pap());
    c.remaining.insert(d(5), 30);
    out.push(("amount-slice-exhausted", c));
    let mut c = Case::of(&pap());
    c.remaining.insert(d(6), 0);
    out.push(("count-slice-exhausted", c));
    let mut c = Case::of(&pap());
    c.remaining.remove(&d(6));
    out.push(("slice-not-kept", c));
    let mut c = Case::of(&pap());
    c.fresh = false;
    out.push(("metadata-not-fresh", c));
    out
}

// L2-PAP-3: each step rejects its case, in order; the valid uses verify
#[test]
fn paps_verify_or_name_their_failure() {
    let got: Vec<(&str, Result<Pap, &str>)> = cases()
        .iter()
        .map(|(id, c)| (*id, c.run().map_err(PapError::code)))
        .collect();
    assert_eq!(got[0].1, Ok(pap()));
    assert!(got[1].1.is_ok());
    let errors: Vec<&str> = got[2..]
        .iter()
        .map(|(_, r)| r.clone().unwrap_err())
        .collect();
    assert_eq!(
        errors,
        [
            "pap-malformed",
            "pap-key",
            "pap-key",
            "pap-signature",
            "pap-domain",
            "pap-validity",
            "pap-validity",
            "pap-validity",
            "pap-holder",
            "pap-presentation",
            "pap-presentation",
            "pap-presentation",
            "pap-presentation",
            "pap-presentation",
            "pap-presentation",
            "pap-presentation",
            "pap-bounds",
            "pap-bounds",
            "pap-requirements",
            "pap-requirements",
            "pap-slice",
            "pap-slice",
            "pap-slice",
            "pap-stale",
        ]
    );
}

// L2-PAP-1, L2-PAP-2
#[test]
fn digests_use_their_contexts() {
    let s = sign1(2, CONTENT_TYPE, &pap().to_bytes().unwrap());
    assert_eq!(
        pap_digest(&s),
        suiss_crypto::digest::context_digest("access/pap/v1", &s)
    );
    assert_eq!(
        holder_digest(&holder()).unwrap(),
        suiss_crypto::digest::context_digest("access/holder/v1", &holder().to_bytes().unwrap())
    );
    assert_eq!(Pap::from_bytes(&pap().to_bytes().unwrap()), Ok(pap()));
}

// L2-PAP-3: a negative amount has no demand and does not fit a slice
#[test]
fn negative_amount_does_not_fit_a_slice() {
    let mut c = Case::of(&pap());
    c.intent = intent("pay", -5);
    c.present(|_| {});
    assert_eq!(c.run().map_err(PapError::code), Err("pap-slice"));
}

fn cbor(v: &Value) -> String {
    hex(&dcbor::encode(v, Limits::CEILING).unwrap())
}

// L2-PAP-3
#[test]
fn pap_vectors_match() {
    let m = metadata();
    let lines: Vec<String> = cases()
        .iter()
        .map(|(id, c)| {
            let result = match c.run() {
                Ok(p) => format!("\"pap\": \"{}\"", hex(&p.to_bytes().unwrap())),
                Err(e) => format!("\"error\": \"{}\"", e.code()),
            };
            let satisfied = set_value(c.satisfied.iter().map(Canonical::to_value));
            let remaining = Value::Array(
                c.remaining
                    .iter()
                    .map(|(t, n)| Value::Array(vec![t.to_value(), Value::Unsigned(*n)]))
                    .collect(),
            );
            let understood: Vec<String> =
                c.understood.iter().map(|u| format!("\"{u}\"")).collect();
            format!(
                "  {{\"id\": \"{id}\", {}, \"excerpt\": \"{}\", \"sign1\": \"{}\", \"presentation\": \"{}\", \"domain\": \"{}\", \"intent\": \"{}\", \"audience\": \"{}\", \"nonce\": \"{}\", \"now\": {}, \"satisfied\": \"{}\", \"remaining\": \"{}\", \"fresh\": {}, \"understood\": [{}], \"online\": {}, \"skew_ms\": {}, \"horizon_cap_ms\": {}, {result}}}",
                field(&["L2-PAP-3"]),
                hex(&c.excerpt),
                hex(&c.pap),
                hex(&c.presentation),
                cbor(&c.domain.to_value()),
                hex(&c.intent.to_bytes().unwrap()),
                c.audience,
                hex(&c.nonce),
                c.now,
                cbor(&satisfied),
                cbor(&remaining),
                c.fresh,
                understood.join(", "),
                c.online,
                c.skew_ms,
                c.horizon_cap_ms,
            )
        })
        .collect();
    let json = format!(
        "{{\n \"rule\": \"L2-PAP-3\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"pap.verify\",\n \"metadata\": \"{}\",\n \"catalog\": \"{}\",\n \"cases\": [\n{}\n ]\n}}\n",
        hex(&m.to_bytes().unwrap()),
        hex(&catalog().to_bytes().unwrap()),
        lines.join(",\n")
    );
    golden(
        "pap.json",
        include_str!("../../../../conformance/vectors/core/1/pap.json"),
        &json,
    );
}
