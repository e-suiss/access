#![allow(clippy::arithmetic_side_effects, reason = "test fixtures")]

use alloc::string::ToString;
use alloc::vec;

use super::*;
use crate::combinator::Capacity;
use crate::intent::ContextRefs;
use crate::model::{ActionRef, ActionSet, Id, ResourceRef, ResourceSelector, Structural};
use crate::pap::{CONTENT_TYPE, Holder, PRESENTATION_CONTENT_TYPE, Presentation};
use crate::validity::{ProfileVariant, Revalidation, ValidityContract};
use crate::verify::PureBackend;
use crate::verify::cose::{Algorithm, to_be_signed};
use crate::verify::key_scope::{
    BindingScope, DomainMetadata, EXCERPT_CONTENT_TYPE, KeyExcerpt, KeyUsage,
    METADATA_CONTENT_TYPE, OperationalKey, SpecVersions, thumbprint,
};

const HOUR: u64 = 3_600_000;
const IAT: u64 = 10 * HOUR + HOUR / 2;
const NOW: u64 = 12 * HOUR;

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
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(1), Value::int(Algorithm::Ed25519.cose())),
            (Value::Unsigned(3), Value::text(content_type)),
            (
                Value::Unsigned(4),
                Value::Bytes(thumbprint(&ed_pub(seed)).to_vec()),
            ),
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

fn binding(seed: u8) -> BindingKey {
    let key = ed_pub(seed);
    BindingKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        scope: BindingScope::Domain,
        superseded: None,
    }
}

fn op_key() -> OperationalKey {
    let key = ed_pub(2);
    OperationalKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        valid_from: 10 * HOUR,
        valid_until: 11 * HOUR,
        usage: BTreeSet::from([KeyUsage::Pap]),
    }
}

fn metadata_bytes(issued_at: u64, signer: u8) -> Vec<u8> {
    let b = binding(1);
    let m = DomainMetadata {
        domain: d(1),
        genesis: d(9),
        issued_at,
        binding: BTreeMap::from([(b.kid, b)]),
        algorithms: BTreeSet::from([Algorithm::Ed25519]),
        operational_window_max_ms: HOUR,
        operational_keys: vec![op_key()],
        min_versions: SpecVersions::default(),
        adopted: SpecVersions::default(),
        caps: None,
        hybrid: None,
        discovery: None,
    };
    sign1(signer, METADATA_CONTENT_TYPE, &m.to_bytes().unwrap())
}

fn excerpt() -> Vec<u8> {
    let e = KeyExcerpt {
        domain: d(1),
        key: op_key(),
    };
    sign1(1, EXCERPT_CONTENT_TYPE, &e.to_bytes().unwrap())
}

fn action(namespace: &str) -> ActionRef {
    ActionRef {
        namespace: namespace.to_string(),
        name: "order".to_string(),
        major: 1,
        schema: d(8),
    }
}

fn bounds(namespace: &str) -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: BTreeSet::from([action(namespace)]),
            prefix: BTreeSet::new(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: "shop".to_string(),
            prefix: vec![],
            kind: None,
            attrs: BTreeMap::new(),
        }),
        params: BTreeMap::new(),
        recipient: None,
        purpose: None,
    }
}

fn pap(namespace: &str) -> Pap {
    let holder = Holder {
        instance: Id([6; 16]),
        key: ed_pub(3),
    };
    Pap {
        domain: d(1),
        projection_exercise: d(3),
        holder: holder.clone(),
        capacity: Capacity::Own,
        bounds: bounds(namespace),
        local_requirements: BTreeSet::new(),
        validity: ValidityContract {
            issuing_exercise: d(3),
            basis_ref: vec![9],
            holder: pap::holder_digest(&holder).unwrap(),
            audience: BTreeSet::from([domain_text(&d(2))]),
            bounds: bounds(namespace),
            class: ProfileVariant::CheckpointedOffline.class(),
            variant: ProfileVariant::CheckpointedOffline,
            profile_version: 1,
            params: BTreeMap::new(),
            horizon: 14 * HOUR,
            max_staleness_ms: None,
            freshness_sources: BTreeSet::new(),
            revalidation: Revalidation::default(),
            offline_slice: BTreeSet::new(),
            local_requirements: BTreeSet::new(),
            verifier_profile_ref: d(7),
            clock_source: "trusted".to_string(),
            clock_skew_ms: 60_000,
            must_understand: BTreeSet::new(),
            status: None,
        },
        lineage_commitment: d(4),
        iat: IAT,
    }
}

fn intent(namespace: &str) -> IntentEnvelope {
    IntentEnvelope {
        provenance: alloc::collections::BTreeMap::new(),
        action: action(namespace),
        resources: vec![ResourceRef {
            namespace: "shop".to_string(),
            path: vec!["o1".to_string()],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: crate::model::Window {
            from: 11 * HOUR,
            until: 13 * HOUR,
        },
    }
}

fn gate(pins: &[u8]) -> ForeignGate {
    ForeignGate {
        issuer: ForeignIssuer {
            domain: d(1),
            binding: pins
                .iter()
                .map(|s| (binding(*s).kid, binding(*s)))
                .collect(),
        },
        classes: BTreeSet::from(["pay".to_string()]),
        validity: crate::model::Window {
            from: 0,
            until: 100 * HOUR,
        },
        ingest_until: None,
        issued_until: None,
    }
}

struct Case {
    gate: ForeignGate,
    metadata: Vec<u8>,
    pap: Vec<u8>,
    intent: IntentEnvelope,
    verifier: Digest,
    actor_key: PublicKey,
    class: &'static str,
    now: u64,
}

impl Case {
    fn new() -> Self {
        Self {
            gate: gate(&[1]),
            metadata: metadata_bytes(11 * HOUR + HOUR / 2, 1),
            pap: sign1(2, CONTENT_TYPE, &pap("pay").to_bytes().unwrap()),
            intent: intent("pay"),
            verifier: d(2),
            actor_key: ed_pub(3),
            class: "pay",
            now: NOW,
        }
    }

    fn run(&self) -> Result<Pap, &'static str> {
        let p = Presentation {
            pap: pap::pap_digest(&self.pap),
            intent: crate::intent::intent_digest(&self.intent).unwrap(),
            audience: domain_text(&self.verifier),
            nonce: vec![5; 16],
            iat: self.now,
        };
        let presentation = sign1(3, PRESENTATION_CONTENT_TYPE, &p.to_bytes().unwrap());
        let excerpt = excerpt();
        verify(
            &PureBackend,
            &self.gate,
            &Presented {
                metadata: &self.metadata,
                pap: &self.pap,
                excerpt: &excerpt,
                presentation: &presentation,
            },
            &Use {
                domain: &self.verifier,
                intent: &self.intent,
                nonce: &[5; 16],
                now: self.now,
                catalog: &Catalog::default(),
                actor_key: &self.actor_key,
                class: self.class,
                remaining: &BTreeMap::new(),
            },
        )
        .map(|(p, _)| p)
        .map_err(ForeignError::code)
    }
}

// OP-143 m.13 (d)
#[test]
fn a_foreign_pap_is_verified_under_the_pins() {
    assert_eq!(Case::new().run().map(|p| p.domain), Ok(d(1)));
    let refused = [
        (
            Case {
                gate: gate(&[4]),
                ..Case::new()
            },
            "foreign-metadata",
        ),
        (
            Case {
                metadata: metadata_bytes(11 * HOUR, 4),
                gate: gate(&[1, 4]),
                ..Case::new()
            },
            "foreign-metadata",
        ),
        (
            Case {
                gate: ForeignGate {
                    issuer: ForeignIssuer {
                        domain: d(5),
                        ..gate(&[1]).issuer
                    },
                    ..gate(&[1])
                },
                ..Case::new()
            },
            "foreign-metadata-domain",
        ),
        (
            Case {
                metadata: metadata_bytes(NOW - FRESHNESS_MS - 1, 1),
                ..Case::new()
            },
            "foreign-stale",
        ),
        (
            Case {
                verifier: d(3),
                ..Case::new()
            },
            "pap-validity",
        ),
        (
            Case {
                intent: intent("shop"),
                ..Case::new()
            },
            "pap-bounds",
        ),
        (
            Case {
                actor_key: ed_pub(4),
                ..Case::new()
            },
            "foreign-holder-key",
        ),
        (
            Case {
                class: "pa",
                ..Case::new()
            },
            "foreign-class",
        ),
        (
            Case {
                gate: ForeignGate {
                    issued_until: Some(IAT - 1),
                    ..gate(&[1])
                },
                ..Case::new()
            },
            "foreign-cutoff",
        ),
    ];
    for (case, code) in refused {
        assert_eq!(case.run().map(|_| ()), Err(code), "{code}");
    }
}

// OP-143 m.13 (a), (d)
#[test]
fn a_class_contains_its_namespace() {
    assert!(within_class("pay", &bounds("pay")));
    assert!(within_class("pay", &bounds("pay.eu")));
    assert!(!within_class("pay", &bounds("payroll")));
    assert!(!within_class("pay.eu", &bounds("pay")));
    let mut prefixed = bounds("pay");
    prefixed.actions.prefix.insert(("shop".to_string(), d(8)));
    assert!(!within_class("pay", &prefixed));
}

// OP-143 m.13 (a)
#[test]
fn a_foreign_gate_opens_for_its_domain_and_classes() {
    let g = gate(&[1]);
    let content = map([
        (
            "issuer",
            Some(Value::Map(vec![(Value::text(INDEX), g.issuer.to_value())])),
        ),
        ("use", Some(Value::text(USE))),
        ("classes", Some(Value::Array(vec![Value::text("pay")]))),
        ("subject", Some(Value::text("public"))),
        ("validity", Some(g.validity.to_value())),
    ]);
    assert_eq!(ForeignGate::of(&content), Ok(Some(g.clone())));
    assert!(g.opens(&d(1), "pay", NOW));
    assert!(!g.opens(&d(2), "pay", NOW));
    assert!(!g.opens(&d(1), "shop", NOW));
    assert!(!g.opens(&d(1), "pay", 101 * HOUR));
    let cut = ForeignGate {
        ingest_until: Some(NOW - 1),
        ..g
    };
    assert!(!cut.opens(&d(1), "pay", NOW));
    assert_eq!(
        domain_text(&Digest([0; 32])),
        "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
}

// OP-143 m.13 (d)
#[test]
fn freshness_and_cutoff_bounds_are_inclusive() {
    let edge = [
        Case {
            metadata: metadata_bytes(NOW - FRESHNESS_MS, 1),
            ..Case::new()
        },
        Case {
            gate: ForeignGate {
                issued_until: Some(IAT),
                ..gate(&[1])
            },
            ..Case::new()
        },
    ];
    for case in edge {
        assert_eq!(case.run().map(|p| p.iat), Ok(IAT));
    }
}

// OP-143 m.13 (d)
#[test]
fn a_binding_pinned_under_another_algorithm_is_dropped() {
    let both = Case {
        gate: gate(&[1, 4]),
        ..Case::new()
    };
    assert_eq!(both.run().map(|p| p.iat), Ok(IAT));
    let mut g = gate(&[1, 4]);
    let kid = binding(1).kid;
    if let Some(b) = g.issuer.binding.get_mut(&kid) {
        b.alg = Algorithm::Es256;
    }
    let case = Case {
        gate: g,
        ..Case::new()
    };
    assert_eq!(case.run().map(|_| ()), Err("pap-key"));
}

// OP-143 m.13 (a), (d)
#[test]
fn validity_bounds_outside_the_class_are_refused() {
    let mut p = pap("pay");
    p.validity.bounds.actions.exact.insert(action("shop"));
    let case = Case {
        pap: sign1(2, CONTENT_TYPE, &p.to_bytes().unwrap()),
        ..Case::new()
    };
    assert_eq!(case.run().map(|_| ()), Err("foreign-class"));
}

// OP-143 m.13 (d)
#[test]
fn the_claimed_domain_is_read_from_the_payload() {
    let signed = sign1(2, CONTENT_TYPE, &pap("pay").to_bytes().unwrap());
    assert_eq!(claimed_domain(&signed), Some(d(1)));
    assert_eq!(claimed_domain(&excerpt()), None);
    assert_eq!(claimed_domain(b"not cose"), None);
}
