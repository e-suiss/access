//! The Reference Verifier's foreign mode (§9.15A.2, OP-143 m.13 (d), INV-17, PI-3, Ek B 5068,
//! 4739): a foreign domain's PAP used in this domain only under a `foreign-authority`
//! Acceptance that pins the foreign domain's binding keys and names the class.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "test helpers and one table of refusals"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::foreign::{ForeignIssuer, domain_text};
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, Id, ResourceRef, ResourceSelector, Structural,
    SubjectSelector, Window,
};
use access_kernel::pap::{CONTENT_TYPE, Holder, PRESENTATION_CONTENT_TYPE, Pap, Presentation};
use access_kernel::validity::{ProfileVariant, Revalidation, ValidityContract};
use access_kernel::verify::cose::{Algorithm, PublicKey, to_be_signed};
use access_kernel::verify::key_scope::{
    BindingKey, BindingScope, DomainMetadata, EXCERPT_CONTENT_TYPE, KeyExcerpt, KeyUsage,
    METADATA_CONTENT_TYPE, OperationalKey, SpecVersions, thumbprint,
};
use ed25519_dalek::Signer as _;
use suiss_crypto::dcbor::{self, Limits, Value};

const HOUR: u64 = 3_600_000;
const IAT: u64 = 10 * HOUR + HOUR / 2;
const NOW: u64 = 12 * HOUR;
const FOREIGN: Digest = Digest([1; 32]);
const HERE: Digest = Digest([2; 32]);

fn ed(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn ed_pub(seed: u8) -> PublicKey {
    PublicKey::Ed25519(ed(seed).verifying_key().to_bytes())
}

fn sign1(seed: u8, content_type: &str, payload: &[u8]) -> Vec<u8> {
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

fn metadata(issued_at: u64, signer: u8) -> Vec<u8> {
    let b = binding(1);
    let m = DomainMetadata {
        domain: FOREIGN,
        genesis: Digest([9; 32]),
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
        domain: FOREIGN,
        key: op_key(),
    };
    sign1(1, EXCERPT_CONTENT_TYPE, &e.to_bytes().unwrap())
}

fn action(namespace: &str) -> ActionRef {
    ActionRef {
        namespace: namespace.to_owned(),
        name: String::from("order"),
        major: 1,
        schema: Digest([8; 32]),
    }
}

fn bounds(namespace: &str) -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: BTreeSet::from([action(namespace)]),
            prefix: BTreeSet::new(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: String::from("shop"),
            prefix: vec![],
            kind: None,
            attrs: BTreeMap::new(),
        }),
        params: BTreeMap::new(),
        recipient: None,
        purpose: None,
    }
}

fn pap(namespace: &str) -> Vec<u8> {
    let holder = Holder {
        instance: Id([6; 16]),
        key: ed_pub(3),
    };
    let p = Pap {
        domain: FOREIGN,
        projection_exercise: Digest([3; 32]),
        holder: holder.clone(),
        capacity: Capacity::Own,
        bounds: bounds(namespace),
        local_requirements: BTreeSet::new(),
        validity: ValidityContract {
            issuing_exercise: Digest([3; 32]),
            basis_ref: vec![9],
            holder: access_kernel::pap::holder_digest(&holder).unwrap(),
            audience: BTreeSet::from([domain_text(&HERE)]),
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
            verifier_profile_ref: Digest([7; 32]),
            clock_source: String::from("trusted"),
            clock_skew_ms: 60_000,
            must_understand: BTreeSet::new(),
            status: None,
        },
        lineage_commitment: Digest([4; 32]),
        iat: IAT,
    };
    sign1(2, CONTENT_TYPE, &p.to_bytes().unwrap())
}

fn intent(namespace: &str) -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: action(namespace),
        resources: vec![ResourceRef {
            namespace: String::from("shop"),
            path: vec![String::from("o1")],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
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

/// The content of an Acceptance of `issuer` for `use_` and `classes`, cut off at `issued_until`.
fn acceptance(issuer: Value, use_: &str, classes: &[&str], issued_until: Option<u64>) -> Vec<u8> {
    let mut entries = vec![
        (Value::text("issuer"), issuer),
        (Value::text("use"), Value::text(use_)),
        (
            Value::text("classes"),
            Value::Array(classes.iter().map(|c| Value::text(c)).collect()),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(100 * HOUR)]),
        ),
    ];
    if let Some(u) = issued_until {
        entries.push((Value::text("issued_until"), Value::Unsigned(u)));
    }
    dcbor::encode(&Value::Map(entries), Limits::CEILING).unwrap()
}

fn foreign_issuer(domain: Digest, pins: &[u8]) -> Value {
    let issuer = ForeignIssuer {
        domain,
        binding: pins
            .iter()
            .map(|s| (binding(*s).kid, binding(*s)))
            .collect(),
    };
    Value::Map(vec![(Value::text("foreign"), issuer.to_value())])
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut h, x| {
        let _ = write!(h, "{x:02x}");
        h
    })
}

/// One use of a foreign PAP, as files for the binary.
struct Case {
    acceptance: Vec<u8>,
    metadata: Vec<u8>,
    pap: Vec<u8>,
    intent: IntentEnvelope,
    actor_key: PublicKey,
    class: &'static str,
    now: u64,
}

impl Case {
    fn new() -> Self {
        Self {
            acceptance: acceptance(
                foreign_issuer(FOREIGN, &[1]),
                "foreign-authority",
                &["pay"],
                None,
            ),
            metadata: metadata(11 * HOUR + HOUR / 2, 1),
            pap: pap("pay"),
            intent: intent("pay"),
            actor_key: ed_pub(3),
            class: "pay",
            now: NOW,
        }
    }

    /// The first line the binary prints for this use.
    fn run(&self, name: &str) -> String {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("access-verify-foreign")
            .join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let file = |n: &str, bytes: &[u8]| {
            let p = dir.join(n);
            std::fs::write(&p, bytes).unwrap();
            p.to_str().unwrap().to_owned()
        };
        let nonce = [5u8; 16];
        let presentation = Presentation {
            pap: access_kernel::pap::pap_digest(&self.pap),
            intent: access_kernel::intent::intent_digest(&self.intent).unwrap(),
            audience: domain_text(&HERE),
            nonce: nonce.to_vec(),
            iat: self.now,
        };
        let presentation = sign1(
            3,
            PRESENTATION_CONTENT_TYPE,
            &presentation.to_bytes().unwrap(),
        );
        let args = [
            ("--acceptance", file("acceptance", &self.acceptance)),
            ("--metadata", file("metadata", &self.metadata)),
            ("--pap", file("pap", &self.pap)),
            ("--excerpt", file("excerpt", &excerpt())),
            ("--presentation", file("presentation", &presentation)),
            ("--domain", hex(&HERE.0)),
            ("--intent", file("intent", &self.intent.to_bytes().unwrap())),
            ("--nonce", hex(&nonce)),
            ("--now", self.now.to_string()),
            (
                "--catalog",
                file(
                    "catalog",
                    &access_kernel::algebra::Catalog::default()
                        .to_bytes()
                        .unwrap(),
                ),
            ),
            (
                "--actor-key",
                file("actor-key", &self.actor_key.to_bytes().unwrap()),
            ),
            ("--class", String::from(self.class)),
            ("--remaining", file("remaining", &[0x80])),
        ];
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_access-verify"));
        cmd.arg("foreign");
        for (k, v) in &args {
            cmd.arg(k).arg(v);
        }
        let out = cmd.output().unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let first = text.lines().next().unwrap_or_default().to_owned();
        let code = out.status.code().unwrap();
        assert_eq!(code, i32::from(first != "accept"), "{name}: {text}");
        if first == "accept" {
            assert!(
                text.contains(&format!("foreign_domain: {}", hex(&FOREIGN.0))),
                "{text}"
            );
        }
        first
    }
}

// OP-143 m.13 (d), §9.15A.2, INV-17, Ek B 5068, 4739
#[test]
fn a_foreign_pap_is_accepted_only_under_its_pinned_foreign_authority_acceptance() {
    assert_eq!(Case::new().run("accept"), "accept");
    let refused: [(&str, Case, &str); 10] = [
        (
            "predicate-input",
            Case {
                acceptance: acceptance(
                    foreign_issuer(FOREIGN, &[1]),
                    "predicate-input",
                    &["pay"],
                    None,
                ),
                ..Case::new()
            },
            "foreign-not-accepted",
        ),
        (
            "other-class",
            Case {
                class: "shop",
                ..Case::new()
            },
            "foreign-not-accepted",
        ),
        (
            "other-domain",
            Case {
                acceptance: acceptance(
                    foreign_issuer(Digest([5; 32]), &[1]),
                    "foreign-authority",
                    &["pay"],
                    None,
                ),
                ..Case::new()
            },
            "foreign-not-accepted",
        ),
        (
            "unpinned",
            Case {
                acceptance: acceptance(
                    foreign_issuer(FOREIGN, &[4]),
                    "foreign-authority",
                    &["pay"],
                    None,
                ),
                ..Case::new()
            },
            "foreign-metadata",
        ),
        (
            "stale",
            Case {
                metadata: metadata(NOW - access_kernel::foreign::FRESHNESS_MS - 1, 1),
                ..Case::new()
            },
            "foreign-stale",
        ),
        (
            "outside-bounds",
            Case {
                intent: intent("shop"),
                ..Case::new()
            },
            "pap-bounds",
        ),
        (
            "holder-key",
            Case {
                actor_key: ed_pub(4),
                ..Case::new()
            },
            "foreign-holder-key",
        ),
        (
            "class",
            Case {
                acceptance: acceptance(
                    foreign_issuer(FOREIGN, &[1]),
                    "foreign-authority",
                    &["pa"],
                    None,
                ),
                class: "pa",
                ..Case::new()
            },
            "foreign-class",
        ),
        (
            "cutoff",
            Case {
                acceptance: acceptance(
                    foreign_issuer(FOREIGN, &[1]),
                    "foreign-authority",
                    &["pay"],
                    Some(IAT - 1),
                ),
                ..Case::new()
            },
            "foreign-cutoff",
        ),
        (
            "expired-acceptance",
            Case {
                now: 101 * HOUR,
                ..Case::new()
            },
            "foreign-not-accepted",
        ),
    ];
    for (name, case, reason) in refused {
        assert_eq!(case.run(name), format!("reject: {reason}"), "{name}");
    }
}
