#![allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "test fixtures"
)]

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

use super::*;
use crate::claim::{Channel, Unsigned, claim_id, unsigned};
use crate::model::Window;
use crate::report::{Entry, LocalOutcome, Report, SliceAmount};
use crate::vector_rules::{field, golden, hex};

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

const DOMAIN: Digest = Digest([1; 32]);

fn statement(class: &str, value: Option<EqValue>) -> Statement {
    Statement {
        domain: DOMAIN,
        issuer: Id([2; 16]),
        subject: Id([3; 16]),
        class: class.to_string(),
        value,
        issued_at: 1_000,
        validity: Window {
            from: 1_000,
            until: 100_000,
        },
        assurance: BTreeMap::new(),
        bound_intent: None,
        bound_instance: Some(Id([4; 16])),
        bound_resource: None,
        supersedes: None,
    }
}

fn authentication() -> Authentication {
    Authentication {
        method: AuthMethod::Webauthn,
        auth_time: 900,
        statement: Some(d(7)),
        evidence: Some(d(8)),
        webauthn: Some(WebauthnDetail {
            aaguid: [9; 16],
            sign_count: 0,
            up: true,
            uv: true,
            be: true,
            bs: false,
        }),
        upstream: None,
    }
}

fn oidc() -> Authentication {
    Authentication {
        method: AuthMethod::Oidc,
        auth_time: 900,
        statement: None,
        evidence: Some(d(8)),
        webauthn: None,
        upstream: Some(Upstream {
            iss: "https://idp.example".to_string(),
            acr: Some("urn:mace:incommon:iap:silver".to_string()),
            amr: vec!["pwd".to_string(), "mfa".to_string()],
        }),
    }
}

fn binding() -> AuthenticatorBinding {
    AuthenticatorBinding {
        kind: AuthenticatorKind::Passkey,
        material: d(10),
        alg: Some(-7),
        attestation: Some(("packed".to_string(), AttestationResult::Verified)),
        aaguid: Some([9; 16]),
        be: true,
        transports: ["hybrid".to_string(), "internal".to_string()]
            .into_iter()
            .collect(),
    }
}

fn posture() -> DevicePosture {
    DevicePosture {
        verdict: Verdict::Compliant,
        source: "mdm.example".to_string(),
        observed_at: 950,
        nonce: Some(d(11)),
        evidence: None,
    }
}

fn profile() -> VerifierProfile {
    VerifierProfile {
        verifier: VerifierId::Instance(Id([5; 16])),
        profiles: [
            (
                ProfileVariant::CheckpointedOffline,
                [("horizon_ms".to_string(), 14_400_000)]
                    .into_iter()
                    .collect(),
            ),
            (ProfileVariant::OnlineStrict, BTreeMap::new()),
        ]
        .into_iter()
        .collect(),
        versions: SpecVersions {
            core: 1,
            meta_schema: 1,
            profiles: BTreeMap::new(),
            schemas: BTreeSet::new(),
        },
        clock_source: "secure_rtc".to_string(),
        clock_skew_ms: 2_000,
        tamper_evident_counter: true,
        offline_report: true,
        content_position_check: false,
        status_access: ["https://access.example/status/1".to_string()]
            .into_iter()
            .collect(),
        refresh_interval_ms: Some(60_000),
        attestation: Some(d(12)),
        cap_horizon: [(
            ProfileVariant::CheckpointedOffline,
            [(0, 14_400_000), (2, 3_600_000)].into_iter().collect(),
        )]
        .into_iter()
        .collect(),
        slice_max: [("eur".to_string(), 50_000)].into_iter().collect(),
        conformance: ["access-pep-1".to_string()].into_iter().collect(),
    }
}

fn workload_profile() -> VerifierProfile {
    VerifierProfile {
        verifier: VerifierId::Workload("spiffe://example.org/rs".to_string()),
        profiles: [(ProfileVariant::BoundedStaleness, BTreeMap::new())]
            .into_iter()
            .collect(),
        content_position_check: true,
        tamper_evident_counter: false,
        offline_report: false,
        status_access: BTreeSet::new(),
        refresh_interval_ms: None,
        attestation: None,
        cap_horizon: BTreeMap::new(),
        slice_max: BTreeMap::new(),
        conformance: BTreeSet::new(),
        ..profile()
    }
}

pub(crate) fn report_fixture() -> Report {
    let mut r = Report {
        verifier_profile: d(20),
        verifier_instance: Some(Id([5; 16])),
        exercise: d(21),
        contract: d(22),
        period: Window {
            from: 1_000,
            until: 9_000,
        },
        previous: None,
        first_seq: 0,
        entries: vec![
            Entry {
                intent: d(23),
                params: None,
                time: 2_000,
                clock_evidence: Some(d(24)),
                outcome: LocalOutcome::Allow,
                drawn: [SliceAmount {
                    budget_term: d(25),
                    amount: 3,
                }]
                .into_iter()
                .collect(),
                holder_proof: Some(d(26)),
            },
            Entry {
                intent: d(27),
                params: Some(d(28)),
                time: 3_000,
                clock_evidence: None,
                outcome: LocalOutcome::Deny,
                drawn: BTreeSet::new(),
                holder_proof: None,
            },
        ],
        head: d(0),
        slice_unused: [SliceAmount {
            budget_term: d(25),
            amount: 7,
        }]
        .into_iter()
        .collect(),
        profile_version: 1,
    };
    let mut head = crate::report::seed(&r.exercise, &r.contract).unwrap();
    for (i, e) in r.entries.iter().enumerate() {
        head = crate::report::link(&head, i as u64, e).unwrap();
    }
    r.head = head;
    r
}

fn ack() -> AuthorityStateAck {
    AuthorityStateAck {
        pep: "pep.example".to_string(),
        event: AckEvent::Exercise(d(30)),
        applied_at: 5_000,
        clock_evidence: None,
        basis: 42,
        scope: [AckScope::Cache, AckScope::Token].into_iter().collect(),
    }
}

fn key_state() -> PartyKeyState {
    PartyKeyState {
        sequence: 3,
        keys: [d(31), d(32)].into_iter().collect(),
        designated: [(
            "authenticator_binding".to_string(),
            [Id([2; 16])].into_iter().collect(),
        )]
        .into_iter()
        .collect(),
    }
}

fn bodies() -> Vec<(&'static str, Class, Body)> {
    vec![
        (
            "authentication-webauthn",
            Class::Authentication,
            Body::Authentication(authentication()),
        ),
        (
            "authentication-oidc",
            Class::Authentication,
            Body::Authentication(oidc()),
        ),
        (
            "authenticator-binding",
            Class::AuthenticatorBinding,
            Body::AuthenticatorBinding(binding()),
        ),
        (
            "posture-device",
            Class::PostureDevice,
            Body::DevicePosture(posture()),
        ),
        (
            "verifier-profile",
            Class::VerifierProfile,
            Body::VerifierProfile(profile()),
        ),
        (
            "verifier-profile-workload",
            Class::VerifierProfile,
            Body::VerifierProfile(workload_profile()),
        ),
        (
            "offline-report",
            Class::OfflineExerciseReport,
            Body::OfflineReport(report_fixture()),
        ),
        (
            "authority-state-ack",
            Class::AuthorityStateAck,
            Body::AuthorityStateAck(ack()),
        ),
        (
            "party-key-state",
            Class::PartyKeyState,
            Body::PartyKeyState(key_state()),
        ),
        (
            "party-recovered",
            Class::PartyRecovered,
            Body::PartyRecovered(PartyRecovered {
                previous: d(33),
                next: d(34),
            }),
        ),
        (
            "identity-binding-person",
            Class::IdentityBinding(BindingKind::Person),
            Body::IdentityBinding(IdentityBinding { evidence: d(35) }),
        ),
    ]
}

fn enc(v: &Value) -> Vec<u8> {
    dcbor::encode(v, Limits::CEILING).unwrap()
}

// L2-CLB-1, L2-CLB-3
#[test]
fn bodies_round_trip_and_bind_their_class() {
    for (id, class, body) in bodies() {
        let v = body.to_value();
        assert_eq!(Body::from_value(class, &v).unwrap(), body, "{id}");
        let digest = body_digest(class, &v).unwrap();
        assert_eq!(Class::parse(&class.name()), Some(class), "{id}");
        if class != Class::AuthenticatorBinding {
            assert_ne!(
                body_digest(Class::AuthenticatorBinding, &v).unwrap(),
                digest,
                "{id}"
            );
        }
    }
    assert_eq!(Class::parse("identity_binding_robot"), None);
    assert_eq!(Class::parse("kyc"), None);
}

// §9.12.1, PI-12, U25
#[test]
fn a_profile_covers_only_what_it_declares() {
    let p = profile();
    let within: BTreeMap<String, u64> = [("horizon_ms".to_string(), 3_600_000)]
        .into_iter()
        .collect();
    let beyond: BTreeMap<String, u64> = [("horizon_ms".to_string(), 86_400_000)]
        .into_iter()
        .collect();
    let undeclared: BTreeMap<String, u64> = [("uses".to_string(), 1)].into_iter().collect();
    assert!(p.covers(ProfileVariant::CheckpointedOffline, &within));
    assert!(!p.covers(ProfileVariant::CheckpointedOffline, &beyond));
    assert!(!p.covers(ProfileVariant::CheckpointedOffline, &undeclared));
    assert!(!p.covers(ProfileVariant::BoundedStaleness, &BTreeMap::new()));
    assert_eq!(
        p.cap_horizon(ProfileVariant::CheckpointedOffline, 2),
        Some(3_600_000)
    );
    assert_eq!(p.cap_horizon(ProfileVariant::CheckpointedOffline, 3), None);
}

struct Case {
    rules: &'static [&'static str],
    class: String,
    value: Option<EqValue>,
    body: Option<Vec<u8>>,
}

fn digest_value(class: Class, body: &Body) -> EqValue {
    EqValue::Bytes(body_digest(class, &body.to_value()).unwrap().to_vec())
}

fn cases() -> Vec<(String, Case)> {
    let mut out = Vec::new();
    for (id, class, body) in bodies() {
        out.push((
            String::from(id),
            Case {
                rules: &["L2-CLB-1", "L2-CLB-3"],
                class: class.name(),
                value: Some(digest_value(class, &body)),
                body: Some(enc(&body.to_value())),
            },
        ));
    }
    let auth = Body::Authentication(authentication());
    out.push((
        "body-withheld".to_string(),
        Case {
            rules: &["L2-CLB-2"],
            class: "authentication".to_string(),
            value: Some(digest_value(Class::Authentication, &auth)),
            body: None,
        },
    ));
    out.push((
        "body-digest-mismatch".to_string(),
        Case {
            rules: &["L2-CLB-3"],
            class: "authentication".to_string(),
            value: Some(EqValue::Bytes(vec![0; 32])),
            body: Some(enc(&auth.to_value())),
        },
    ));
    out.push((
        "body-of-another-class".to_string(),
        Case {
            rules: &["L2-CLB-1", "L2-CLB-3"],
            class: "authenticator_binding".to_string(),
            value: Some(digest_value(Class::Authentication, &auth)),
            body: Some(enc(&auth.to_value())),
        },
    ));
    let mut extra = authentication().to_value();
    if let Value::Map(m) = &mut extra {
        m.push((Value::text("password"), Value::text("hunter2")));
    }
    out.push((
        "body-unknown-field".to_string(),
        Case {
            rules: &["L2-CLB-3"],
            class: "authentication".to_string(),
            value: Some(EqValue::Bytes(
                body_digest(Class::Authentication, &extra).unwrap().to_vec(),
            )),
            body: Some(enc(&extra)),
        },
    ));
    let mut no_material = binding().to_value();
    if let Value::Map(m) = &mut no_material {
        m.retain(|(k, _)| *k != Value::text("material"));
    }
    out.push((
        "binding-without-material".to_string(),
        Case {
            rules: &["L2-CLB-3"],
            class: "authenticator_binding".to_string(),
            value: Some(EqValue::Bytes(
                body_digest(Class::AuthenticatorBinding, &no_material)
                    .unwrap()
                    .to_vec(),
            )),
            body: Some(enc(&no_material)),
        },
    ));
    out.push((
        "body-class-scalar-value".to_string(),
        Case {
            rules: &["L2-CLB-2"],
            class: "verifier_profile".to_string(),
            value: Some(EqValue::Bool(true)),
            body: None,
        },
    ));
    let scalar: [(&str, &str, Option<EqValue>, bool); 14] = [
        (
            "account-status-suspended",
            "account_status",
            Some(EqValue::Text("suspended".to_string())),
            true,
        ),
        (
            "account-status-unknown",
            "account_status",
            Some(EqValue::Text("frozen".to_string())),
            false,
        ),
        (
            "party-compromise-unknown-time",
            "party_compromise",
            None,
            true,
        ),
        (
            "party-compromise-occurred",
            "party_compromise",
            Some(EqValue::Int(500)),
            true,
        ),
        (
            "party-compromise-negative",
            "party_compromise",
            Some(EqValue::Int(-1)),
            false,
        ),
        (
            "party-terminated",
            "party_terminated",
            Some(EqValue::Int(700)),
            true,
        ),
        ("party-terminated-missing", "party_terminated", None, false),
        (
            "identity-break",
            "party_identity_break",
            Some(EqValue::Text("key_loss".to_string())),
            true,
        ),
        (
            "controller-of",
            "controller_of",
            Some(EqValue::Bytes(vec![6; 16])),
            true,
        ),
        (
            "controller-of-short",
            "controller_of",
            Some(EqValue::Bytes(vec![6; 15])),
            false,
        ),
        (
            "org-member",
            "org_member",
            Some(EqValue::Bytes(vec![7; 16])),
            true,
        ),
        (
            "org-member-digest",
            "org_member",
            Some(EqValue::Bytes(vec![7; 32])),
            false,
        ),
        (
            "agent-kind",
            "agent_kind",
            Some(EqValue::Text("assistant".to_string())),
            true,
        ),
        (
            "class-outside-the-table",
            "kyc",
            Some(EqValue::Bool(true)),
            true,
        ),
    ];
    for (id, class, value, _) in scalar {
        out.push((
            String::from(id),
            Case {
                rules: &["L2-CLB-2"],
                class: class.to_string(),
                value,
                body: None,
            },
        ));
    }
    out
}

fn run(c: &Case) -> Result<Option<Body>, BodyError> {
    check(&statement(&c.class, c.value.clone()), c.body.as_deref())
}

// L2-CLB-2, L2-CLB-3, E26
#[test]
fn values_and_bodies_are_checked() {
    let got: BTreeMap<String, Result<bool, &str>> = cases()
        .iter()
        .map(|(id, c)| {
            (
                id.clone(),
                run(c).map(|b| b.is_some()).map_err(BodyError::code),
            )
        })
        .collect();
    assert_eq!(got["authentication-webauthn"], Ok(true));
    assert_eq!(got["offline-report"], Ok(true));
    assert_eq!(got["body-withheld"], Ok(false));
    assert_eq!(got["body-digest-mismatch"], Err("claim-body-digest"));
    assert_eq!(got["body-of-another-class"], Err("claim-body"));
    assert_eq!(got["body-unknown-field"], Err("claim-body"));
    assert_eq!(got["binding-without-material"], Err("claim-body"));
    assert_eq!(got["body-class-scalar-value"], Err("claim-value"));
    assert_eq!(got["account-status-suspended"], Ok(false));
    assert_eq!(got["account-status-unknown"], Err("claim-value"));
    assert_eq!(got["party-compromise-negative"], Err("claim-value"));
    assert_eq!(got["party-terminated-missing"], Err("claim-value"));
    assert_eq!(got["controller-of-short"], Err("claim-value"));
    assert_eq!(got["class-outside-the-table"], Ok(false));
}

// L2-CLB-1 to L2-CLB-3
#[test]
fn claim_body_vectors_match() {
    let rows: Vec<String> = cases()
        .iter()
        .map(|(id, c)| {
            let result = match run(c) {
                Ok(Some(_)) => match &c.value {
                    Some(EqValue::Bytes(b)) => format!("\"digest\": \"{}\"", hex(b)),
                    _ => String::from("\"valid\": true"),
                },
                Ok(None) => String::from("\"valid\": true"),
                Err(e) => format!("\"error\": \"{}\"", e.code()),
            };
            let value = c
                .value
                .as_ref()
                .map(|v| format!(", \"value\": \"{}\"", hex(&enc(&v.to_value()))))
                .unwrap_or_default();
            let body = c
                .body
                .as_ref()
                .map(|b| format!(", \"body\": \"{}\"", hex(b)))
                .unwrap_or_default();
            format!(
                "  {{\"id\": \"{id}\", {}, \"class\": \"{}\"{value}{body}, {result}}}",
                field(c.rules),
                c.class
            )
        })
        .collect();
    let json = format!(
        "{{\n \"rule\": \"L2-CLB-3\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"claim.body\",\n \"cases\": [\n{}\n ]\n}}\n",
        rows.join(",\n")
    );
    golden(
        "claim-body.json",
        include_str!("../../../../../conformance/vectors/core/1/claim-body.json"),
        &json,
    );
}

fn pep_fact() -> Unsigned {
    Unsigned {
        statement: statement("store_open", Some(EqValue::Bool(true))),
        channel: Channel::Pep([0xaa; 32]),
    }
}

fn unsigned_cases() -> Vec<(&'static str, Vec<u8>, Channel)> {
    let fact = pep_fact().to_bytes().unwrap();
    let mut other_domain = pep_fact();
    other_domain.statement.domain = Digest([9; 32]);
    let mut two = pep_fact().to_value();
    if let Value::Map(m) = &mut two {
        for (k, v) in m.iter_mut() {
            if *k == Value::text("channel") {
                *v = Value::Map(vec![
                    (Value::text("pep"), Value::Bytes(vec![0xaa; 32])),
                    (Value::text("scim"), Value::Bytes(vec![0xbb; 32])),
                ]);
            }
        }
    }
    let scim = Unsigned {
        channel: Channel::Scim([0xbb; 32]),
        ..pep_fact()
    };
    vec![
        ("pep-fact", fact.clone(), Channel::Pep([0xaa; 32])),
        (
            "scim-claim",
            scim.to_bytes().unwrap(),
            Channel::Scim([0xbb; 32]),
        ),
        ("another-channel", fact, Channel::Pep([0xcc; 32])),
        (
            "another-domain",
            other_domain.to_bytes().unwrap(),
            Channel::Pep([0xaa; 32]),
        ),
        ("two-channels", enc(&two), Channel::Pep([0xaa; 32])),
    ]
}

// L2-CLM-5, §5.10, P37
#[test]
fn unsigned_claims_name_their_channel() {
    let got: Vec<Result<Unsigned, &str>> = unsigned_cases()
        .iter()
        .map(|(_, b, c)| unsigned(b, &DOMAIN, c).map_err(crate::claim::ClaimError::code))
        .collect();
    assert_eq!(got[0], Ok(pep_fact()));
    assert!(got[1].is_ok());
    assert!(got[2..].iter().all(|r| *r == Err("claim-payload")));
}

// L2-CLM-5
#[test]
fn unsigned_claim_vectors_match() {
    let rows: Vec<String> = unsigned_cases()
        .iter()
        .map(|(id, bytes, channel)| {
            let (kind, thumb) = match channel {
                Channel::Pep(t) => ("pep", t),
                Channel::Scim(t) => ("scim", t),
            };
            let result = match unsigned(bytes, &DOMAIN, channel) {
                Ok(_) => format!("\"claim_id\": \"{}\"", hex(&claim_id(bytes).0)),
                Err(e) => format!("\"error\": \"{}\"", e.code()),
            };
            format!(
                "  {{\"id\": \"{id}\", {}, \"claim\": \"{}\", \"channel\": \"{kind}\", \"thumbprint\": \"{}\", {result}}}",
                field(&["L2-CLM-5"]),
                hex(bytes),
                hex(thumb)
            )
        })
        .collect();
    let json = format!(
        "{{\n \"rule\": \"L2-CLM-5\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"claim.unsigned\",\n \"domain\": \"{}\",\n \"cases\": [\n{}\n ]\n}}\n",
        hex(&enc(&DOMAIN.to_value())),
        rows.join(",\n")
    );
    golden(
        "claim-unsigned.json",
        include_str!("../../../../../conformance/vectors/core/1/claim-unsigned.json"),
        &json,
    );
}

// L2-CLB-1, §10.1.5
#[test]
fn an_upstream_amr_is_never_an_empty_list() {
    fn member<'a>(v: &'a mut Value, key: &str) -> &'a mut Value {
        let Value::Map(m) = v else {
            panic!("not a map")
        };
        &mut m
            .iter_mut()
            .find(|(k, _)| *k == Value::text(key))
            .unwrap()
            .1
    }
    let mut v = oidc().to_value();
    *member(member(&mut v, "upstream"), "amr") = Value::Array(Vec::new());
    assert_eq!(Authentication::from_value(&v), Err(ModelError::Range));
}

// L2-CLB-1, §9.12.3, §9.16
#[test]
fn an_ack_for_a_semantic_event_round_trips() {
    let a = AuthorityStateAck {
        event: AckEvent::Event("domain.key_rotated".to_string()),
        ..ack()
    };
    assert_eq!(AuthorityStateAck::from_value(&a.to_value()).unwrap(), a);
}
