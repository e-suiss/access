#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_kernel::combinator::Decision;

use super::*;

const MAX: usize = 256 * 1024;

fn b64(bytes: &[u8]) -> String {
    b64url_encode(bytes)
}

fn body(context_extra: &str, carriers: &str) -> String {
    format!(
        r#"{{{carriers}, "context": {{
            "domain": "{d}", "mode": "commit", "nonce": "{n}",
            "basis": {{"holding": {{"grant": "{g}", "holder": "{h}", "since": 7}}}},
            "capacity": "own",
            "intent": {{
                "action": {{"namespace": "shop", "name": "read", "major": 1, "schema": "{s}"}},
                "resources": [{{"namespace": "shop", "path": ["items", "1"], "incarnation": 0}}],
                "params": {{"limit": {{"amount": {{"value": 500, "unit": "EUR"}}}}, "tag": {{"eq": {{"bytes": "AQI"}}}}}},
                "validity": {{"from": 0, "until": 100}}
            }}{context_extra}
        }}}}"#,
        d = b64(&[1; 32]),
        n = b64(&[2; 16]),
        g = b64(&[3; 16]),
        h = b64(&[4; 16]),
        s = b64(&[5; 32]),
    )
}

const CARRIERS: &str = r#""subject": {"type": "user", "id": "ignored", "properties": {"x": 1}}, "action": {"name": "read"}, "resource": {"type": "shop", "id": "items/1"}"#;

// PI-1
#[test]
fn a_request_decodes_into_the_core_terms() {
    let d = decode(body("", CARRIERS).as_bytes(), MAX).unwrap();
    let r = &d.request;
    assert_eq!(r.domain, Digest([1; 32]));
    assert_eq!(r.mode, Mode::Commit);
    assert_eq!(r.nonce, vec![2; 16]);
    assert_eq!(
        r.basis,
        ExerciseBasis::Holding(HoldingRef {
            grant: Id([3; 16]),
            holder: Id([4; 16]),
            since: 7
        })
    );
    assert_eq!(r.capacity, Capacity::Own);
    assert_eq!(r.intent.action.schema, Digest([5; 32]));
    assert_eq!(r.intent.resources[0].path, ["items", "1"]);
    assert_eq!(
        r.intent.params["limit"],
        ParamValue::Amount {
            value: 500,
            unit: String::from("EUR")
        }
    );
    assert_eq!(
        r.intent.params["tag"],
        ParamValue::Eq(EqValue::Bytes(vec![1, 2]))
    );
    assert!(d.ais.is_none() && r.payload.is_none());
}

// L1-ADP-12, L1-ADP-13, OP-143 m.13 (c)
#[test]
fn proofs_and_the_continued_exercise_decode() {
    let extra = format!(
        r#", "proofs": [{{"claim": "{c}"}}, {{"claim_ref": "{r}"}}, {{"contribution": "{e}"}}, {{"aas": "{c}"}}, {{"foreign_pap": {{"metadata": "{c}", "pap": "{r}", "excerpt": "{e}", "presentation": "{c}", "status": {{"list": "{r}", "excerpt": "{e}"}}}}}}], "exercise": "{e}""#,
        c = b64(&[9, 9]),
        r = b64(&[8; 16]),
        e = b64(&[7; 32]),
    );
    let d = decode(body(&extra, CARRIERS).as_bytes(), MAX).unwrap();
    assert_eq!(
        d.request.proofs,
        [
            ProofRef::Claim(vec![9, 9]),
            ProofRef::ClaimRef(Id([8; 16])),
            ProofRef::Contribution(Digest([7; 32])),
            ProofRef::Aas(vec![9, 9]),
            ProofRef::ForeignPap {
                metadata: vec![9, 9],
                pap: vec![8; 16],
                excerpt: vec![7; 32],
                presentation: vec![9, 9],
                status: Some((vec![8; 16], vec![7; 32])),
            },
        ]
    );
    assert_eq!(d.request.exercise, Some(Digest([7; 32])));
    for bad in [
        r#", "proofs": []"#.to_owned(),
        r#", "proofs": [{"pin": "AA"}]"#.to_owned(),
        r#", "proofs": [{"foreign_pap": {"metadata": "AA", "pap": "AA", "excerpt": "AA"}}]"#
            .to_owned(),
        r#", "proofs": [{"foreign_pap": {"metadata": "AA", "pap": "AA", "excerpt": "AA", "presentation": "AA", "x": "AA"}}]"#
            .to_owned(),
        format!(
            r#", "proofs": [{}]"#,
            vec![r#"{"claim": "AA"}"#; 65].join(",")
        ),
    ] {
        assert!(
            decode(body(&bad, CARRIERS).as_bytes(), MAX).is_err(),
            "{bad}"
        );
    }
}

// OP-152 m.5 (b): the PEP's pseudonymous rate context travels in `rate_context`
#[test]
fn a_rate_context_is_decoded_or_refused() {
    let d = decode(body("", CARRIERS).as_bytes(), MAX).unwrap();
    assert_eq!(d.context, None);
    let with = decode(
        body(r#", "rate_context": "ip:0a1b""#, CARRIERS).as_bytes(),
        MAX,
    )
    .unwrap();
    assert_eq!(with.context, RateContext::parse("ip:0a1b"));
    for bad in [r#""""#, r#""192.0.2.0/24""#, "7"] {
        let extra = format!(r#", "rate_context": {bad}"#);
        assert_eq!(
            decode(body(&extra, CARRIERS).as_bytes(), MAX).unwrap_err(),
            AdpError("rate_context"),
            "{bad}"
        );
    }
    assert_eq!(
        pointer(Body::Context, "rate_context").as_deref(),
        Some("#/context/rate_context")
    );
}

#[test]
fn an_unknown_context_member_is_a_protocol_error() {
    let e = decode(body(r#", "hint": 1"#, CARRIERS).as_bytes(), MAX).unwrap_err();
    assert_eq!(e, AdpError("unknown-member"));
}

// PI-2
#[test]
fn the_carriers_must_name_the_intent() {
    let wrong = CARRIERS.replace("items/1", "items/2");
    assert_eq!(
        decode(body("", &wrong).as_bytes(), MAX).unwrap_err(),
        AdpError("carrier")
    );
    let no_subject = r#""action": {"name": "read"}, "resource": {"type": "shop", "id": "items/1"}"#;
    assert_eq!(
        decode(body("", no_subject).as_bytes(), MAX).unwrap_err(),
        AdpError("carrier")
    );
}

#[test]
fn json_outside_i_json_is_refused() {
    let dup = body("", CARRIERS).replace(
        r#""mode": "commit","#,
        r#""mode": "commit", "mode": "check","#,
    );
    assert_eq!(decode(dup.as_bytes(), MAX).unwrap_err(), AdpError("json"));
    let float = body("", CARRIERS).replace(r#""since": 7"#, r#""since": 7.0"#);
    assert_eq!(decode(float.as_bytes(), MAX).unwrap_err(), AdpError("json"));
    assert_eq!(
        decode(body("", CARRIERS).as_bytes(), 64).unwrap_err(),
        AdpError("json")
    );
}

#[test]
fn a_meta_payload_travels_as_dcbor() {
    let payload = Payload::GrantRevoke { grant: Id([6; 16]) };
    let extra = format!(r#", "payload": "{}""#, b64(&payload.to_bytes().unwrap()));
    let d = decode(body(&extra, CARRIERS).as_bytes(), MAX).unwrap();
    assert_eq!(d.request.payload, Some(payload));
    let bad = body(r#", "payload": "AQI""#, CARRIERS);
    assert_eq!(
        decode(bad.as_bytes(), MAX).unwrap_err(),
        AdpError("payload")
    );
}

#[test]
fn a_short_nonce_is_refused() {
    let short = body("", CARRIERS).replace(&b64(&[2; 16]), &b64(&[2; 8]));
    assert_eq!(
        decode(short.as_bytes(), MAX).unwrap_err(),
        AdpError("nonce")
    );
}

fn response(outcome: Outcome) -> Response {
    Response {
        decision: Decision {
            outcome,
            blockers: Vec::new(),
            unmet: Vec::new(),
            relied_on: vec![Id([7; 16])],
        },
        exercise: (outcome == Outcome::Allow).then_some(Digest([8; 32])),
        record: Some(12),
        replayed: false,
        basis_ref: Some(String::from("ref")),
        consistency: Some(String::from("seen")),
        receipt: None,
        signed_receipt: None,
        pap: None,
        signed_pap: None,
        ended: Vec::new(),
        explained: None,
    }
}

#[test]
fn only_allow_is_true() {
    let allow = encode(&response(Outcome::Allow), Mode::Commit);
    assert_eq!(allow["decision"], true);
    assert_eq!(allow["context"]["outcome"], "allow");
    assert_eq!(allow["context"]["exercise"], b64(&[8; 32]));
    assert_eq!(allow["context"]["basis_ref"], "ref");
    assert!(allow["context"].get("record").is_none());
    assert_eq!(allow["context"]["relied_on"][0], b64(&[7; 16]));
    for o in [Outcome::Deny, Outcome::RequireAction] {
        assert_eq!(encode(&response(o), Mode::Commit)["decision"], false);
    }
}

#[test]
fn check_is_advisory() {
    let r = encode(&response(Outcome::Allow), Mode::Check);
    assert_eq!(r["context"]["advisory"], true);
    assert!(
        encode(&response(Outcome::Allow), Mode::Commit)["context"]
            .get("advisory")
            .is_none()
    );
}

// TI-20, OP-141 m.22 (h)
#[test]
fn the_requester_sees_no_subcode_and_hop_positions_only() {
    use access_kernel::combinator::{Blocker, BlockerClass, Position, Remediation, Resolver};
    let mut r = response(Outcome::Deny);
    r.decision.blockers = vec![
        Blocker {
            class: BlockerClass::Restricted,
            subcode: Some(String::from("secret-policy")),
            position: Position::DomainPolicy,
            resolver: Resolver::RestrictionOwner,
            remediation: Remediation::RouteToCoordinator,
        },
        Blocker {
            class: BlockerClass::Ended,
            subcode: None,
            position: Position::Hop(1),
            resolver: Resolver::GrantorOfHop(1),
            remediation: Remediation::RouteToCoordinator,
        },
    ];
    let out = encode(&r, Mode::Commit);
    let blockers = out["context"]["blockers"].as_array().unwrap();
    assert!(blockers[0].get("subcode").is_none());
    assert!(blockers[0].get("position").is_none());
    assert_eq!(blockers[0]["class"], "restricted");
    assert_eq!(blockers[1]["position"]["hop"], 1);
    assert!(!out.to_string().contains("secret-policy"));
}

// OP-141 m.38 (c), (d)
#[test]
fn viewer_and_audit_filters_disclose_more() {
    use access_authority_core::app::Scope;
    use access_kernel::combinator::{Blocker, BlockerClass, Position, Remediation, Resolver};
    let mut r = response(Outcome::Deny);
    r.decision.blockers = vec![
        Blocker {
            class: BlockerClass::Restricted,
            subcode: Some(String::from("secret-policy")),
            position: Position::DomainPolicy,
            resolver: Resolver::RestrictionOwner,
            remediation: Remediation::RouteToCoordinator,
        },
        Blocker {
            class: BlockerClass::Ended,
            subcode: Some(String::from("ended/revoked")),
            position: Position::Anchor,
            resolver: Resolver::Root,
            remediation: Remediation::NewRequestRequired,
        },
    ];
    let viewer = encode_for(&r, Mode::Commit, Scope::Viewer);
    let blockers = viewer["context"]["blockers"].as_array().unwrap();
    assert!(blockers[0].get("subcode").is_none());
    assert!(blockers[0].get("position").is_some());
    assert_eq!(blockers[1]["subcode"], "ended/revoked");
    let audit = encode_for(&r, Mode::Commit, Scope::Audit);
    assert!(audit.to_string().contains("secret-policy"));
}

fn explanation_case(id: &str) -> Out {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/cddl/examples/explanation.json");
    let doc: Out = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
        .clone()
}

fn committed_decision(id: &str) -> Decision {
    let hex = explanation_case(id)["cbor"].as_str().unwrap().to_owned();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i.saturating_add(2)], 16).unwrap())
        .collect();
    let value = suiss_crypto::dcbor::decode(&bytes, suiss_crypto::dcbor::Limits::CEILING).unwrap();
    access_kernel::combinator::codec::decision_from_value(&value).unwrap()
}

fn explained(response: &Response, scope: access_authority_core::app::Scope) -> Out {
    let context = encode_for(response, Mode::Check, scope)["context"].clone();
    let mut out = Map::new();
    for member in ["outcome", "blockers", "unmet", "relied_on"] {
        if let Some(v) = context.get(member) {
            out.insert(String::from(member), v.clone());
        }
    }
    Out::Object(out)
}

// E43, L1-ADP-10, L1-ADP-15, TI-20, OP-141 m.38
#[test]
fn the_adp_explains_in_the_published_format() {
    use access_authority_core::app::Scope;
    let mut r = response(Outcome::Deny);
    r.decision = committed_decision("deny-audit");
    for (scope, id) in [
        (Scope::Audit, "deny-audit"),
        (Scope::Viewer, "deny-viewer"),
        (Scope::Requester, "deny-requester"),
    ] {
        assert_eq!(explained(&r, scope), explanation_case(id)["json"], "{id}");
    }
    for id in ["allow-with-proofs", "allow-bare", "require-action"] {
        r.decision = committed_decision(id);
        assert_eq!(
            explained(&r, Scope::Requester),
            explanation_case(id)["json"],
            "{id}"
        );
    }
}

// §9.7.1
#[test]
fn page_total_counts_only_a_complete_visible_result() {
    assert_eq!(
        page(2, None, true),
        serde_json::json!({ "next_token": "", "total": 2 })
    );
    assert_eq!(
        page(0, None, true),
        serde_json::json!({ "next_token": "", "total": 0 })
    );
    let more = page(100, Some("t"), true);
    assert_eq!(more["has_more"], true);
    assert!(more.get("total").is_none());
    let last = page(3, None, false);
    assert_eq!(last["has_more"], false);
    assert!(last.get("total").is_none());
    let out = encode_search(&[Hit::Public], None, true);
    assert_eq!(out["page"]["total"], 1);
}

fn sample_explained() -> access_authority_core::app::audit::Explained {
    use access_authority_core::app::audit::{AuditDetail, BasisRef, LineageHop};
    access_authority_core::app::audit::Explained {
        lineage: vec![
            LineageHop {
                hop: 0,
                grant: Named::Pseudonym([1; 16]),
                holder: Some(Named::Pseudonym([2; 16])),
            },
            LineageHop {
                hop: 1,
                grant: Named::Clear(Id([3; 16])),
                holder: Some(Named::Clear(Id([4; 16]))),
            },
        ],
        audit: Some(AuditDetail {
            basis: BasisRef {
                domain: Digest([5; 32]),
                position_q_minus_1: 11,
                version_vector_digest: Digest([6; 32]),
            },
            evaluated_at: 9,
            reads: vec![(vec![1, 2], 3)],
            reason_admin: Vec::new(),
            cited: vec![Id([7; 16])],
            consumption: None,
        }),
    }
}

// §9.6.1, P41, E26, §17.1.1
#[test]
fn reason_admin_exists_only_at_audit_scope() {
    let mut r = response(Outcome::Allow);
    r.explained = Some(Box::new(sample_explained()));
    let audit = encode_for(&r, Mode::Commit, Scope::Audit);
    let admin = &audit["context"]["reason_admin"];
    assert_eq!(admin["basis_ref"]["position_q_minus_1"], 11);
    assert_eq!(admin["basis_ref"]["domain"], b64(&[5; 32]));
    assert_eq!(admin["basis_ref"]["version_vector_digest"], b64(&[6; 32]));
    assert_eq!(admin["state_basis"]["reads"][0]["version"], 3);
    assert_eq!(admin["cited"][0], b64(&[7; 16]));
    let viewer = encode_for(&r, Mode::Commit, Scope::Viewer);
    assert!(viewer["context"].get("reason_admin").is_none());
    assert_eq!(
        viewer["context"]["lineage"][0]["holder"]["pseudonym"],
        b64(&[2; 16])
    );
    assert_eq!(
        viewer["context"]["lineage"][1]["holder"]["id"],
        b64(&[4; 16])
    );
    let requester = encode_for(&r, Mode::Commit, Scope::Requester);
    assert!(requester["context"].get("reason_admin").is_none());
    assert!(requester["context"].get("lineage").is_none());
}
