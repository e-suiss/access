//! The wire contracts under `conformance/cddl/` (OP-149 m.3, m.9): every committed example is
//! checked against its CDDL and, where the contract has one, its JSON Schema, and the JSON and
//! CBOR forms of an example are the same value. The Kernel's own vectors are checked against
//! `kernel.cddl` too. `ACCESS_UPDATE_VECTORS=1` rewrites the examples' `cbor` hex.

#![cfg(not(any(target_family = "wasm", target_os = "android")))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::print_stderr,
    clippy::unused_self,
    clippy::match_wildcard_for_single_variants,
    clippy::single_match_else,
    clippy::too_many_lines,
    clippy::format_collect,
    missing_docs,
    unreachable_pub,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "contracts/cddl.rs"]
mod cddl;
#[path = "contracts/edn.rs"]
mod edn;
#[path = "contracts/regex.rs"]
mod regex;
#[path = "contracts/schema.rs"]
mod schema;

use std::path::PathBuf;

use access_kernel::codec::ModelError;
use access_kernel::combinator::codec::{
    Explanation, decision_from_value, decision_value, explanation_from_value, explanation_value,
};
use access_kernel::meta::ActorKind;
use serde_json::Value as Json;
use suiss_crypto::dcbor::{self, Limits, Value};

use cddl::Cddl;
use schema::Schema;

pub const LIMITS: Limits = Limits::CEILING;

fn conformance() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(conformance().join(path)).unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn kernel() -> Cddl {
    Cddl::new(&[&read("cddl/kernel.cddl")])
}

fn check_examples(file: &str) {
    let path = format!("cddl/examples/{file}");
    let mut doc: Json = serde_json::from_str(&read(&path)).unwrap();
    let rule = doc["contract"].as_str().unwrap().to_owned();
    let sources: Vec<String> = doc["cddl"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| read(&format!("cddl/{}", f.as_str().unwrap())))
        .collect();
    let cddl = Cddl::new(&sources.iter().map(String::as_str).collect::<Vec<_>>());
    let schema_doc: Option<Json> = doc
        .get("schema")
        .and_then(Json::as_str)
        .map(|f| serde_json::from_str(&read(&format!("cddl/{f}"))).unwrap());
    let schema = schema_doc.as_ref().map(Schema::new);
    let generic = Json::Null;
    let mut changed = false;
    for case in doc["cases"].as_array_mut().unwrap() {
        let id = case["id"].as_str().unwrap().to_owned();
        let valid = case["valid"].as_bool().unwrap();
        let value = edn::parse(case["edn"].as_str().unwrap());
        let bytes = dcbor::encode(&value, LIMITS).unwrap();
        let canonical = dcbor::decode(&bytes, LIMITS).unwrap();
        let verdict = cddl.validate(&rule, &canonical);
        assert_eq!(verdict.is_ok(), valid, "{file} {id}: CDDL {verdict:?}");
        if let (Some(s), Some(json)) = (&schema, case.get("json")) {
            let errors = s.errors(json);
            assert_eq!(
                errors.is_empty(),
                valid,
                "{file} {id}: JSON Schema {errors:?}"
            );
        }
        if !valid {
            continue;
        }
        if let Some(json) = case.get("json") {
            let from_json = schema
                .as_ref()
                .map_or_else(|| Schema::new(&generic).to_cbor(json), |s| s.to_cbor(json));
            assert_eq!(
                hex(&dcbor::encode(&from_json, LIMITS).unwrap()),
                hex(&bytes),
                "{file} {id}: the JSON and CBOR forms differ"
            );
        }
        let committed = case["cbor"].as_str().unwrap_or_default();
        if committed != hex(&bytes) {
            if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
                case["cbor"] = Json::String(hex(&bytes));
                changed = true;
            } else {
                panic!(
                    "{file} {id}: cbor is {}; run with ACCESS_UPDATE_VECTORS=1",
                    hex(&bytes)
                );
            }
        }
        assert_eq!(
            dcbor::decode(&unhex(&hex(&bytes)), LIMITS).unwrap(),
            value_sorted(&value)
        );
    }
    if changed {
        let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
        std::fs::write(conformance().join(&path), text).unwrap();
    }
}

fn value_sorted(v: &Value) -> Value {
    dcbor::decode(&dcbor::encode(v, LIMITS).unwrap(), LIMITS).unwrap()
}

// OP-149 m.9, XI-7, E44: the typed authority request examples meet its CDDL and JSON Schema,
// and each JSON form is the same value as its CBOR form
#[test]
fn authority_request_examples_meet_both_schemas() {
    check_examples("authority-request.json");
}

// OP-149 m.9, E32: the Approval Act Statement examples meet kernel.cddl; an act names its class
// exactly when it is a contribution
#[test]
fn approval_act_statement_examples_meet_the_cddl() {
    check_examples("approval-act-statement.json");
}

// §9.9, OP-150 m.2: the holder's projection.issue Exercise at the token endpoint meets its CDDL;
// an Exercise without its AIS, with a short nonce or an unknown member does not
#[test]
fn token_exercise_examples_meet_the_cddl() {
    check_examples("token-exercise.json");
}

// L0-META-30, §9.14.1 A step 4, OP-149 m.9, m.29 (b), m.33 (b): the contribute intent an
// approver's device pre-signs is an intent-envelope of kernel.cddl, and the committed example is
// byte for byte what the Kernel's contribute_intent builds for its target and class, with the
// intent digest the AIS names; an envelope without the payload digest is no contribution
#[test]
fn contribute_intent_example_is_the_kernels() {
    use access_kernel::codec::Canonical;
    use access_kernel::contribution::contribute_intent;
    use access_kernel::digest::Digest;
    use access_kernel::intent::intent_digest;
    use access_kernel::model::Window;

    check_examples("contribute-intent.json");
    let path = "cddl/examples/contribute-intent.json";
    let mut doc: Json = serde_json::from_str(&read(path)).unwrap();
    let validity = Window {
        from: 1_767_225_540_000,
        until: 1_767_226_200_000,
    };
    let mut built = 0;
    let mut changed = false;
    for case in doc["cases"].as_array_mut().unwrap() {
        let id = case["id"].as_str().unwrap().to_owned();
        let edn = edn::parse(case["edn"].as_str().unwrap());
        let Some(target) = case.get("target").and_then(Json::as_str) else {
            let envelope = access_kernel::intent::IntentEnvelope::from_value(&edn);
            if case["valid"].as_bool().unwrap() {
                let e = envelope.unwrap_or_else(|err| panic!("{id}: {err:?}"));
                assert!(
                    e.opaque.is_empty(),
                    "{id}: no contribution without its payload"
                );
            }
            continue;
        };
        let target = Digest(<[u8; 32]>::try_from(unhex(target)).unwrap());
        let class = case["class"].as_str().unwrap();
        let intent = contribute_intent(target, class, validity).unwrap();
        let bytes = dcbor::encode(&intent.to_value(), LIMITS).unwrap();
        assert_eq!(
            hex(&bytes),
            case["cbor"].as_str().unwrap(),
            "{id}: the Kernel builds {}",
            hex(&bytes)
        );
        assert_eq!(
            access_kernel::intent::IntentEnvelope::from_value(&edn).unwrap(),
            intent,
            "{id}"
        );
        let digest = hex(&intent_digest(&intent).unwrap().0);
        if case["intent_digest"].as_str() != Some(digest.as_str()) {
            if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
                case["intent_digest"] = Json::String(digest);
                changed = true;
            } else {
                panic!("{id}: intent_digest is {digest}; run with ACCESS_UPDATE_VECTORS=1");
            }
        }
        built += 1;
    }
    assert_eq!(built, 1);
    if changed {
        let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
        std::fs::write(conformance().join(path), text).unwrap();
    }
}

// OP-149 m.3, CR-58 m.3: the discovery endpoint map is deterministic CBOR of https URLs
#[test]
fn suiss_discovery_examples_meet_the_cddl() {
    check_examples("suiss-discovery.json");
}

// OP-149 m.8: the auth_context examples meet their CDDL; the session id never stands in for
// session_ref, and the AIS digest is required
#[test]
fn auth_context_examples_meet_the_cddl() {
    check_examples("auth-context.json");
}

// OP-149 m.5, OP-149 m.8, CR-24: the key lookup examples meet their CDDL; every key names its
// Party's actor kind, and a kind outside the closed set is not an answer
#[test]
fn key_lookup_examples_meet_the_cddl() {
    check_examples("key-lookup.json");
}

// OP-149 m.28 (c), m.8: the Party status lookup examples meet their CDDL; a Party is named by a
// full id with a kind from the closed set and the record that admitted it
#[test]
fn party_lookup_examples_meet_the_cddl() {
    check_examples("party-lookup.json");
}

// E43, TI-20, OP-141 m.38: the decision explanation examples meet explanation.cddl and its JSON
// Schema in every reader's view; no_objection is not an outcome and an empty list is not a list
#[test]
fn explanation_examples_meet_both_schemas() {
    check_examples("explanation.json");
}

fn explanation_cddl() -> Cddl {
    Cddl::new(&[&read("cddl/kernel.cddl"), &read("cddl/explanation.cddl")])
}

/// A `require_action` explanation whose one unmet term asks for `dim` at `level`, as CBOR and
/// as JSON.
fn assurance_explanation(dim: &str, level: u64) -> (Value, Json) {
    let edn = format!(
        "{{\"outcome\": \"require_action\", \"unmet\": [{{\"term\": {{\"proof_kind\": \
         \"authentication\", \"class\": \"step_up\", \"assurance\": {{\"{dim}\": {level}}}}}, \
         \"missing\": 1, \"position\": \"instance\", \"satisfiable_by_actor\": true}}]}}"
    );
    let value = value_sorted(&edn::parse(&edn));
    let json = serde_json::json!({
        "outcome": "require_action",
        "unmet": [{
            "term": { "proof_kind": "authentication", "class": "step_up", "assurance": { dim: level } },
            "missing": 1,
            "position": "instance",
            "satisfiable_by_actor": true,
        }],
    });
    (value, json)
}

// OP-149 m.28 (e), OP-118 m.3: the assurance ranges of explanation.cddl and the JSON Schema are
// the Kernel's, dimension by dimension and one past each bound, and the Kernel decodes exactly
// what both contracts accept; a dimension the Kernel does not know is refused by all three
#[test]
fn assurance_ranges_are_the_kernels_in_both_contracts() {
    use access_kernel::requirement::{ASSURANCE_DIMENSIONS, check_assurance};
    let cddl = explanation_cddl();
    let doc: Json = serde_json::from_str(&read("cddl/explanation.schema.json")).unwrap();
    let schema = Schema::new(&doc);
    let mut cases = Vec::new();
    for (dim, low, high) in ASSURANCE_DIMENSIONS {
        for level in low.saturating_sub(1)..=high + 1 {
            cases.push((dim, level));
        }
    }
    cases.push(("strength", 1));
    let mut accepted = 0;
    for (dim, level) in cases {
        let kernel = check_assurance(&std::collections::BTreeMap::from([(
            String::from(dim),
            level,
        )]))
        .is_ok();
        let (value, json) = assurance_explanation(dim, level);
        let decoded = decision_from_value(&value).is_ok();
        let by_cddl = cddl.validate("explanation", &value).is_ok();
        let by_schema = schema.errors(&json).is_empty();
        assert_eq!(
            (decoded, by_cddl, by_schema),
            (kernel, kernel, kernel),
            "{dim} = {level}: (kernel decode, CDDL, JSON Schema) against the Kernel's rule"
        );
        accepted += usize::from(kernel);
    }
    assert_eq!(accepted, 2 * 3 + 7 * 2);
    let (_, empty) = assurance_explanation("aal", 1);
    let mut empty = empty;
    empty["unmet"][0]["term"]["assurance"] = serde_json::json!({});
    assert!(!schema.errors(&empty).is_empty(), "an empty assurance map");
}

// E43, OP-114 m.2, OP-114 m.3, OP-141 m.38, OP-149 m.25 (a), m.33 (a): the Kernel's Decision is
// the explanation format; every valid example, in whichever scope, decodes into an Explanation
// and encodes back byte for byte; the audit scope is the Kernel decision and round-trips through
// it, the viewer's keeps every position and is one too, the requester's view of a blocker
// outside the lineage is no Kernel decision; an invalid example is not decoded
#[test]
fn explanation_examples_round_trip_through_the_kernel_decision() {
    let doc: Json = serde_json::from_str(&read("cddl/examples/explanation.json")).unwrap();
    let k = kernel();
    let mut whole = 0;
    let mut scoped = 0;
    for case in doc["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let bytes = dcbor::encode(&edn::parse(case["edn"].as_str().unwrap()), LIMITS).unwrap();
        let value = dcbor::decode(&bytes, LIMITS).unwrap();
        let explained = explanation_from_value(&value);
        let decoded = decision_from_value(&value);
        if !case["valid"].as_bool().unwrap() {
            assert!(explained.is_err(), "{id}");
            assert!(decoded.is_err(), "{id}");
            continue;
        }
        let e = explained.unwrap_or_else(|err| panic!("{id}: {err:?}"));
        assert_eq!(
            dcbor::encode(&explanation_value(&e), LIMITS).unwrap(),
            bytes,
            "{id}"
        );
        match id {
            "deny-requester" => {
                assert!(k.validate("decision", &value).is_err(), "{id}");
                assert_eq!(e.decision(), None, "{id}");
                assert_eq!(decoded.unwrap_err(), ModelError::Missing, "{id}");
                scoped += 1;
            }
            // the filter dropped a subcode, so the blockers are no longer in the order of
            // their own encodings: a Kernel decision in content, not in bytes
            "deny-viewer" => {
                let d = e.decision().unwrap_or_else(|| panic!("{id}"));
                assert_eq!(Explanation::from(d), e, "{id}");
                assert_eq!(decoded.unwrap_err(), ModelError::SetOrder, "{id}");
                scoped += 1;
            }
            _ => {
                let d = decoded.unwrap_or_else(|err| panic!("{id}: {err:?}"));
                assert_eq!(e.decision().as_ref(), Some(&d), "{id}");
                assert_eq!(Explanation::from(d.clone()), e, "{id}");
                assert_eq!(
                    dcbor::encode(&decision_value(&d), LIMITS).unwrap(),
                    bytes,
                    "{id}"
                );
                k.validate("decision", &value).unwrap();
                whole += 1;
            }
        }
    }
    assert!(whole >= 4);
    assert_eq!(scoped, 2);
}

// E43, OP-111 m.1, OP-149 m.33 (a): every decision in the Kernel's vectors decodes into a
// Decision and into an Explanation, encodes back byte for byte from each and is an explanation
#[test]
fn decision_vectors_are_explanations() {
    let k = kernel();
    let e = explanation_cddl();
    let mut seen = 0;
    for file in ["decision.json", "adversarial.json", "cve-regressions.json"] {
        for case in vectors(file)["cases"].as_array().unwrap() {
            let Some(h) = case.get("decision").and_then(Json::as_str) else {
                continue;
            };
            let value = decoded(h);
            let decision = decision_from_value(&value)
                .unwrap_or_else(|err| panic!("{file} {}: {err:?}", case["id"]));
            assert_eq!(
                hex(&dcbor::encode(&decision_value(&decision), LIMITS).unwrap()),
                h
            );
            let explained = explanation_from_value(&value)
                .unwrap_or_else(|err| panic!("{file} {}: {err:?}", case["id"]));
            assert_eq!(
                hex(&dcbor::encode(&explanation_value(&explained), LIMITS).unwrap()),
                h
            );
            assert_eq!(explained.decision().as_ref(), Some(&decision));
            k.validate("decision", &value).unwrap();
            e.validate("explanation", &value).unwrap();
            seen += 1;
        }
    }
    assert!(seen >= 100);
}

// OP-149 m.8: the CDDL actor kinds are the Kernel's
#[test]
fn actor_kinds_match_the_cddl() {
    let k = kernel();
    for kind in [
        ActorKind::Human,
        ActorKind::Agent,
        ActorKind::System,
        ActorKind::Machine,
        ActorKind::Organization,
    ] {
        assert!(k.validate("actor-kind", &Value::text(kind.name())).is_ok());
    }
    assert!(k.validate("actor-kind", &Value::text("robot")).is_err());
}

fn vectors(file: &str) -> Json {
    serde_json::from_str(&read(&format!("vectors/core/1/{file}"))).unwrap()
}

fn decoded(h: &str) -> Value {
    dcbor::decode(&unhex(h), LIMITS).unwrap()
}

// L2-RCP-1, OP-149 m.11: every receipt the Kernel accepts is a CDDL receipt
#[test]
fn receipt_vectors_meet_the_cddl() {
    let k = kernel();
    let doc = vectors("receipt.json");
    let mut seen = 0;
    for case in doc["cases"].as_array().unwrap() {
        if let Some(r) = case.get("receipt").and_then(Json::as_str) {
            k.validate("receipt", &decoded(r)).unwrap();
            seen += 1;
        }
    }
    assert!(seen >= 3);
}

// OP-149 m.6, m.8, L0-META-1: every payload the Kernel decodes is a CDDL meta-payload, and the
// Party and Instance states it writes are the CDDL's
#[test]
fn meta_vectors_meet_the_cddl() {
    let k = kernel();
    let doc = vectors("meta.json");
    let mut states = 0;
    for case in doc["cases"].as_array().unwrap() {
        let payload = decoded(case["payload"].as_str().unwrap());
        let malformed = case.get("error").and_then(Json::as_str) == Some("meta-malformed");
        if !malformed {
            k.validate("meta-payload", &payload)
                .unwrap_or_else(|e| panic!("{}: {e}", case["id"]));
        }
        for effect in case
            .get("effects")
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
        {
            let key = decoded(effect[0].as_str().unwrap());
            let Value::Array(parts) = &key else { continue };
            let rule = match parts.first() {
                Some(Value::Text(t)) if t == "party" => "party-state",
                Some(Value::Text(t)) if t == "instance" => "instance-state",
                _ => continue,
            };
            if let Some(v) = effect.get(1).and_then(Json::as_str) {
                k.validate(rule, &decoded(v))
                    .unwrap_or_else(|e| panic!("{}: {e}", case["id"]));
                states += 1;
            }
        }
    }
    assert!(states >= 3);
}

fn sign1_payload(h: &str) -> Value {
    let bytes = unhex(h);
    let Value::Array(parts) = dcbor::decode(&bytes[1..], LIMITS).unwrap() else {
        panic!("a COSE_Sign1 is an array");
    };
    let Value::Bytes(payload) = &parts[2] else {
        panic!("an attached payload");
    };
    dcbor::decode(payload, LIMITS).unwrap()
}

fn body_rule(class: &str) -> &'static str {
    match class {
        "authentication" => "authentication",
        "authenticator_binding" => "authenticator-binding",
        "posture_device" => "device-posture",
        "verifier_profile" => "verifier-profile",
        "offline_exercise_report" => "offline-exercise-report",
        "authority_state_ack" => "authority-state-ack",
        "party_key_state" => "party-key-state",
        "party_recovered" => "party-recovered",
        c if c.starts_with("identity_binding_") => "identity-binding",
        other => panic!("no body rule for {other}"),
    }
}

// L2-CLB-1, L2-CLB-3, OP-150 m.2: every body the Kernel accepts is the CDDL body of its class,
// and a body it refuses for its shape is not
#[test]
fn claim_body_vectors_meet_the_cddl() {
    let k = kernel();
    let doc = vectors("claim-body.json");
    let (mut accepted, mut refused) = (0, 0);
    for case in doc["cases"].as_array().unwrap() {
        let Some(body) = case.get("body").and_then(Json::as_str) else {
            continue;
        };
        let class = case["class"].as_str().unwrap();
        let value = decoded(body);
        let rule = body_rule(class);
        match case.get("error").and_then(Json::as_str) {
            None | Some("claim-body-digest") => {
                k.validate(rule, &value)
                    .unwrap_or_else(|e| panic!("{}: {e}", case["id"]));
                k.validate(
                    "claim-body-binding",
                    &Value::Array(vec![Value::text(class), value]),
                )
                .unwrap();
                accepted += 1;
            }
            Some(_) => {
                assert!(k.validate(rule, &value).is_err(), "{}", case["id"]);
                refused += 1;
            }
        }
    }
    assert!(accepted >= 11 && refused >= 3);
}

// L2-RPT-1: every report the Kernel decodes is a CDDL report
#[test]
fn report_vectors_meet_the_cddl() {
    let k = kernel();
    let doc = vectors("report.json");
    let mut seen = 0;
    for case in doc["cases"].as_array().unwrap() {
        if case.get("error").and_then(Json::as_str) == Some("report-malformed") {
            continue;
        }
        k.validate(
            "offline-exercise-report",
            &decoded(case["report"].as_str().unwrap()),
        )
        .unwrap_or_else(|e| panic!("{}: {e}", case["id"]));
        seen += 1;
    }
    assert!(seen >= 9);
}

// L2-AAS-1: every statement the Kernel accepts is a CDDL approval-act-statement
#[test]
fn aas_vectors_meet_the_cddl() {
    let k = kernel();
    let doc = vectors("aas.json");
    let mut seen = 0;
    for case in doc["cases"].as_array().unwrap() {
        if case.get("digest").is_some() {
            k.validate(
                "approval-act-statement",
                &sign1_payload(case["sign1"].as_str().unwrap()),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", case["id"]));
            seen += 1;
        }
    }
    assert!(seen >= 3);
}

// L2-STL-1, L2-STL-2: references and list tokens meet the CDDL
#[test]
fn status_list_vectors_meet_the_cddl() {
    let k = kernel();
    let doc = vectors("status-list.json");
    for case in doc["cases"].as_array().unwrap() {
        k.validate("status-ref", &decoded(case["reference"].as_str().unwrap()))
            .unwrap();
        let token = decoded(case["token"].as_str().unwrap());
        let malformed = case.get("error").and_then(Json::as_str) == Some("status-malformed");
        assert_eq!(
            k.validate("status-list-cwt", &token).is_ok(),
            !malformed,
            "{}",
            case["id"]
        );
    }
}

// L2-CLM-5: the unsigned Claims the Kernel reads are CDDL unsigned-claims
#[test]
fn unsigned_claim_vectors_meet_the_cddl() {
    let k = kernel();
    let doc = vectors("claim-unsigned.json");
    let mut seen = 0;
    for case in doc["cases"].as_array().unwrap() {
        let value = decoded(case["claim"].as_str().unwrap());
        let valid = k.validate("unsigned-claim", &value).is_ok();
        if case.get("claim_id").is_some() {
            assert!(valid, "{}", case["id"]);
            seen += 1;
        }
        if case["id"] == "two-channels" {
            assert!(!valid);
        }
    }
    assert!(seen >= 2);
}

// L2-STL-1, OP-150 m.3 (a): a contract that names its status entry is a CDDL contract
#[test]
fn validity_vectors_meet_the_cddl() {
    let k = kernel();
    let doc = vectors("validity.json");
    k.validate(
        "validity-contract",
        &decoded(doc["contract"].as_str().unwrap()),
    )
    .unwrap();
    let mut with_status = 0;
    for case in doc["cases"].as_array().unwrap() {
        let Some(c) = case.get("contract").and_then(Json::as_str) else {
            continue;
        };
        let v = decoded(c);
        let Value::Map(m) = &v else { continue };
        if m.iter().any(|(key, _)| *key == Value::text("status")) {
            k.validate("validity-contract", &v).unwrap();
            with_status += 1;
        }
    }
    assert!(with_status >= 1);
}
