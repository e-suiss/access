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

// OP-149 m.9, XI-7, E44
#[test]
fn authority_request_examples_meet_both_schemas() {
    check_examples("authority-request.json");
}

// OP-149 m.9, E32
#[test]
fn approval_act_statement_examples_meet_the_cddl() {
    check_examples("approval-act-statement.json");
}

// OP-158 m.3 (c), T16
#[test]
fn checkpoint_claim_examples_meet_the_cddl() {
    check_examples("checkpoint-claim.json");
}

// OP-158 m.3 (c), CMP-6
#[test]
fn checkpoint_body_examples_meet_the_cddl() {
    check_examples("checkpoint-body.json");
}

// OP-158 m.3 (d), U11
#[test]
fn witness_cosign_examples_meet_the_cddl() {
    check_examples("witness.json");
}

// OP-158 m.3 (d), U9, HL-7
#[test]
fn equivocation_examples_meet_the_cddl() {
    check_examples("equivocation.json");
}

// OP-158 m.3 (b), P18, SEC25
#[test]
fn inclusion_bundle_examples_meet_the_cddl() {
    check_examples("inclusion-bundle.json");
}

// OP-158 m.3 (f), T21
#[test]
fn mirror_frame_examples_meet_the_cddl() {
    check_examples("mirror.json");
}

// OP-158 m.3 (e), TI-13
#[test]
fn replica_ack_examples_meet_the_cddl() {
    check_examples("replica-ack.json");
}

// OP-158 m.3 (g), AP-14
#[test]
fn export_frame_examples_meet_the_cddl() {
    check_examples("export.json");
}

// OP-158 m.3 (l), U27
#[test]
fn handover_statement_examples_meet_the_cddl() {
    check_examples("handover.json");
}

// OP-158 m.3 (i), TI-RT1, G32
#[test]
fn divergence_set_examples_meet_the_cddl() {
    check_examples("divergence.json");
}

// OP-158 m.3 (i), TI-RT4
#[test]
fn snapshot_examples_meet_the_cddl() {
    check_examples("snapshot.json");
}

// OP-158 m.3 (o), CMP-26
#[test]
fn placement_examples_meet_the_cddl() {
    check_examples("placement.json");
}

// OP-158 m.3 (q), OP-56
#[test]
fn compatibility_manifest_examples_meet_the_cddl() {
    check_examples("upgrade.json");
}

// §9.9, OP-150 m.2
#[test]
fn token_exercise_examples_meet_the_cddl() {
    check_examples("token-exercise.json");
}

// L0-META-30, §9.14.1 step 4, OP-149 m.9, m.29 (b), m.33 (b)
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

// OP-149 m.3, CR-58 m.3
#[test]
fn suiss_discovery_examples_meet_the_cddl() {
    check_examples("suiss-discovery.json");
}

// OP-149 m.8
#[test]
fn auth_context_examples_meet_the_cddl() {
    check_examples("auth-context.json");
}

// OP-153 m.3 (b), (c), (o), (q), L2-CLB-1
#[test]
fn identity_claim_examples_meet_the_cddl() {
    check_examples("identity-claims.json");
}

// OP-149 m.5, OP-149 m.8, CR-24
#[test]
fn key_lookup_examples_meet_the_cddl() {
    check_examples("key-lookup.json");
}

// OP-149 m.28 (c), m.8
#[test]
fn party_lookup_examples_meet_the_cddl() {
    check_examples("party-lookup.json");
}

// OP-155 m.3 (c), (d), U43, IDI-8
#[test]
fn parser_worker_examples_meet_the_cddl() {
    check_examples("parser-worker-request.json");
    check_examples("parser-worker-response.json");
}

// OP-155 m.3 (c), IDI-11, IDP-26
#[test]
fn edge_channel_examples_meet_the_cddl() {
    check_examples("edge-channel-request.json");
    check_examples("edge-channel-response.json");
}

// OP-156 m.3 (b), (f), (k), (r), (t), (u), L2-CLB-1
#[test]
fn product_seam_claim_examples_meet_the_cddl() {
    check_examples("product-seam.json");
}

// OP-156 m.3 (d), (e), IDP-4, TN-100
#[test]
fn push_answer_examples_meet_the_cddl() {
    check_examples("push-answer.json");
}

// OP-156 m.3 (j), OP-138
#[test]
fn doorbell_examples_meet_the_cddl() {
    check_examples("doorbell.json");
}

// OP-156 m.3 (p), IDP-32
#[test]
fn linux_client_examples_meet_the_cddl() {
    check_examples("linux-client-request.json");
    check_examples("linux-client-response.json");
}

// OP-156 m.3 (l), IDP-30
#[test]
fn proxy_examples_meet_the_cddl() {
    check_examples("proxy-decision.json");
    check_examples("app-token-claims.json");
}

// OP-156 m.3 (o), IDP-32
#[test]
fn ssh_cert_examples_meet_the_cddl() {
    check_examples("ssh-cert.json");
}

// OP-156 m.3 (z), E58
#[test]
fn first_contact_examples_meet_the_cddl() {
    check_examples("first-contact-request.json");
    check_examples("first-contact-token.json");
}

// OP-157 m.3 (b), (r), §9.13.4, INV-8
#[test]
fn compat_mapping_examples_are_the_kernels() {
    use access_kernel::codec::Canonical;
    use access_kernel::compat::Mapping;
    check_examples("compat-mapping.json");
    let doc: Json = serde_json::from_str(&read("cddl/examples/compat-mapping.json")).unwrap();
    for case in doc["cases"].as_array().unwrap() {
        let value = value_sorted(&edn::parse(case["edn"].as_str().unwrap()));
        assert_eq!(
            Mapping::from_value(&value).is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}: the Kernel and the CDDL disagree",
            case["id"]
        );
    }
}

// OP-157 m.3 (j), OP-46, G63
#[test]
fn breakglass_directive_examples_meet_the_cddl() {
    check_examples("breakglass-directive.json");
    check_examples("breakglass-trail.json");
}

// OP-157 m.3 (x), CR-29
#[test]
fn ceremony_examples_meet_the_cddl() {
    check_examples("ceremony-permit.json");
    check_examples("ceremony-transcript.json");
}

// OP-157 m.3 (m), SEC26
#[test]
fn approval_inline_examples_meet_the_cddl() {
    check_examples("approval-inline.json");
}

// OP-157 m.3 (s), P2
#[test]
fn conformance_profile_examples_meet_both_schemas() {
    check_examples("conformance-profile.json");
}

// IDP-40, F23, OP-155 m.3 (q)
#[test]
fn interop_profile_examples_meet_both_schemas() {
    check_examples("interop-profile.json");
}

// IDP-23, OP-155 m.3 (g)
#[test]
fn scim_set_examples_meet_the_cddl() {
    check_examples("scim-set.json");
}

// E43, TI-20, OP-141 m.38
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

// OP-149 m.28 (e), OP-118 m.3
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
    assert_eq!(accepted, 2 * 3 + 7 * 2 + 3);
    let (_, empty) = assurance_explanation("aal", 1);
    let mut empty = empty;
    empty["unmet"][0]["term"]["assurance"] = serde_json::json!({});
    assert!(!schema.errors(&empty).is_empty(), "an empty assurance map");
}

// E43, OP-114 m.2, OP-114 m.3, OP-141 m.38, OP-149 m.25 (a), m.33 (a)
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

// E43, OP-111 m.1, OP-149 m.33 (a)
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

// OP-149 m.8
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

// L2-RCP-1, OP-149 m.11
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

// OP-149 m.6, m.8, L0-META-1
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
        "identity_binding_workload" => "workload-binding",
        c if c.starts_with("identity_binding_") => "identity-binding",
        "effect_attestation" => "effect-attestation",
        "executor_control" => "executor-control",
        other => panic!("no body rule for {other}"),
    }
}

// L2-CLB-1, L2-CLB-3, OP-150 m.2
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

// L2-RPT-1
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

// L2-AAS-1
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

// L2-STL-1, L2-STL-2
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

// L2-CLM-5
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

// L2-STL-1, OP-150 m.3 (a)
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

// OP-159 m.3 (g), CR-45 RA-2, RA-3
#[test]
fn pq_checkpoint_examples_meet_the_cddl() {
    check_examples("pq-checkpoint.json");
}

// OP-159 m.3 (h), CR-45 RA-7
#[test]
fn pq_anchor_examples_meet_the_cddl() {
    check_examples("pq-anchor.json");
}

// OP-159 m.3 (q), CR-43
#[test]
fn projection_ref_examples_meet_the_cddl() {
    check_examples("projection-ref.json");
}

// OP-159 m.3 (i), P18, SEC25
#[test]
fn inclusion_evidence_examples_meet_the_cddl() {
    check_examples("inclusion-evidence.json");
}

// OP-159 m.3 (b), (h), (j)
#[test]
fn the_kernels_stage_14_values_meet_the_cddl() {
    use access_kernel::codec::Canonical as _;
    use access_kernel::meta::{AnchorScope, Payload, Root, RootSets};
    use access_kernel::verify::cose::{Algorithm, PublicKey};
    use access_kernel::verify::key_scope::{Witness, thumbprint};
    use access_kernel::verify::pq::{PqAlgorithm, PqAnchor};
    let public = |alg: PqAlgorithm| -> Vec<u8> {
        (0..alg.public_key_len())
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect()
    };
    let witness = Witness::new(
        "witness.example".into(),
        PublicKey::MlDsa(Algorithm::MlDsa44, public(PqAlgorithm::MlDsa44)),
        Algorithm::MlDsa44,
        "northwind".into(),
        true,
    );
    let key = PublicKey::MlDsa(Algorithm::MlDsa65, public(PqAlgorithm::MlDsa65));
    let anchor = PqAnchor::new(
        access_kernel::digest::Digest([3; 32]),
        thumbprint(&key),
        key,
        vec![witness.clone()],
        1_767_225_000_000,
    );
    let pq = Cddl::new(&[&read("cddl/kernel.cddl"), &read("cddl/pq-anchor.cddl")]);
    pq.validate("pq-anchor", &anchor.to_value()).unwrap();
    let create = Payload::AnchorCreate {
        scope: AnchorScope::Domain,
        root: Root::Sole(access_kernel::model::Id([1; 16])),
        root_terms: std::collections::BTreeSet::new(),
        sets: RootSets::new(vec![witness], Vec::new()),
    };
    kernel().validate("meta-payload", &create.to_value()).unwrap();
}
