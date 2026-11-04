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
