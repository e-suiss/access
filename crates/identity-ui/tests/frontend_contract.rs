//! The committed Frontend API document for products (`sdks/openapi/frontend.json`) and its
//! examples are what the code produces (OP-65, OP-149 m.6, m.8, m.9), and every example meets
//! the document's schemas and reads back into its wire type. `ACCESS_UPDATE_CONTRACTS=1`
//! rewrites them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_identity_ui::domain::frontend::{
    AUTH_CONTEXT_PATH, AuthContextIssued, AuthContextRequest, CHALLENGES_PATH, INSTANCE_PATH,
    INSTANCES_PATH, InstanceChallenge, InstanceRegistered, InstanceRegistration,
    InstanceTerminated, InstanceTermination, openapi, rfc3339,
};
use access_kernel::json::b64url_encode;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

mod support;

use support::{check_file, pretty, root, validate};

fn b64(byte: u8, len: usize) -> String {
    b64url_encode(&vec![byte; len])
}

fn example<T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug>(
    doc: &Value,
    schema: &str,
    name: &str,
    value: &T,
) {
    let json = serde_json::to_value(value).unwrap();
    validate(
        doc,
        &json!({ "$ref": format!("#/components/schemas/{schema}") }),
        &json,
        name,
    );
    let back: T = serde_json::from_value(json).unwrap();
    assert_eq!(&back, value, "{name}");
    check_file(
        &root()
            .join("examples/frontend")
            .join(format!("{name}.json")),
        &pretty(value),
    );
}

// OP-65, OP-149 m.6, m.8, m.9
#[test]
fn committed_openapi_matches_the_code() {
    check_file(&root().join("frontend.json"), &pretty(&openapi()));
}

// OP-149 m.6, m.8, m.9: the contract names every endpoint the products call
#[test]
fn the_document_has_every_endpoint() {
    let doc = openapi();
    let paths = doc["paths"].as_object().unwrap();
    for (path, method) in [
        (CHALLENGES_PATH, "post"),
        (INSTANCES_PATH, "post"),
        (INSTANCE_PATH, "delete"),
        (AUTH_CONTEXT_PATH, "post"),
        ("/v1/approve", "get"),
    ] {
        assert!(paths[path].get(method).is_some(), "{method} {path}");
    }
    let approve = &paths["/v1/approve"]["get"]["parameters"];
    let names: Vec<&str> = approve
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["request", "redirect_uri", "state"]);
}

// OP-65, OP-149 m.6, m.8: the examples meet the schemas and read back unchanged
#[test]
fn committed_examples_match_the_code_and_the_schema() {
    let doc = openapi();
    example(
        &doc,
        "InstanceChallenge",
        "instance-challenge",
        &InstanceChallenge {
            challenge: b64(0x11, 32),
            expires_at: rfc3339(1_767_225_300_000),
        },
    );
    example(
        &doc,
        "InstanceRegistration",
        "instance-registration",
        &InstanceRegistration {
            key: b64(0xa4, 77),
            pop: b64(0xd2, 160),
        },
    );
    example(
        &doc,
        "InstanceRegistered",
        "instance-registered",
        &InstanceRegistered {
            instance: String::from("ins_0123456789abcdefghjkmnpqrs"),
            kid: b64(0x22, 32),
        },
    );
    example(
        &doc,
        "InstanceTermination",
        "instance-termination",
        &InstanceTermination {
            nonce: b64(0x33, 16),
            basis: b64(0x44, 16),
            valid_from: rfc3339(1_767_225_000_000),
            valid_until: rfc3339(1_767_225_300_000),
            ais: b64(0xd2, 200),
        },
    );
    example(
        &doc,
        "InstanceTerminated",
        "instance-terminated",
        &InstanceTerminated {
            exercise: b64(0x55, 32),
        },
    );
    example(
        &doc,
        "AuthContextRequest",
        "auth-context-request",
        &AuthContextRequest {
            content_type: String::from("application/vnd.suiss.work.record+cbor"),
            content_digest: b64(0x66, 32),
        },
    );
    example(
        &doc,
        "AuthContextIssued",
        "auth-context-issued",
        &AuthContextIssued {
            auth_context: b64(0xd2, 240),
            digest: b64(0x77, 32),
        },
    );
}

// OP-149 m.6: a registration names nothing but the key and its proof
#[test]
fn unknown_fields_are_refused() {
    let extra = json!({ "key": "a", "pop": "b", "party": "c" });
    assert!(serde_json::from_value::<InstanceRegistration>(extra).is_err());
}
