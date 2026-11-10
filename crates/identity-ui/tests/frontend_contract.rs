//! The committed Frontend API document for products (`sdks/openapi/frontend.json`) and its
//! examples are what the code produces (OP-65, OP-149 m.6, m.8, m.9), and every example meets
//! the document's schemas and reads back into its wire type. `ACCESS_UPDATE_CONTRACTS=1`
//! rewrites them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_identity_ui::domain::approval::{
    APP_PATH, ApprovalFinish, ApprovalFinished, ApprovalPush, ApprovalPushed, ApprovalStart,
    ApprovalStarted, BasisRef, ContributionEnvelope, FLOW_PATH, FLOWS_PATH, FieldView,
    REQUESTS_PATH, RenderView,
};
use access_identity_ui::domain::frontend::{
    AUTH_CONTEXT_PATH, AuthContextIssued, AuthContextRequest, BINDINGS_PATH, CHALLENGES_PATH,
    INSTANCE_PATH, INSTANCES_PATH, InstanceBinding, InstanceChallenge, InstanceRegistered,
    InstanceRegistration, InstanceTerminated, InstanceTermination, openapi, rfc3339,
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

// OP-149 m.6, m.8, m.9
#[test]
fn the_document_has_every_endpoint() {
    let doc = openapi();
    let paths = doc["paths"].as_object().unwrap();
    for (path, method) in [
        (CHALLENGES_PATH, "post"),
        (INSTANCES_PATH, "post"),
        (BINDINGS_PATH, "post"),
        (INSTANCE_PATH, "delete"),
        (AUTH_CONTEXT_PATH, "post"),
        ("/v1/approve", "get"),
        (REQUESTS_PATH, "post"),
        (FLOWS_PATH, "post"),
        (FLOW_PATH, "post"),
        (APP_PATH, "get"),
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

// OP-65, OP-149 m.6, m.8, m.16 (a), (f)
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
            domain: b64(0x07, 32),
            basis: b64(0x05, 16),
            pep: String::from("access-identity"),
            party: None,
        },
    );
    example(
        &doc,
        "InstanceRegistration",
        "instance-registration",
        &InstanceRegistration {
            challenge: b64(0x11, 32),
            party: b64(0x08, 16),
            key: b64(0xa4, 77),
            valid_from: rfc3339(1_767_225_000_000),
            valid_until: rfc3339(1_767_225_300_000),
            ais: b64(0xd2, 200),
            register_ais: Some(b64(0xd2, 190)),
        },
    );
    // OP-149 m.32
    example(
        &doc,
        "InstanceBinding",
        "instance-binding",
        &InstanceBinding {
            challenge: b64(0x11, 32),
            key: b64(0xa4, 77),
            pop: b64(0xd2, 120),
        },
    );
    example(
        &doc,
        "InstanceRegistered",
        "instance-registered",
        &InstanceRegistered {
            instance: b64(0x09, 16),
            kid: b64(0x22, 32),
            party: b64(0x08, 16),
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
            content_type: String::from("application/work-record+cbor"),
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

// OP-149 m.6
#[test]
fn unknown_fields_are_refused() {
    let extra = json!({ "key": "a", "pop": "b", "party": "c" });
    assert!(serde_json::from_value::<InstanceRegistration>(extra).is_err());
}

// OP-150 m.3 (r), OP-149 m.9, §9.14.1
#[test]
fn approval_examples_match_the_code_and_the_schema() {
    let doc = openapi();
    example(
        &doc,
        "ApprovalPush",
        "approval-push",
        &ApprovalPush {
            request: json!({
                "requester": { "party": b64(0x01, 16), "instance": b64(0x02, 16) },
                "action": { "namespace": "shop", "name": "refund", "major": 1, "schema": b64(0x01, 32) },
                "resource": { "namespace": "shop", "path": ["orders", "o-1042"], "incarnation": 0 },
                "params": { "amount": { "amount": { "value": 4200, "unit": "eur_cent" } } },
                "capacity": "own",
                "reason": "The customer reported that the parcel arrived damaged.",
                "require_action": { "domain": b64(0x33, 32), "nonce": b64(0x0a, 16), "intent": b64(0x44, 32) },
                "expires_at": 1_767_225_600_000u64,
            }),
            contribution: ContributionEnvelope {
                nonce: b64(0x0b, 16),
                class: None,
                basis: BasisRef::Holding {
                    grant: b64(0x05, 16),
                    holder: b64(0x08, 16),
                    since: 0,
                },
                valid_from: rfc3339(1_767_225_000_000),
                valid_until: rfc3339(1_767_225_300_000),
                ais: b64(0xd2, 180),
                work_gate: None,
            },
        },
    );
    example(
        &doc,
        "ApprovalPushed",
        "approval-pushed",
        &ApprovalPushed {
            request_uri: format!("urn:ietf:params:oauth:request_uri:{}", b64(0x1f, 32)),
            digest: b64(0x2e, 32),
            expires_at: rfc3339(1_767_225_600_000),
        },
    );
    example(
        &doc,
        "ApprovalStart",
        "approval-start",
        &ApprovalStart {
            request: format!("urn:ietf:params:oauth:request_uri:{}", b64(0x1f, 32)),
            redirect_uri: String::from("https://shop.example/approved"),
            state: String::from("st-1"),
        },
    );
    example(
        &doc,
        "ApprovalStarted",
        "approval-started",
        &ApprovalStarted {
            flow: b64(0x3c, 16),
            render: RenderView {
                fields: vec![
                    FieldView {
                        name: String::from("action"),
                        text: String::from("shop/refund@1"),
                        material: true,
                    },
                    FieldView {
                        name: String::from("amount"),
                        text: String::from("4200 eur_cent"),
                        material: true,
                    },
                ],
                reason: String::from("The customer reported that the parcel arrived damaged."),
                tier: 1,
                expires_at: rfc3339(1_767_225_900_000),
            },
            options: json!({
                "challenge": b64(0x4d, 32),
                "rpId": "acme.example",
                "allowCredentials": [{ "type": "public-key", "id": b64(0x6e, 20), "transports": ["internal"] }],
                "userVerification": "preferred",
                "timeout": 300_000,
            }),
        },
    );
    example(
        &doc,
        "ApprovalFinish",
        "approval-finish",
        &ApprovalFinish {
            credential: json!({
                "id": b64(0x6e, 20), "rawId": b64(0x6e, 20), "type": "public-key",
                "response": {
                    "clientDataJSON": b64(0x7f, 120),
                    "authenticatorData": b64(0x80, 37),
                    "signature": b64(0x91, 64),
                    "userHandle": b64(0xa2, 64),
                },
                "clientExtensionResults": {},
            }),
            redirect_uri: String::from("https://shop.example/approved"),
            state: String::from("st-1"),
        },
    );
    example(
        &doc,
        "ApprovalFinished",
        "approval-finished",
        &ApprovalFinished {
            redirect: format!(
                "https://shop.example/approved?exercise={}&render_digest={}&claim={}&state=st-1",
                b64(0xe3, 32),
                b64(0xb4, 32),
                b64(0xc1, 16)
            ),
            exercise: b64(0xe3, 32),
            render_digest: b64(0xb4, 32),
            claim: b64(0xc1, 16),
        },
    );
}
