//! The committed `OpenAPI` document and examples under `sdks/openapi/` are what the code
//! produces (OP-65), and every example validates against the document's schemas.
//! `ACCESS_UPDATE_CONTRACTS=1` rewrites them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_identity_ui::domain::flow::{FlowId, Requirement, SecondFactors, Ui};
use access_identity_ui::domain::message::{Message, TextId};
use access_identity_ui::domain::node::{CreateMediation, PasskeyOptions, PasskeySignal};
use access_identity_ui::domain::schema::openapi;
use access_identity_ui::domain::submission::Submission;
use serde_json::{Value, json};

mod support;

use support::{check_file, pretty, root, validate};

const RP_ID: &str = "acme.localhost";
const CHALLENGE: &str = "c2lnbi1pbi1jaGFsbGVuZ2UtZXhhbXBsZS0wMDAwMDA";
const USER_ID: &str =
    "dXNlci1oYW5kbGUtZXhhbXBsZS0wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMA";
const POLICY: [Requirement; 1] = [Requirement::SecondFactor];

fn flow() -> FlowId {
    FlowId::parse("lgf_example").unwrap()
}

fn request_options(allow: &[&str]) -> PasskeyOptions {
    let allow: Vec<Value> = allow
        .iter()
        .map(|id| json!({ "type": "public-key", "id": id, "transports": ["internal", "hybrid"] }))
        .collect();
    PasskeyOptions::new(json!({
        "challenge": CHALLENGE,
        "rpId": RP_ID,
        "allowCredentials": allow,
        "userVerification": "preferred",
        "timeout": 300_000,
    }))
    .unwrap()
}

fn creation_options(conditional: bool) -> PasskeyOptions {
    PasskeyOptions::new(json!({
        "rp": { "id": RP_ID, "name": "Acme" },
        "user": { "id": USER_ID, "name": "ada@example.org", "displayName": "Ada" },
        "challenge": CHALLENGE,
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -8 },
        ],
        "timeout": 300_000,
        "excludeCredentials": [],
        "authenticatorSelection": { "residentKey": "required", "userVerification": "preferred" },
        "attestation": "none",
        "extensions": { "credProps": true },
        "hints": if conditional { json!([]) } else { json!(["client-device"]) },
    }))
    .unwrap()
}

fn examples() -> Vec<(&'static str, Ui)> {
    let identifier = Ui::identifier(flow(), request_options(&[]), &POLICY);
    let authenticate = Ui::authenticate(
        flow(),
        "ada@example.org",
        request_options(&["Y3JlZC1hZGEtMDE"]),
        &POLICY,
    );
    let mfa = SecondFactors {
        totp: true,
        recovery_code: true,
    };
    vec![
        ("identifier", identifier.clone()),
        (
            "identifier-passkey-failed",
            identifier
                .login_failed()
                .with_signal(PasskeySignal::UnknownCredential {
                    rp_id: RP_ID.into(),
                    credential_id: "dW5rbm93bi1jcmVkZW50aWFs".into(),
                })
                .unwrap(),
        ),
        ("authenticate", authenticate.clone()),
        ("authenticate-failed", authenticate.clone().login_failed()),
        (
            "authenticate-throttled",
            authenticate
                .with_message(Message::error(TextId::TooManyAttempts).retry_after(30))
                .unwrap(),
        ),
        ("second-factor", Ui::second_factor(flow(), mfa, &POLICY)),
        (
            "second-factor-failed",
            Ui::second_factor(flow(), mfa, &POLICY)
                .with_message(Message::error(TextId::SecondFactorFailed))
                .unwrap(),
        ),
        (
            "complete",
            Ui::complete(flow(), "/callback?state=example".into(), &POLICY)
                .with_signal(PasskeySignal::AllAcceptedCredentials {
                    rp_id: RP_ID.into(),
                    user_id: USER_ID.into(),
                    all_accepted_credential_ids: vec!["Y3JlZC1hZGEtMDE".into()],
                })
                .unwrap()
                .with_signal(PasskeySignal::CurrentUserDetails {
                    rp_id: RP_ID.into(),
                    user_id: USER_ID.into(),
                    name: "ada@example.org".into(),
                    display_name: "Ada".into(),
                })
                .unwrap()
                .with_passkey_create(CreateMediation::Conditional, creation_options(true))
                .unwrap(),
        ),
        (
            "complete-passkey-offer",
            Ui::complete(flow(), "/callback?state=example".into(), &POLICY)
                .with_passkey_create(CreateMediation::Explicit, creation_options(false))
                .unwrap(),
        ),
    ]
}

// OP-65, TN-106
#[test]
fn committed_openapi_matches_the_code() {
    check_file(&root().join("login.json"), &pretty(&openapi()));
}

// OP-65, TN-106, TN-132
#[test]
fn committed_examples_match_the_code_and_the_schema() {
    let doc = openapi();
    for (name, ui) in examples() {
        let value = serde_json::to_value(&ui).unwrap();
        validate(
            &doc,
            &json!({ "$ref": "#/components/schemas/LoginUi" }),
            &value,
            name,
        );
        let back: Ui = serde_json::from_value(value).unwrap();
        assert_eq!(back, ui, "{name}");
        check_file(
            &root().join("examples/login").join(format!("{name}.json")),
            &pretty(&ui),
        );
    }
}

// TN-106
#[test]
fn submissions_validate_against_the_schema() {
    let doc = openapi();
    let body = json!({ "method": "password", "fields": { "password": "correct horse" } });
    validate(
        &doc,
        &json!({ "$ref": "#/components/schemas/LoginSubmission" }),
        &body,
        "submission",
    );
    let _: Submission = serde_json::from_value(body).unwrap();
}

// X27, §8.11, TN-105
#[test]
fn the_contract_has_no_scope_list_consent_button_or_script() {
    fn words(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                for (k, v) in map {
                    if k != "description" && k != "summary" {
                        out.push(k.to_lowercase());
                        words(v, out);
                    }
                }
            }
            Value::Array(list) => list.iter().for_each(|v| words(v, out)),
            Value::String(s) => out.push(s.to_lowercase()),
            _ => {}
        }
    }
    let mut all = Vec::new();
    words(&openapi()["components"], &mut all);
    for (_, ui) in examples() {
        words(&serde_json::to_value(ui).unwrap(), &mut all);
    }
    for banned in [
        "scope",
        "authorize",
        "script",
        "html",
        "expression",
        "template",
    ] {
        assert!(!all.iter().any(|w| w.contains(banned)), "{banned}");
    }
}
