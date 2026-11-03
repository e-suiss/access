//! The committed `OpenAPI` document and examples under `sdks/openapi/` are what the code
//! produces (OP-65), and every example validates against the document's schemas.
//! `ACCESS_UPDATE_CONTRACTS=1` rewrites them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;

use access_identity_ui::domain::flow::{FlowId, Requirement, SecondFactors, Ui};
use access_identity_ui::domain::message::{Message, TextId};
use access_identity_ui::domain::node::{CreateMediation, PasskeyOptions, PasskeySignal};
use access_identity_ui::domain::schema::openapi;
use access_identity_ui::domain::submission::Submission;
use serde_json::{Value, json};

const RP_ID: &str = "acme.localhost";
const CHALLENGE: &str = "c2lnbi1pbi1jaGFsbGVuZ2UtZXhhbXBsZS0wMDAwMDA";
const USER_ID: &str =
    "dXNlci1oYW5kbGUtZXhhbXBsZS0wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMA";
const POLICY: [Requirement; 1] = [Requirement::SecondFactor];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi")
}

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

fn pretty(v: &impl serde::Serialize) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap();
    s.push('\n');
    s
}

fn check_file(path: &PathBuf, expected: &str) {
    if std::env::var_os("ACCESS_UPDATE_CONTRACTS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, expected).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        committed == expected,
        "{} is stale; run ACCESS_UPDATE_CONTRACTS=1 cargo test -p access-identity-ui --test contract",
        path.display()
    );
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

fn resolve<'a>(doc: &'a Value, schema: &'a Value) -> &'a Value {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(r) => {
            let name = r.trim_start_matches("#/components/schemas/");
            resolve(doc, &doc["components"]["schemas"][name])
        }
        None => schema,
    }
}

fn errors(doc: &Value, schema: &Value, value: &Value, at: &str) -> Vec<String> {
    let schema = resolve(doc, schema);
    let mut out = Vec::new();
    if let Some(c) = schema.get("const")
        && c != value
    {
        out.push(format!("{at}: expected {c}"));
    }
    if let Some(e) = schema.get("enum").and_then(Value::as_array)
        && !e.contains(value)
    {
        out.push(format!("{at}: {value} not in enum"));
    }
    if let Some(alts) = schema.get("oneOf").and_then(Value::as_array) {
        let ok = alts
            .iter()
            .filter(|a| errors(doc, a, value, at).is_empty())
            .count();
        if ok != 1 {
            out.push(format!("{at}: {ok} oneOf branches match"));
        }
    }
    let ty = schema.get("type").and_then(Value::as_str);
    let type_ok = match ty {
        Some("object") => value.is_object(),
        Some("string") => value.is_string(),
        Some("integer") => value.is_u64() || value.is_i64(),
        Some("boolean") => value.is_boolean(),
        Some("array") => value.is_array(),
        _ => true,
    };
    if !type_ok {
        out.push(format!("{at}: not {}", ty.unwrap_or_default()));
        return out;
    }
    if let Some(items) = schema.get("items")
        && let Some(list) = value.as_array()
    {
        for (i, v) in list.iter().enumerate() {
            out.extend(errors(doc, items, v, &format!("{at}[{i}]")));
        }
    }
    if let Some(obj) = value.as_object() {
        for req in schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if !obj.contains_key(req.as_str().unwrap()) {
                out.push(format!("{at}: missing {req}"));
            }
        }
        let props = schema.get("properties").and_then(Value::as_object);
        for (k, v) in obj {
            if let Some(names) = schema.get("propertyNames") {
                out.extend(errors(doc, names, &Value::String(k.clone()), at));
            }
            match (
                props.and_then(|p| p.get(k)),
                schema.get("additionalProperties"),
            ) {
                (Some(s), _) => out.extend(errors(doc, s, v, &format!("{at}.{k}"))),
                (None, Some(Value::Bool(false))) => out.push(format!("{at}: unexpected {k}")),
                (None, Some(extra)) if extra.is_object() => {
                    out.extend(errors(doc, extra, v, &format!("{at}.{k}")));
                }
                _ => {}
            }
        }
    }
    out
}

fn validate(doc: &Value, schema: &Value, value: &Value, name: &str) {
    let errs = errors(doc, schema, value, name);
    assert!(errs.is_empty(), "{errs:#?}");
}
