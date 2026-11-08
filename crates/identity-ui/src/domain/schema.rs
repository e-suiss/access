//! The node contract as an `OpenAPI` 3.1 document (JSON Schema 2020-12 components), generated
//! from code and committed under `sdks/openapi/` (OP-65, TN-112).

use serde_json::{Map, Value, json};

use super::flow::{CONTRACT_VERSION, FLOWS_PATH};
use super::message::TextId;
use super::node::{FieldName, Method};

pub(crate) fn r(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

pub(crate) fn object(properties: &Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

pub(crate) fn string_enum(values: &[&str]) -> Value {
    json!({ "type": "string", "enum": values })
}

fn variant(tag_name: &str, tag: &str, properties: &Value, required: &[&str]) -> Value {
    let mut props = Map::new();
    props.insert(tag_name.to_owned(), json!({ "const": tag }));
    if let Some(p) = properties.as_object() {
        props.extend(p.clone());
    }
    let mut req = vec![tag_name];
    req.extend_from_slice(required);
    object(&Value::Object(props), &req)
}

fn text_ids() -> Vec<&'static str> {
    TextId::ALL.iter().map(|t| t.as_str()).collect()
}

fn node() -> Value {
    let input = variant(
        "type",
        "input",
        &json!({
            "name": r("FieldName"),
            "method": r("Method"),
            "kind": string_enum(&["text", "password", "code", "hidden"]),
            "autocomplete": string_enum(&["username webauthn", "username", "current-password", "one-time-code", "off", "new-password", "email", "name"]),
            "required": { "type": "boolean" },
            "max_length": { "type": "integer", "minimum": 1 },
            "label": r("Text"),
            "value": { "type": "string" },
            "read_only": { "type": "boolean" },
        }),
        &[
            "name",
            "method",
            "kind",
            "autocomplete",
            "required",
            "max_length",
            "label",
        ],
    );
    let submit = variant(
        "type",
        "submit",
        &json!({ "method": r("Method"), "label": r("Text") }),
        &["method", "label"],
    );
    let passkey_get = variant(
        "type",
        "passkey_get",
        &json!({ "label": r("Text"), "options": r("PasskeyOptions") }),
        &["label", "options"],
    );
    let passkey_autofill = variant(
        "type",
        "passkey_autofill",
        &json!({ "field": r("FieldName"), "options": r("PasskeyOptions") }),
        &["field", "options"],
    );
    let passkey_create = variant(
        "type",
        "passkey_create",
        &json!({
            "mediation": string_enum(&["explicit", "conditional"]),
            "label": r("Text"),
            "options": r("PasskeyOptions"),
        }),
        &["mediation", "label", "options"],
    );
    let passkey_signal = variant(
        "type",
        "passkey_signal",
        &json!({ "signal": r("PasskeySignal") }),
        &["signal"],
    );
    let option = variant(
        "type",
        "option",
        &json!({ "name": r("FieldName"), "label": r("Text"), "checked": { "type": "boolean" } }),
        &["name", "label", "checked"],
    );
    let provider = variant(
        "type",
        "provider",
        &json!({
            "provider": { "type": "string" },
            "label": r("Text"),
            "href": { "type": "string", "pattern": "^/" },
        }),
        &["provider", "label", "href"],
    );
    json!({ "oneOf": [
        input,
        submit,
        passkey_get,
        passkey_autofill,
        passkey_create,
        passkey_signal,
        option,
        provider,
    ] })
}

fn signal() -> Value {
    let s = json!({ "type": "string" });
    json!({
        "oneOf": [
            variant("kind", "unknown_credential", &json!({ "rp_id": s, "credential_id": s }), &["rp_id", "credential_id"]),
            variant(
                "kind",
                "all_accepted_credentials",
                &json!({ "rp_id": s, "user_id": s, "all_accepted_credential_ids": { "type": "array", "items": s } }),
                &["rp_id", "user_id", "all_accepted_credential_ids"],
            ),
            variant(
                "kind",
                "current_user_details",
                &json!({ "rp_id": s, "user_id": s, "name": s, "display_name": s }),
                &["rp_id", "user_id", "name", "display_name"],
            ),
        ]
    })
}

fn components() -> Value {
    let field_names: Vec<&str> = FieldName::ALL.iter().map(|f| f.as_str()).collect();
    let methods: Vec<&str> = Method::ALL.iter().map(|m| m.as_str()).collect();
    let s = json!({ "type": "string" });
    let options = json!({
        "type": "object",
        "description": "WebAuthn options in their JSON form (parseRequestOptionsFromJSON / parseCreationOptionsFromJSON).",
    });
    json!({
        "LoginUi": object(
            &json!({
                "version": { "const": CONTRACT_VERSION },
                "flow": r("FlowId"),
                "kind": string_enum(&[
                    "login",
                    "registration",
                    "recovery",
                    "settings",
                    "consent",
                    "invitation",
                    "link",
                ]),
                "step": string_enum(&["identifier", "authenticate", "second_factor", "complete"]),
                "action": { "type": "string" },
                "requirements": { "type": "array", "items": r("RequirementStatus") },
                "nodes": { "type": "array", "items": r("Node") },
                "messages": { "type": "array", "items": r("Message") },
                "redirect_to": { "type": "string" },
            }),
            &["version", "flow", "step", "action", "requirements", "nodes", "messages"],
        ),
        "FlowId": { "type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$" },
        "RequirementStatus": object(
            &json!({
                "requirement": string_enum(&["identifier", "first_factor", "second_factor"]),
                "state": string_enum(&["missing", "satisfied"]),
            }),
            &["requirement", "state"],
        ),
        "Node": node(),
        "FieldName": string_enum(&field_names),
        "Method": string_enum(&methods),
        "TextId": string_enum(&text_ids()),
        "Text": object(&json!({ "id": r("TextId"), "text": s }), &["id", "text"]),
        "Message": object(
            &json!({
                "id": r("TextId"),
                "text": s,
                "severity": string_enum(&["info", "error"]),
                "retry_after_s": { "type": "integer", "minimum": 0 },
            }),
            &["id", "text", "severity"],
        ),
        "PasskeyOptions": options,
        "PasskeySignal": signal(),
        "LoginSubmission": object(
            &json!({
                "method": r("Method"),
                "fields": {
                    "type": "object",
                    "propertyNames": r("FieldName"),
                    "additionalProperties": s,
                },
            }),
            &["method"],
        ),
        "Problem": {
            "type": "object",
            "required": ["type", "title", "status"],
            "properties": {
                "type": s,
                "title": s,
                "status": { "type": "integer" },
                "detail": s,
            },
        },
    })
}

fn ui_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": { "application/json": { "schema": r("LoginUi") } },
    })
}

fn problem_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": { "application/problem+json": { "schema": r("Problem") } },
    })
}

/// The `OpenAPI` document of the login node contract.
#[must_use]
pub fn openapi() -> Value {
    let flow_path = format!("{FLOWS_PATH}/{{flow}}");
    let flow_param = json!({
        "name": "flow",
        "in": "path",
        "required": true,
        "schema": r("FlowId"),
    });
    let idempotency = json!({
        "name": "Idempotency-Key",
        "in": "header",
        "required": true,
        "schema": { "type": "string", "maxLength": 255 },
    });
    let mut paths = Map::new();
    paths.insert(
        FLOWS_PATH.to_owned(),
        json!({
            "post": {
                "operationId": "createLoginFlow",
                "summary": "Start a login flow; answers the identifier step (TN-96).",
                "parameters": [idempotency],
                "responses": {
                    "201": ui_response("The identifier step."),
                    "429": problem_response("Too many flows from this network."),
                    "503": problem_response("Temporarily unavailable (OP-36)."),
                },
            },
        }),
    );
    paths.insert(
        flow_path,
        json!({
            "parameters": [flow_param],
            "get": {
                "operationId": "getLoginFlow",
                "summary": "The flow's current step.",
                "responses": {
                    "200": ui_response("The current step."),
                    "410": problem_response("The flow expired or was used up; start a new one."),
                },
            },
            "post": {
                "operationId": "submitLoginFlow",
                "summary": "Submit one method of the current step (TN-106: fields the step did not offer are refused).",
                "parameters": [idempotency],
                "requestBody": {
                    "required": true,
                    "content": { "application/json": { "schema": r("LoginSubmission") } },
                },
                "responses": {
                    "200": ui_response("The next step, or the same step with messages."),
                    "400": problem_response("The submission does not match the step."),
                    "401": ui_response("The same step with the one neutral refusal, identical for every account (CR-40)."),
                    "410": problem_response("The flow expired or was used up; start a new one."),
                    "429": ui_response("The same step with `login.throttled`; the same for every identifier."),
                    "503": problem_response("Temporarily unavailable (OP-36)."),
                },
            },
        }),
    );
    json!({
        "openapi": "3.1.1",
        "info": {
            "title": "Access Frontend API: login node contract",
            "version": format!("{CONTRACT_VERSION}"),
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
        },
        "paths": paths,
        "components": { "schemas": components() },
    })
}
