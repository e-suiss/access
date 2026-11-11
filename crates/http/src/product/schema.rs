//! The product client contract as an `OpenAPI` 3.1 document (JSON Schema 2020-12 components),
//! generated from code and committed as `sdks/openapi/access-v1.json` (OP-65, TN-112, OP-149):
//! the Suiss discovery document (m.3), tenant snapshots (m.4), Instance key lookup (m.5),
//! Party status lookup (m.28 (c)), the eligibility check (m.10), the problem types (m.12),
//! subject resolution (A11), allowed Exercises (m.9) and the platform product routes:
//! pairing (m.4, m.16 (a)) and the platform client's event streams (m.17 (e), (g)), and the
//! Stage 6 entries not served yet (OP-150 m.2).

use serde_json::{Map, Value, json};

use access_authority_core::keys::MAX_KIDS;
use access_authority_core::parties::MAX_PARTIES;

use super::adapters::{COSE_CONTENT_TYPE, EXCERPT_HEADER};
use super::domain::{ACTIVE_MAX_AGE, ENDED_CACHE};
use crate::problem::TYPE_PREFIX;

/// Version of the contract.
pub const VERSION: &str = "1.0.0";

fn r(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

fn object(properties: &Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

fn text(description: &str) -> Value {
    json!({ "type": "string", "description": description })
}

fn key_components() -> Value {
    let b64 =
        |d: &str| json!({ "type": "string", "pattern": "^[A-Za-z0-9_-]+$", "description": d });
    json!({
        "Problem": {
            "type": "object",
            "description": format!("RFC 9457. `type` is `{TYPE_PREFIX}<code>`, or `about:blank` when the status says all."),
            "required": ["type", "title", "status", "code"],
            "properties": {
                "type": text("Problem type URI."),
                "title": text("Short title."),
                "status": { "type": "integer" },
                "code": text("Stable error code (OP-65)."),
                "detail": text("Detail."),
                "reason": text("A stable, non-secret reason narrowing `code`, such as `signer-no-key` on a 503 while no operational key of the domain may sign (SAI-46, CR-23)."),
                "errors": {
                    "type": "array",
                    "description": "The parts of the request a protocol problem is about (RFC 9457 §3); never request values.",
                    "items": {
                        "type": "object",
                        "required": ["code"],
                        "properties": {
                            "pointer": text("A JSON Pointer (RFC 6901) into the request body, as a URI fragment, e.g. `#/set/basis`."),
                            "code": text("Stable code of what is wrong there."),
                        },
                    },
                },
            },
        },
        "Position": { "type": "string", "pattern": "^[0-9]+$", "description": "A ledger position, in decimal." },
        "Time": { "type": "string", "format": "date-time", "description": "RFC 3339, UTC." },
        "DomainId": { "type": "string", "pattern": "^sha-256:[A-Za-z0-9_-]{43}$" },
        "Kid": { "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$", "description": "RFC 7638 SHA-256 thumbprint, unpadded base64url (CR-24)." },
        "LedgerPoint": object(&json!({ "position": r("Position"), "time": r("Time") }), &["position", "time"]),
        "Compromise": object(
            &json!({
                "from": r("Time"),
                "declared_at": r("Time"),
                "source": b64("The party_compromise ClaimID."),
            }),
            &["from", "declared_at", "source"],
        ),
        "KeyEntry": object(
            &json!({
                "kid": r("Kid"),
                "alg": { "type": "integer", "description": "COSE algorithm: -19 Ed25519, -9 ESP256." },
                "public_key": b64("The RFC 9052 COSE_Key, CBOR, base64url."),
                "party": b64("PartyID."),
                "actor_kind": {
                    "type": "string",
                    "enum": ["human", "agent", "system", "machine", "organization"],
                    "description": "The kind the Party's `party_register` recorded; nothing changes it (OP-149 m.8).",
                },
                "instance": b64("InstanceID."),
                "since": r("LedgerPoint"),
                "ended": r("LedgerPoint"),
                "successor": b64("The recovery successor InstanceID."),
                "key_state": { "type": "string", "enum": ["active", "ended", "compromised"] },
                "compromise": r("Compromise"),
            }),
            &["kid", "alg", "public_key", "party", "actor_kind", "instance", "since", "key_state"],
        ),
        "KeyLookup": object(
            &json!({
                "domain": r("DomainId"),
                "position": r("Position"),
                "iat": r("Time"),
                "keys": { "type": "array", "items": r("KeyEntry") },
                "unknown": { "type": "array", "items": r("Kid") },
                "consistency_token": text("Opaque; the head the answer was read at."),
                "witnessed_through": r("Position"),
            }),
            &["domain", "position", "iat", "keys", "unknown", "consistency_token", "witnessed_through"],
        ),
        "KeyBatchRequest": object(
            &json!({
                "domain": r("DomainId"),
                "kids": { "type": "array", "items": r("Kid"), "minItems": 1, "maxItems": MAX_KIDS, "uniqueItems": true },
                "as_of": r("AsOf"),
            }),
            &["domain", "kids"],
        ),
        "AsOf": text("A ledger position in decimal, or an RFC 3339 time."),
    })
}

/// The Party status lookup (OP-149 m.28 (c)), the key lookup's twin.
fn party_components() -> Value {
    json!({
        "PartyId": { "type": "string", "pattern": "^[A-Za-z0-9_-]{22}$", "description": "PartyID, unpadded base64url of its 16 bytes (OP-149 m.16 (f))." },
        "PartyEntry": object(
            &json!({
                "party": r("PartyId"),
                "actor_kind": {
                    "type": "string",
                    "enum": ["human", "agent", "system", "machine", "organization"],
                    "description": "The kind the Party's `party_register` recorded; nothing changes it (OP-149 m.8).",
                },
                "since": r("LedgerPoint"),
                "ended": r("LedgerPoint"),
            }),
            &["party", "actor_kind", "since"],
        ),
        "PartyLookup": object(
            &json!({
                "domain": r("DomainId"),
                "position": r("Position"),
                "iat": r("Time"),
                "parties": { "type": "array", "items": r("PartyEntry") },
                "unknown": { "type": "array", "items": r("PartyId") },
                "consistency_token": text("Opaque; the head the answer was read at."),
                "witnessed_through": r("Position"),
            }),
            &["domain", "position", "iat", "parties", "unknown", "consistency_token", "witnessed_through"],
        ),
        "PartyBatchRequest": object(
            &json!({
                "domain": r("DomainId"),
                "parties": { "type": "array", "items": r("PartyId"), "minItems": 1, "maxItems": MAX_PARTIES, "uniqueItems": true },
                "as_of": r("AsOf"),
            }),
            &["domain", "parties"],
        ),
    })
}

mod developer;
mod eligibility;
mod iys;
mod platform;
mod records;
mod ssf;
mod stage11;
mod stage13;
mod stage6;

fn components() -> Value {
    let mut all = key_components();
    for more in [
        party_components(),
        other_components(),
        records::components(),
        platform::components(),
        crate::declarations::openapi_components(),
        stage6::components(),
        ssf::components(),
        developer::components(),
        stage11::components(),
        eligibility::components(),
        iys::components(),
    ] {
        if let (Value::Object(m), Value::Object(more)) = (&mut all, more) {
            m.extend(more);
        }
    }
    all
}

fn other_components() -> Value {
    let b64 =
        |d: &str| json!({ "type": "string", "pattern": "^[A-Za-z0-9_-]+$", "description": d });
    json!({
        "EligibilityRequest": object(
            &json!({
                "subject": b64("PartyID of the subject."),
                "set": {
                    "type": "object",
                    "description": "The context of an ADP `check` without `mode` and `nonce`: `domain`, `intent`, `basis`, `capacity`, `proofs` (L1-ADP-5…9).",
                },
                "as_of": text("A consistency token: answered at or after it (P36)."),
            }),
            &["subject", "set"],
        ),
        "EligibilityResponse": object(
            &json!({
                "eligible": { "type": "boolean" },
                "consistency_token": text("Opaque; the head the answer was read at."),
            }),
            &["eligible", "consistency_token"],
        ),
        "TenantSnapshot": object(
            &json!({
                "tenant": text("Opaque tenant id (`tnt_…`), the same id events carry in `accesstenant`, `access_tenant` and `tenant` (OP-149 m.15 (i))."),
                "organizations": { "type": "array", "items": { "type": "string" } },
                "realms": { "type": "array", "items": r("TenantRealm"), "description": "The tenant's live realms, by slug." },
                "region": text("The deployment's region."),
                "status": { "type": "string", "enum": ["provisioning", "active", "suspended", "deleted"] },
                "version": text("Changes exactly when the snapshot does."),
                "retention": { "type": "object", "description": "Retention policies (OP-147); empty until they are stored." },
            }),
            &["tenant", "organizations", "realms", "region", "status", "version", "retention"],
        ),
        "TenantRealm": object(
            &json!({
                "id": { "type": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", "description": "The realm, as events name it in `accessrealm` and `realm`." },
                "issuer": text("The realm's fixed issuer; its `/.well-known/suiss-configuration` describes it."),
                "slug": text("The realm's immutable slug."),
            }),
            &["id", "issuer", "slug"],
        ),
        "TenantPage": object(
            &json!({
                "tenants": { "type": "array", "items": r("TenantSnapshot") },
                "next_cursor": text("Absent on the last page."),
            }),
            &["tenants"],
        ),
        "SuissConfiguration": object(
            &json!({
                "suiss_configuration_version": { "const": 1 },
                "issuer": text("The realm issuer."),
                "suiss_region": text("The deployment's region."),
                "suiss_relay": text("Relay's base URL."),
                "suiss_management_api": text("The management API's base URL."),
                "suiss_event_subscriptions": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "ssf_configuration": text("The realm's SSF transmitter metadata (SSF 1.0 §7.1)."),
                        "webhooks": { "const": "urn:suiss:access:delivery:webhook", "description": "The Suiss webhook profile's delivery method: CloudEvents 1.0 structured JSON signed per Standard Webhooks." },
                    },
                    "required": ["ssf_configuration", "webhooks"],
                },
                "suiss_products": { "type": "object", "additionalProperties": { "type": "string" } },
                "suiss_coordinator": r("SuissCoordinator"),
                "endpoints": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "adp": { "type": "string" },
                        "key_lookup": { "type": "string" },
                        "key_batch": { "type": "string" },
                        "party_lookup": { "type": "string" },
                        "party_batch": { "type": "string" },
                        "eligibility": { "type": "string" },
                        "tenant_snapshot": { "type": "string" },
                        "auth_context": { "type": "string" },
                        "instances": { "type": "string" },
                        "pairing_challenges": { "type": "string" },
                        "pairing": { "type": "string" },
                        "platform_streams": { "type": "string" },
                        "subject_resolution": { "type": "string" },
                        "exercise": { "type": "string" },
                        "exercise_agency": { "type": "string" },
                        "claim_ingest": { "type": "string" },
                        "status_list": { "type": "string" },
                        "approval": { "type": "string" },
                        "approval_requests": { "type": "string" },
                        "pushed_authorization_request": { "type": "string" },
                        "relay_status": { "type": "string" },
                    },
                },
            }),
            &[
                "suiss_configuration_version", "issuer", "suiss_region", "suiss_relay",
                "suiss_management_api", "suiss_event_subscriptions", "suiss_products", "endpoints",
            ],
        ),
    })
}

fn problems(codes: &[(&str, &str)]) -> Map<String, Value> {
    codes
        .iter()
        .map(|(status, description)| {
            (
                (*status).to_owned(),
                json!({
                    "description": description,
                    "content": { "application/problem+json": { "schema": r("Problem") } },
                }),
            )
        })
        .collect()
}

/// A signed lookup answer: `what` has ended for the immutable cache, `usage` and `cddl` name
/// the canonical form, `schema` the JSON one.
fn signed_ok(description: &str, (what, usage, cddl, schema): (&str, &str, &str, &str)) -> Value {
    json!({
        "description": description,
        "headers": {
            "ETag": { "description": "The ledger position, quoted.", "schema": { "type": "string" } },
            "Cache-Control": {
                "description": format!("`{ACTIVE_MAX_AGE}`, or `{ENDED_CACHE}` once every {what} has ended."),
                "schema": { "type": "string" },
            },
            EXCERPT_HEADER.as_str(): {
                "description": "With `application/cose`: the binding-signed excerpt of the signing key, base64url (CR-58 m.1).",
                "schema": { "type": "string" },
            },
        },
        "content": {
            COSE_CONTENT_TYPE: {
                "schema": { "type": "string", "contentMediaType": "application/cose" },
                "description": format!("Canonical: COSE_Sign1 under usage `{usage}` over `conformance/cddl/{cddl}`."),
            },
            "application/json": { "schema": r(schema) },
        },
    })
}

fn keys_ok(description: &str) -> Value {
    signed_ok(
        description,
        ("key", "key-lookup", "key-lookup.cddl", "KeyLookup"),
    )
}

fn parties_ok(description: &str) -> Value {
    signed_ok(
        description,
        ("Party", "party-lookup", "party-lookup.cddl", "PartyLookup"),
    )
}

fn json_ok(description: &str, schema: &str) -> Value {
    json!({
        "description": description,
        "content": { "application/json": { "schema": r(schema) } },
    })
}

fn with(mut responses: Map<String, Value>, status: &str, ok: Value) -> Value {
    responses.insert(status.to_owned(), ok);
    Value::Object(responses)
}

fn query(name: &str, required: bool, schema: &str, description: &str) -> Value {
    json!({ "name": name, "in": "query", "required": required, "schema": r(schema), "description": description })
}

fn path(name: &str, schema: &Value) -> Value {
    json!({ "name": name, "in": "path", "required": true, "schema": schema })
}

/// OP-149 m.37: the security of a route a platform client may also call with its assertion.
pub(super) fn either_caller() -> Value {
    json!([{ "client": [] }, { "platform_client": [] }])
}

/// The 401 of such a route.
pub(super) const EITHER_401: (&str, &str) = (
    "401",
    "No client certificate and no valid platform client assertion; client-unauthenticated when an assertion was sent (OP-141 m.18 (b), OP-149 m.37).",
);

/// OP-149 m.28 (c): the Party status lookup routes, the key lookup's twins.
fn party_paths(paths: &mut Map<String, Value>, common: &[(&str, &str); 4]) {
    paths.insert(
        "/access/v1/parties/{party}".into(),
        json!({ "get": {
            "operationId": "getParty",
            "summary": "One Party's status at a ledger position (OP-149 m.28 (c)): its actor kind, the record that admitted it and, once it has, the one that ended it.",
            "security": either_caller(),
            "parameters": [
                path("party", &r("PartyId")),
                query("domain", true, "DomainId", "The authority domain."),
                query("as_of", false, "AsOf", "Defaults to the head."),
            ],
            "responses": with(
                problems(&[common[0], EITHER_401, ("404", "The Party is not admitted at the position."), common[2], common[3]]),
                "200",
                parties_ok("The Party."),
            ),
        }}),
    );
    paths.insert(
        "/access/v1/parties:batchGet".into(),
        json!({ "post": {
            "operationId": "batchGetParties",
            "summary": "Up to 100 Parties' status at one ledger position (OP-149 m.28 (c)).",
            "security": either_caller(),
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("PartyBatchRequest") } } },
            "responses": with(problems(&[common[0], EITHER_401, common[2], common[3]]), "200", parties_ok("The Parties; the others are listed as `unknown`.")),
        }}),
    );
}

/// OP-149 m.4: the tenant snapshot routes, which a platform client may also call (m.37).
fn tenant_paths(paths: &mut Map<String, Value>, common: &[(&str, &str); 4]) {
    paths.insert(
        "/access/v1/tenants".into(),
        json!({ "get": {
            "operationId": "listTenants",
            "summary": "Tenant snapshots, one page at a time (OP-149 m.4).",
            "security": either_caller(),
            "parameters": [{ "name": "cursor", "in": "query", "required": false, "schema": { "type": "string" } }],
            "responses": with(problems(&[common[0], EITHER_401, common[2], common[3]]), "200", json_ok("One page.", "TenantPage")),
        }}),
    );
    paths.insert(
        "/access/v1/tenants/{tenant}/snapshot".into(),
        json!({ "get": {
            "operationId": "getTenantSnapshot",
            "summary": "One tenant's snapshot (OP-149 m.4, OP-147 m.4).",
            "security": either_caller(),
            "parameters": [path("tenant", &json!({ "type": "string" }))],
            "responses": with(
                problems(&[EITHER_401, ("404", "No such tenant."), common[2], common[3]]),
                "200",
                json_ok("The snapshot.", "TenantSnapshot"),
            ),
        }}),
    );
}

/// CR-22: the provider declarations document (OP-150).
fn declarations(paths: &mut serde_json::Map<String, Value>) {
    paths.insert(
        crate::declarations::PATH.into(),
        crate::declarations::openapi_path(),
    );
}

/// The `OpenAPI` document of the product client contract.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one call per contract section, in contract order"
)]
pub fn openapi() -> Value {
    let common = [
        ("400", "The request is refused; nothing is read."),
        ("401", "No client certificate (OP-141 m.18 (b))."),
        ("429", "Over a rate limit."),
        ("503", "Temporarily unavailable; retry."),
    ];
    let mut paths = Map::new();
    paths.insert(
        "/access/v1/keys/{kid}".into(),
        json!({ "get": {
            "operationId": "getKey",
            "summary": "One Instance key at a ledger position (OP-149 m.5).",
            "security": either_caller(),
            "parameters": [
                path("kid", &r("Kid")),
                query("domain", true, "DomainId", "The authority domain."),
                query("as_of", false, "AsOf", "Defaults to the head."),
            ],
            "responses": with(
                problems(&[common[0], EITHER_401, ("404", "The key is not held at the position."), common[2], common[3]]),
                "200",
                keys_ok("The key."),
            ),
        }}),
    );
    paths.insert(
        "/access/v1/keys:batchGet".into(),
        json!({ "post": {
            "operationId": "batchGetKeys",
            "summary": "Up to 100 Instance keys at one ledger position (OP-149 m.5).",
            "security": either_caller(),
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("KeyBatchRequest") } } },
            "responses": with(problems(&[common[0], EITHER_401, common[2], common[3]]), "200", keys_ok("The keys; the others are listed as `unknown`.")),
        }}),
    );
    party_paths(&mut paths, &common);
    paths.insert(
        "/access/v1/eligibility:check".into(),
        json!({ "post": {
            "operationId": "checkEligibility",
            "summary": "Whether one subject may act as the `check` describes; records nothing (OP-149 m.10).",
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("EligibilityRequest") } } },
            "responses": with(problems(&common), "200", json_ok("The answer.", "EligibilityResponse")),
        }}),
    );
    tenant_paths(&mut paths, &common);
    paths.insert(
        "/.well-known/suiss-configuration".into(),
        json!({ "get": {
            "operationId": "getSuissConfiguration",
            "summary": "The realm's Suiss discovery document (OP-149 m.3); also under the realm path of a path issuer. `Cache-Control: max-age=300`.",
            "security": [],
            "responses": with(
                problems(&[("404", "No realm here."), ("503", "Temporarily unavailable.")]),
                "200",
                json_ok("The document.", "SuissConfiguration"),
            ),
        }}),
    );
    // OP-156 m.3 (t)
    paths.insert(
        "/.well-known/suiss-configuration/realms/{slug}".into(),
        json!({ "get": {
            "operationId": "getRealmSuissConfiguration",
            "summary": "The same document of the realm `slug`, for a reader that names the realm rather than its host (OP-149 m.3); a service such as the hub reads `suiss_coordinator` here.",
            "security": [],
            "parameters": [path("slug", &json!({ "type": "string" }))],
            "responses": with(
                problems(&[("404", "No realm here."), ("503", "Temporarily unavailable.")]),
                "200",
                json_ok("The document.", "SuissConfiguration"),
            ),
        }}),
    );
    declarations(&mut paths);
    records::paths(&mut paths, &common);
    platform::paths(&mut paths);
    stage6::paths(&mut paths, &common);
    ssf::paths(&mut paths);
    developer::paths(&mut paths);
    stage11::paths(&mut paths);
    stage13::paths(&mut paths);
    eligibility::paths(&mut paths, &common);
    iys::paths(&mut paths);
    json!({
        "openapi": "3.1.1",
        "info": {
            "title": "Access product client API",
            "version": VERSION,
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
        },
        "security": [{ "client": [] }],
        "paths": paths,
        "components": {
            "schemas": components(),
            "securitySchemes": {
                "client": { "type": "mutualTLS", "description": "The client certificate names the product client (OP-141 m.18 (b))." },
                "platform_client": platform::scheme(),
                "stream_bearer": ssf::scheme(),
            },
        },
    })
}
