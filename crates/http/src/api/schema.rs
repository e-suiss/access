//! The management API contract as an `OpenAPI` 3.1 document, generated from the manifest and
//! committed as `sdks/openapi/admin-v1.json` (OP-65 m.3, TN-112, OP-151 m.4): the common
//! components (problem, pagination, idempotency, conditional and rate limit headers,
//! `Request-Id`) and one operation per manifest row. `just admin-contract` rewrites it.

use serde_json::{Map, Value, json};

use super::domain::idempotency::MAX_KEY;
use super::domain::page::{CURSOR, DEFAULT_PAGE, FILTER, MAX_PAGE, PAGE_SIZE};
use super::domain::{PLATFORM_AUDIENCE, REALM_AUDIENCE_PREFIX, Surface};
use super::manifest::{Access, MANIFEST, Route, Visibility};
use crate::problem::TYPE_PREFIX;

/// Version of the contract.
pub const VERSION: &str = "1.0.0";

fn r(kind: &str, name: &str) -> Value {
    json!({ "$ref": format!("#/components/{kind}/{name}") })
}

fn text(description: &str) -> Value {
    json!({ "type": "string", "description": description })
}

fn schemas() -> Value {
    json!({
        "Problem": {
            "type": "object",
            "description": format!("RFC 9457. `type` is `{TYPE_PREFIX}<code>`, or `about:blank` when the status says all; the codes are listed in `problems.json`."),
            "required": ["type", "title", "status", "code"],
            "properties": {
                "type": text("Problem type URI."),
                "title": text("Short title."),
                "status": { "type": "integer", "minimum": 100, "maximum": 599 },
                "code": text("Stable error code (OP-65)."),
                "reason": text("A stable, non-secret reason narrowing `code`."),
                "errors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["code"],
                        "properties": {
                            "pointer": text("A JSON Pointer (RFC 6901) into the request body, as a URI fragment."),
                            "code": text("Stable code of what is wrong there."),
                        },
                    },
                },
            },
        },
        "Position": { "type": "string", "pattern": "^[0-9]{1,20}$", "description": "A ledger position, in decimal: 64-bit integers are strings (OP-65)." },
        "Time": { "type": "string", "format": "date-time", "description": "RFC 3339, UTC." },
        "ExerciseRef": {
            "type": "object",
            "additionalProperties": false,
            "description": "The Exercise a write compiled to and its position (TN-110).",
            "required": ["exercise_id", "position"],
            "properties": {
                "exercise_id": { "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$", "description": "The ExerciseID, unpadded base64url." },
                "position": r("schemas", "Position"),
            },
        },
        "SurfaceRoot": {
            "type": "object",
            "additionalProperties": false,
            "required": ["surface", "audience", "scope_namespace", "read_scope", "domain", "rate_policies"],
            "properties": {
                "surface": { "type": "string", "enum": ["realm", "platform"] },
                "realm": text("The realm's slug (realm surface)."),
                "audience": text(&format!("The token audience: `{REALM_AUDIENCE_PREFIX}<slug>` or `{PLATFORM_AUDIENCE}` (TN-119).")),
                "scope_namespace": text("The surface's scope prefix: `realm.` or `platform.`."),
                "read_scope": text("The scope a read needs at least."),
                "domain": { "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$", "description": "The surface's governing DomainID, unpadded base64url." },
                "rate_policies": { "type": "array", "items": text("A `RateLimit-Policy` item of the caller's own budget.") },
            },
        },
    })
}

fn headers() -> Value {
    let s = |d: &str| json!({ "description": d, "schema": { "type": "string" } });
    json!({
        "Request-Id": s("The request's W3C trace id, 32 lower-case hex digits: the `traceparent` trace id when one was sent (OP-65, OP-67)."),
        "RateLimit-Policy": s("The quotas that applied (IETF httpapi RateLimit header fields): `\"<name>\";q=<quota>;w=<window seconds>`, per layer (TN-127)."),
        "RateLimit": s("What is left of each quota: `\"<name>\";r=<remaining>;t=<seconds to reset>`."),
        "Retry-After": s("Seconds to wait before retrying (RFC 9110 §10.2.3)."),
        "ETag": s("The resource version, a strong entity tag; send it in `If-Match` to update (OP-65)."),
        "Link": s("RFC 8288 `rel=\"next\"` to the next page; absent on the last page."),
        "Deprecation": s("RFC 9745: when the operation was deprecated, `@<unix seconds>`."),
        "Sunset": s("RFC 8594: when the operation goes away, an HTTP-date."),
    })
}

fn parameters() -> Value {
    json!({
        "Traceparent": { "name": "traceparent", "in": "header", "required": false, "description": "W3C Trace Context; its trace id becomes `Request-Id`.", "schema": { "type": "string" } },
        "IdempotencyKey": {
            "name": "Idempotency-Key", "in": "header", "required": true,
            "description": "Required on every write: the AIS nonce, unpadded base64url. The same key and request replay the first answer for 24 hours; another request is 422; a running one 409 (TN-126).",
            "schema": { "type": "string", "minLength": 1, "maxLength": MAX_KEY },
        },
        "Ais": {
            "name": "X-Access-AIS", "in": "header", "required": false,
            "description": "The caller's actor intent statement, a `COSE_Sign1` signed with its Instance key, unpadded base64url; or the body member `ais` (TN-110, PI-7).",
            "schema": { "type": "string" },
        },
        "IfMatch": { "name": "If-Match", "in": "header", "required": true, "description": "The resource's ETag (OP-65): 428 without, 412 on a mismatch.", "schema": { "type": "string" } },
        "Slug": { "name": "slug", "in": "path", "required": true, "schema": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$" } },
        "PageSize": { "name": PAGE_SIZE, "in": "query", "required": false, "schema": { "type": "integer", "minimum": 1, "maximum": MAX_PAGE, "default": DEFAULT_PAGE } },
        "Cursor": { "name": CURSOR, "in": "query", "required": false, "description": "Opaque; from the `Link` of the previous page.", "schema": { "type": "string" } },
        "Filter": { "name": FILTER, "in": "query", "required": false, "description": "SCIM filter subset: eq, ne, co, sw, pr, and, or, parentheses; an attribute the endpoint does not name is 400 (TN-112).", "schema": { "type": "string", "maxLength": access_parse::scim::MAX_LEN } },
    })
}

fn common_headers(extra: &[&str]) -> Map<String, Value> {
    ["Request-Id", "RateLimit-Policy", "RateLimit"]
        .iter()
        .chain(extra)
        .map(|h| ((*h).to_owned(), r("headers", h)))
        .collect()
}

fn problem(description: &str, extra: &[&str]) -> Value {
    json!({
        "description": description,
        "headers": common_headers(extra),
        "content": { "application/problem+json": { "schema": r("schemas", "Problem") } },
    })
}

fn responses() -> Value {
    json!({
        "BadRequest": problem("Malformed request: query, filter, cursor, body or Idempotency-Key.", &[]),
        "Unauthorized": problem("No usable credential for this surface: invalid-token, wrong-audience, token-lifetime, ais-required or ais-invalid.", &[]),
        "Forbidden": problem("insufficient-scope, ais-rejected or exercise-not-allowed.", &[]),
        "NotFound": problem("No such resource, or one the caller may not see (TN-113).", &[]),
        "Conflict": problem("idempotency-key-in-use.", &[]),
        "PreconditionFailed": problem("precondition-failed.", &[]),
        "Unprocessable": problem("idempotency-key-reused.", &[]),
        "PreconditionRequired": problem("precondition-required.", &[]),
        "TooManyRequests": problem("rate-limited.", &["Retry-After"]),
        "Unavailable": problem("A dependency is unavailable; nothing changed.", &[]),
    })
}

/// The response body schema of an operation.
fn body_of(row: &Route) -> &'static str {
    match row.operation_id {
        "getPlatformSurface" | "getRealmSurface" => "SurfaceRoot",
        _ => "ExerciseRef",
    }
}

fn operation(row: &Route) -> Value {
    let write = row.access == Access::Write;
    let mut params = vec![r("parameters", "Traceparent")];
    if row.surface == Surface::Realm {
        params.push(r("parameters", "Slug"));
    }
    for q in row.query {
        let name = match *q {
            PAGE_SIZE => "PageSize",
            CURSOR => "Cursor",
            _ => "Filter",
        };
        params.push(r("parameters", name));
    }
    if write {
        params.push(r("parameters", "IdempotencyKey"));
        params.push(r("parameters", "Ais"));
    }
    let mut ok_headers = common_headers(&[]);
    if row.query.contains(&CURSOR) {
        ok_headers.insert("Link".to_owned(), r("headers", "Link"));
    }
    if row.lifecycle.is_some() {
        ok_headers.insert("Deprecation".to_owned(), r("headers", "Deprecation"));
        ok_headers.insert("Sunset".to_owned(), r("headers", "Sunset"));
    }
    let mut responses = Map::new();
    responses.insert(
        "200".to_owned(),
        json!({
            "description": if write { "Committed: the Exercise record (TN-110)." } else { "The resource." },
            "headers": ok_headers,
            "content": { "application/json": { "schema": r("schemas", body_of(row)) } },
        }),
    );
    let mut errors = vec![
        ("400", "BadRequest"),
        ("401", "Unauthorized"),
        ("404", "NotFound"),
        ("429", "TooManyRequests"),
        ("503", "Unavailable"),
    ];
    if write || row.visibility == Visibility::Forbidden {
        errors.push(("403", "Forbidden"));
    }
    if write {
        errors.extend([("409", "Conflict"), ("422", "Unprocessable")]);
    }
    for (status, name) in errors {
        responses.insert(status.to_owned(), r("responses", name));
    }
    let (security, scope) = match row.access {
        Access::Read { scope } => (json!([{ "read_token": [scope] }]), json!(scope)),
        Access::Write => (json!([{ "ais": [] }]), Value::Null),
    };
    json!({
        "operationId": row.operation_id,
        "summary": row.summary,
        "tags": [row.surface.name()],
        "security": security,
        "parameters": params,
        "responses": responses,
        "deprecated": row.lifecycle.is_some(),
        "x-access-surface": row.surface.name(),
        "x-access-scope": scope,
        "x-access-visibility": match row.visibility { Visibility::Hidden => "hidden", Visibility::Forbidden => "forbidden" },
    })
}

/// The document.
#[must_use]
pub fn openapi() -> Value {
    let mut paths = Map::new();
    for row in MANIFEST {
        let item = paths
            .entry(row.path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(o) = item.as_object_mut() {
            o.insert(row.verb.name().to_owned(), operation(row));
        }
    }
    json!({
        "openapi": "3.1.1",
        "info": {
            "title": "Access management API",
            "version": VERSION,
            "description": "Realm-admin (`/admin/v1/realms/{slug}`) and platform-admin (`/admin/v1/platform`) surfaces on the management listener. Reads take a holder-bound DPoP token of the surface's audience living at most 60 minutes; writes take the caller's AIS and compile to an Exercise; there is no bearer management token (TN-110, TN-119, TN-130). Field names are snake_case, times RFC 3339 UTC, 64-bit integers strings (OP-65).",
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
        },
        "tags": [
            { "name": "realm", "description": format!("Realm administration; audience `{REALM_AUDIENCE_PREFIX}<slug>`, scopes `realm.*`.") },
            { "name": "platform", "description": format!("Platform administration; audience `{PLATFORM_AUDIENCE}`, scopes `platform.*`.") },
        ],
        "paths": paths,
        "components": {
            "schemas": schemas(),
            "headers": headers(),
            "parameters": parameters(),
            "responses": responses(),
            "securitySchemes": {
                "read_token": {
                    "type": "http",
                    "scheme": "DPoP",
                    "description": "A DPoP-bound access token (RFC 9449) whose one audience is the surface's and whose scopes include the operation's; at most 60 minutes; with its `DPoP` proof (TN-27, OP-151 m.3 (c)).",
                },
                "ais": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Access-AIS",
                    "description": "The caller's AIS signed with a live Instance key of the surface's governing domain (PI-7, TN-110).",
                },
            },
        },
    })
}
