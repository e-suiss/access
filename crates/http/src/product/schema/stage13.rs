//! The Stage 13 routes declared before their lanes serve them (OP-158 m.4 (a)): each answers
//! `501 not-yet-served`.

use serde_json::{Map, Value, json};

use super::{problems, r};
use crate::stage13::{Method, PLANNED};

fn parameters(path: &str) -> Value {
    Value::Array(
        path.split('/')
            .filter_map(|s| s.strip_prefix('{')?.strip_suffix('}'))
            .map(|name| {
                json!({
                    "name": name,
                    "in": "path",
                    "required": true,
                    "schema": { "type": "string", "minLength": 1, "maxLength": 128 },
                })
            })
            .collect(),
    )
}

/// The declared Stage 13 paths.
pub(super) fn paths(paths: &mut Map<String, Value>) {
    watch(paths);
    for p in PLANNED {
        let method = match p.method {
            Method::Get => "get",
            Method::Post => "post",
        };
        let mut responses = problems(&[
            ("400", "The request is refused; nothing is read."),
            ("503", "Temporarily unavailable; retry."),
        ]);
        responses.insert(
            "501".into(),
            json!({
                "description": "not-yet-served: the route is declared and its lane does not serve it yet; nothing was read or changed (OP-158 m.4 (a)).",
                "content": { "application/problem+json": { "schema": r("Problem") } },
            }),
        );
        let mut op = Map::new();
        op.insert("operationId".into(), p.operation.into());
        op.insert("summary".into(), p.summary.into());
        op.insert("x-suiss-status".into(), "planned".into());
        op.insert("parameters".into(), parameters(p.path));
        op.insert("responses".into(), Value::Object(responses));
        let entry = paths
            .entry(p.path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(m) = entry {
            m.insert(method.to_owned(), Value::Object(op));
        }
    }
}

/// `GET /access/v1/domains/{domain}/watch` (OP-158 m.3 (u)).
fn watch(paths: &mut Map<String, Value>) {
    let mut responses = problems(&[
        (
            "400",
            "`from` or `wait` is missing or malformed; nothing is read.",
        ),
        ("401", "No authenticated PEP."),
        (
            "409",
            "`as-of-expired`: the first record after `from` is older than the 24 hour history window; read from the head.",
        ),
        (
            "503",
            "`from` is past the head, or temporarily unavailable; retry.",
        ),
    ]);
    responses.insert(
        "200".into(),
        json!({
            "description": "The records after `from`, oldest first, at most 100; empty when none came within `wait`.",
            "headers": { "Cache-Control": { "schema": { "const": "no-store" } } },
            "content": { "application/json": { "schema": {
                "type": "object",
                "required": ["changes", "next", "head", "witnessed_through", "advisory"],
                "additionalProperties": false,
                "properties": {
                    "changes": { "type": "array", "maxItems": 100, "items": {
                        "type": "object",
                        "required": ["position", "recorded_at", "kinds"],
                        "additionalProperties": false,
                        "properties": {
                            "position": { "type": "string", "pattern": "^[1-9][0-9]{0,19}$" },
                            "recorded_at": { "type": "integer", "minimum": 0 },
                            "kinds": { "type": "array", "items": { "type": "string" } },
                        },
                    } },
                    "next": { "type": "integer", "minimum": 0 },
                    "head": { "type": "integer", "minimum": 0 },
                    "witnessed_through": { "type": "integer", "minimum": 0 },
                    "advisory": { "const": true },
                },
            } } },
        }),
    );
    let mut parameters = parameters("/access/v1/domains/{domain}/watch");
    if let Value::Array(list) = &mut parameters {
        list.push(json!({ "name": "from", "in": "query", "required": true, "schema": { "type": "integer", "minimum": 0 } }));
        list.push(json!({ "name": "wait", "in": "query", "required": false, "schema": { "type": "integer", "minimum": 0, "maximum": 25_000, "default": 10_000 } }));
    }
    paths.insert(
        "/access/v1/domains/{domain}/watch".into(),
        json!({ "get": {
            "operationId": "watchDomain",
            "summary": "Changes after `from` (a record position) by long polling: each record's position, trusted time and the kinds of state it changed, and `witnessed_through`, the largest tree size a witness has cosigned. For an authenticated PEP; advisory, never cached and never a source of ALLOW (§9.7A.2, §9.7A.4, OP-158 m.3 (u)).",
            "parameters": parameters,
            "responses": Value::Object(responses),
        }}),
    );
}
