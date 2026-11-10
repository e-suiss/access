//! The Stage 11 routes declared before their lanes serve them (OP-156 m.4): each answers
//! `501 not-yet-served`.

use serde_json::{Map, Value, json};

use super::{object, problems, r};
use crate::stage11::{Method, PLANNED, PROXY_ENGINES};

/// The relay status schema.
pub(super) fn components() -> Value {
    json!({
        "RelayStatus": object(
            &json!({
                "relay_lag_ms": {
                    "type": ["integer", "null"],
                    "minimum": 0,
                    "description": "Age of the courier's oldest undelivered message in milliseconds; null when none waits.",
                },
                "notifications_delayed": { "type": "boolean", "description": "Whether relay_lag_ms is past 60 s (OP-156 m.3 (c))." },
            }),
            &["relay_lag_ms", "notifications_delayed"],
        ),
    })
}

/// Every declared route of [`PLANNED`].
pub(super) fn paths(paths: &mut Map<String, Value>) {
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
                "description": "not-yet-served: the route is declared and its lane does not serve it yet; nothing was read or changed (OP-156 m.4).",
                "content": { "application/problem+json": { "schema": r("Problem") } },
            }),
        );
        if p.operation == "getRelayStatus" {
            responses.insert(
                "200".into(),
                json!({
                    "description": "The status.",
                    "content": { "application/json": { "schema": r("RelayStatus") } },
                }),
            );
        }
        let mut op = Map::new();
        op.insert("operationId".into(), p.operation.into());
        op.insert("summary".into(), p.summary.into());
        op.insert("x-suiss-status".into(), "planned".into());
        op.insert("responses".into(), Value::Object(responses));
        if p.path.contains("{engine}") {
            op.insert(
                "parameters".into(),
                json!([{
                    "name": "engine",
                    "in": "path",
                    "required": true,
                    "schema": { "type": "string", "enum": PROXY_ENGINES },
                }]),
            );
        }
        let entry = paths
            .entry(p.path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(m) = entry {
            m.insert(method.to_owned(), Value::Object(op));
        }
    }
}
