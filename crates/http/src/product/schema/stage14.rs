//! The Stage 14 routes declared before their lanes serve them (OP-159 m.4 (a)): each answers
//! `501 not-yet-served`.

use serde_json::{Map, Value, json};

use super::{problems, r};
use crate::stage14::{Method, PLANNED};

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

/// The declared Stage 14 paths.
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
                "description": "not-yet-served: the route is declared and its lane does not serve it yet; nothing was read or changed (OP-159 m.4 (a)).",
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
