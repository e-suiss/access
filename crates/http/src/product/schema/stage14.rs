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

/// The served projection fetch (CR-43, OP-159 m.3 (q)).
fn projection(paths: &mut Map<String, Value>) {
    let mut responses = problems(&[
        ("401", "pep-required: no authenticated PEP."),
        (
            "404",
            "not-found: no such projection, or the PEP is not in the artefact's aud.",
        ),
        (
            "410",
            "projection-ref-expired: the projection expired and its data key was destroyed; ask for a new projection.",
        ),
        ("503", "Temporarily unavailable; retry."),
    ]);
    responses.insert(
        "200".into(),
        json!({
            "description": "The artefact, byte-identical: a COSE_Sign1 or the hybrid carrier. Its SHA-256 is the digest of the projection_ref.",
            "content": { crate::projections::CONTENT_TYPE: { "schema": { "type": "string", "format": "binary" } } },
        }),
    );
    paths.insert(
        crate::projections::PROJECTION_PATH.to_owned(),
        json!({ "get": {
            "operationId": "getProjection",
            "summary": "The projection a projection_ref names, byte-identical, for the authenticated PEP in the artefact's aud only; the verifier recomputes the digest and verifies the artefact in full. An expired projection answers 410 projection-ref-expired (CR-43, projection-ref.cddl, OP-159 m.3 (q)).",
            "parameters": parameters(crate::projections::PROJECTION_PATH),
            "responses": responses,
        }}),
    );
}

/// The Stage 14 paths: the served ones and those declared before their lanes serve them.
pub(super) fn paths(paths: &mut Map<String, Value>) {
    projection(paths);
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
