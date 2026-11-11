//! A replica agent's divergence statement (G32, G33, OP-158 m.3 (h), (i)).

use serde_json::{Map, Value, json};

use super::problems;
use crate::divergence::DIVERGENCE_PATH;

/// The served route.
pub(super) fn paths(paths: &mut Map<String, Value>) {
    let mut responses = problems(&[
        (
            "400",
            "domain or divergence-set: malformed, not signed by the key it names, or a range past the head.",
        ),
        (
            "403",
            "replica-unknown: not under a key the domain declares for a replica.",
        ),
        ("503", "Temporarily unavailable; retry."),
    ]);
    responses.insert(
        "202".into(),
        json!({ "description": "Kept as a new notice for the root and the Security Party; nothing stops.", "content": { "application/json": { "schema": {} } } }),
    );
    responses.insert(
        "200".into(),
        json!({ "description": "The same set was declared before.", "content": { "application/json": { "schema": {} } } }),
    );
    paths.insert(
        DIVERGENCE_PATH.to_owned(),
        json!({
            "post": {
                "operationId": "declareDivergence",
                "summary": "Records a signed divergence set (recovery.cddl) as a divergence notice for the domain's root and Security Party, under the key the domain declares for the replica that replayed it; it never stops an exit and writes no restriction (G32, G33, OP-158 m.3 (i)).",
                "parameters": [{
                    "name": "domain",
                    "in": "path",
                    "required": true,
                    "schema": { "type": "string", "minLength": 1, "maxLength": 128 },
                }],
                "requestBody": {
                    "required": true,
                    "content": { "application/cbor": { "schema": {} } },
                },
                "responses": responses,
            }
        }),
    );
}
