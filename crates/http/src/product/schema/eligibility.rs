//! `POST /access/v1/eligibility:set` (OP-156 m.3 (t), E41).

use serde_json::{Map, Value, json};

use super::{json_ok, object, problems, r, text, with};

fn b64(description: &str) -> Value {
    json!({ "type": "string", "contentEncoding": "base64url", "description": description })
}

/// The eligible-set schemas.
pub(super) fn components() -> Value {
    json!({
        "EligibleSetQuery": object(
            &json!({
                "gate_class": { "type": "string", "pattern": "^[a-z][a-z0-9_]{0,63}$", "description": "The contribution class the Gate needs: `approve` or a class the domain uses." },
                "resource": text("The resource the Gate is on, as the coordinator names it; opaque to Access, at most 512 bytes."),
                "digest": b64("The digest the approval binds: the target intent's digest for an intent-bound Gate, the Gate payload's for a coordination Gate."),
            }),
            &["gate_class", "resource", "digest"],
        ),
        "EligibleSetRequest": object(
            &json!({
                "context": {
                    "type": "object",
                    "description": "The reader's `check` context (L1-ADP-5…9) with `query` (`EligibleSetQuery`): the intent's action is `access`/`read` and its first resource `access.search` with the path `[\"eligible-set\"]`. The same body is the `eligible-set` search.",
                },
            }),
            &["context"],
        ),
        "SuissCoordinator": object(
            &json!({ "attention": text("The coordinator's public Needs Attention endpoint the realm named (`idp.realm.coordinator`, OP-156 m.3 (t)); `GET` with `party` answers `{count, href}`. Access keeps no queue.") }),
            &["attention"],
        ),
        "EligibleSet": object(
            &json!({
                "parties": { "type": "array", "maxItems": 1000, "items": b64("A PartyID."), "description": "The named holders of `approve:<class>` now: a live Grant covering `access:contribute` on `access.contribution:[gate_class]` whose lineage is in force. Rule-shaped and public holders are not listed; ask `eligibility:check` per Party." },
                "truncated": { "type": "boolean", "description": "More Parties hold it than are listed." },
                "context": object(
                    &json!({ "advisory": { "const": true }, "recorded": { "const": false } }),
                    &["advisory", "recorded"],
                ),
            }),
            &["parties", "truncated", "context"],
        ),
    })
}

/// The route.
pub(super) fn paths(paths: &mut Map<String, Value>, common: &[(&str, &str); 4]) {
    paths.insert(
        "/access/v1/eligibility:set".into(),
        json!({ "post": {
            "operationId": "eligibleSet",
            "summary": "Who may approve a Gate of a class now (§7.9.5.3, E41, OP-156 m.3 (t)): derived, advisory, never recorded, at most 1000 Parties. Only the domain's auditors and a reader holding `access:read` on `access.search:[eligible-set]` get Parties (E26); anyone else gets an empty set. A Gate being satisfied is never an ALLOW (G30, EI-4).",
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("EligibleSetRequest") } } },
            "responses": with(problems(common), "200", json_ok("The set.", "EligibleSet")),
        }}),
    );
}
