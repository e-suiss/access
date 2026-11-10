//! `POST /relay/v1/iys-status` (OP-156 m.3 (c), IDP-37 (4), B23): Relay's report of an İYS
//! consent record, by Relay's platform client assertion.

use serde_json::{Map, Value, json};

use super::{object, problems, r, text};
use crate::relay_callback::PATH;

/// The report schema.
pub(super) fn components() -> Value {
    json!({
        "IysStatusReport": object(
            &json!({
                "tenant": text("The tenant's external id (tnt_), as the Relay message's accesstenant names it."),
                "realm": { "type": "string", "format": "uuid", "description": "The realm, as the Relay message's accessrealm names it." },
                "record": { "type": "string", "format": "uuid", "description": "The CloudEvents id of the relay.message.iys_consent.v1 the record came in." },
                "status": { "enum": ["recorded", "failed"] },
                "reason": { "type": "string", "pattern": "^[a-z][a-z0-9_-]{0,63}$", "description": "Why it failed; never with recorded." },
                "at": { "type": "integer", "minimum": 0, "description": "When it happened at İYS, Unix ms." },
            }),
            &["tenant", "realm", "record", "status", "at"],
        ),
    })
}

/// The served route.
pub(super) fn paths(paths: &mut Map<String, Value>) {
    let mut responses = problems(&[
        (
            "400",
            "invalid-request: the report is malformed; nothing is kept.",
        ),
        (
            "401",
            "client-unauthenticated: no valid platform client assertion.",
        ),
        ("403", "not-relay: the client is not Relay's."),
        ("404", "not-found: the realm has no such record."),
        ("413", "body-too-large"),
        ("503", "Temporarily unavailable; retry."),
    ]);
    responses.insert(
        "204".into(),
        json!({ "description": "Kept beside its record; no preference changed." }),
    );
    paths.insert(
        PATH.into(),
        json!({ "post": {
            "operationId": "relayIysStatus",
            "summary": "Relay's report of an İYS consent record's registration state; it changes no preference and no authority (OP-156 m.3 (c), IDP-37 (4), B23).",
            "x-suiss-served": true,
            "security": [{ "platform_client": [] }],
            "requestBody": {
                "required": true,
                "content": { "application/json": { "schema": r("IysStatusReport") } },
            },
            "responses": Value::Object(responses),
        }}),
    );
}
