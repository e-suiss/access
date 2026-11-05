//! Subject resolution (OP-149 A11), allowed Exercises (OP-149 m.9) and their agency chains
//! (OP-149 m.11) in the contract.

use serde_json::{Map, Value, json};

use super::super::domain::MAX_RESOLVE;
use super::{json_ok, object, path, problems, query, r, text, with};

pub(super) fn components() -> Value {
    let b64 =
        |d: &str| json!({ "type": "string", "pattern": "^[A-Za-z0-9_-]+$", "description": d });
    json!({
        "ResolveRequest": object(
            &json!({
                "realm": { "type": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", "description": "The realm, as the tenant snapshot names it." },
                "client_id": text("The client whose pairwise `sub` is meant, its sector (MD-10), e.g. Relay's client of the realm."),
                "parties": { "type": "array", "items": b64("PartyID, base64url of 16 bytes."), "minItems": 1, "maxItems": MAX_RESOLVE, "uniqueItems": true },
                "subs": { "type": "array", "items": b64("A pairwise `sub` of the client, 43 characters."), "minItems": 1, "maxItems": MAX_RESOLVE, "uniqueItems": true },
            }),
            &["realm", "client_id"],
        ),
        "Resolution": object(
            &json!({
                "realm": text("The realm."),
                "client_id": text("The client."),
                "resolved": {
                    "type": "array",
                    "items": object(&json!({ "party": b64("PartyID."), "sub": b64("The pairwise `sub` the client sees.") }), &["party", "sub"]),
                },
                "unknown": { "type": "array", "items": { "type": "string" }, "description": "The entries asked for that did not resolve, as given." },
                "consistency_token": text("Opaque; the governing domain's head before the read."),
            }),
            &["realm", "client_id", "resolved", "unknown", "consistency_token"],
        ),
        "Exercise": object(
            &json!({
                "exercise": b64("ExerciseID, 32 bytes."),
                "domain": r("DomainId"),
                "status": { "type": "string", "enum": ["allowed"], "description": "Only allowed Exercises are recorded; others are not found." },
                "position": r("Position"),
                "intent": b64("The intent digest it was allowed for."),
                "instance": b64("The actor InstanceID; absent for an anonymous actor."),
                "receipt": object(
                    &json!({
                        "payload": b64("The receipt payload, dCBOR (`application/access-receipt+cbor`)."),
                        "cose_sign1": b64("The receipt as the decision point signed it, COSE_Sign1 under usage `receipt`."),
                        "key_excerpt": b64("The binding-signed excerpt of the signing key (CR-58 m.1)."),
                    }),
                    &["payload"],
                ),
            }),
            &["exercise", "domain", "status", "position", "intent"],
        ),
        "Agency": object(
            &json!({
                "exercise": b64("ExerciseID, 32 bytes."),
                "domain": r("DomainId"),
                "capacity": {
                    "description": "The capacity the actor declared: `own`, or `{for}` the PartyID it acted for.",
                    "oneOf": [
                        { "type": "string", "enum": ["own"] },
                        object(&json!({ "for": b64("PartyID, 16 bytes.") }), &["for"]),
                    ],
                },
                "agency": {
                    "type": "array",
                    "description": "The chain from the principal to the agent; the agent of a link is the principal of the next. Empty when the actor acted for itself, or for another Party without a Mandate on its Instance.",
                    "items": object(
                        &json!({
                            "mandate": b64("The MandateID the agent acted under, 16 bytes."),
                            "principal": b64("The PartyID acted for, 16 bytes."),
                            "agent": b64("The PartyID that acted, 16 bytes."),
                        }),
                        &["mandate", "principal", "agent"],
                    ),
                },
                "receipt": object(
                    &json!({
                        "payload": b64("The receipt payload, dCBOR (`application/access-receipt+cbor`); its `agency` is the chain above."),
                        "cose_sign1": b64("The receipt as the decision point signed it, COSE_Sign1 under usage `receipt`."),
                        "key_excerpt": b64("The binding-signed excerpt of the signing key (CR-58 m.1)."),
                    }),
                    &["payload"],
                ),
            }),
            &["exercise", "domain", "capacity", "agency", "receipt"],
        ),
    })
}

pub(super) fn paths(paths: &mut Map<String, Value>, common: &[(&str, &str); 4]) {
    paths.insert(
        "/access/v1/tenants/{tenant}/subjects:resolve".into(),
        json!({ "post": {
            "operationId": "resolveSubjects",
            "summary": "Between a realm's PartyIDs and the pairwise `sub` one of its clients sees, one direction per call, at most 100 entries; what does not resolve is listed as `unknown` (OP-149 A11). A Party's `sub` is the one the client's tokens carry, assigned now when the client has not seen the subject yet (MD-10).",
            "parameters": [path("tenant", &json!({ "type": "string" }))],
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("ResolveRequest") } } },
            "responses": with(
                problems(&[common[0], common[1], ("404", "tenant-unknown, or client-unknown: no such realm or active client."), common[2], common[3]]),
                "200",
                json_ok("The pairs.", "Resolution"),
            ),
        }}),
    );
    paths.insert(
        "/access/v1/exercises/{id}".into(),
        json!({ "get": {
            "operationId": "getExercise",
            "summary": "An allowed Exercise: its decision record position, intent, actor and the receipt the decision point issued (OP-149 m.9, §9.8).",
            "parameters": [
                path("id", &json!({ "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$", "description": "ExerciseID, base64url of 32 bytes." })),
                query("domain", true, "DomainId", "The authority domain."),
            ],
            "responses": with(
                problems(&[common[0], common[1], ("404", "exercise-unknown: the domain never allowed it."), common[2], common[3]]),
                "200",
                json_ok("The Exercise.", "Exercise"),
            ),
        }}),
    );
    paths.insert(
        "/access/v1/exercises/{id}/agency".into(),
        json!({ "get": {
            "operationId": "getExerciseAgency",
            "summary": "The chain an allowed Exercise's actor acted on behalf of, from the receipt the decision point issued, with that receipt (OP-149 m.11, L2-RCP-1).",
            "parameters": [
                path("id", &json!({ "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$", "description": "ExerciseID, base64url of 32 bytes." })),
                query("domain", true, "DomainId", "The authority domain."),
            ],
            "responses": with(
                problems(&[common[0], common[1], ("404", "exercise-unknown: the domain never allowed it; receipt-unavailable: it was allowed before receipts were kept, so there is no chain to answer with."), common[2], common[3]]),
                "200",
                json_ok("The chain.", "Agency"),
            ),
        }}),
    );
}
