//! The realm SSF routes the contract names beside the transmitter metadata (OP-151 m.3 (l), E30):
//! the RFC 8935 receiver of a declared upstream transmitter and the receivers' semantic
//! acknowledgement. Both also live under `/realms/{slug}` for a path issuer.

use serde_json::{Map, Value, json};

use super::{object, path, problems, r, text};

/// The receiver and acknowledgement schemas.
pub(super) fn components() -> Value {
    json!({
        "SsfError": object(
            &json!({
                "err": {
                    "type": "string",
                    "enum": ["invalid_request", "invalid_key", "invalid_issuer", "invalid_audience", "access_denied"],
                },
                "description": text("Why the SET was refused."),
            }),
            &["err", "description"],
        ),
        "SemanticAck": object(
            &json!({
                "jti": text("The SET the receiver was delivered."),
                "state": { "type": "string", "enum": ["applied", "ignored"] },
            }),
            &["jti", "state"],
        ),
    })
}

/// `POST /ssf/inbound/{stream}` and `POST /ssf/ack`.
pub(super) fn paths(paths: &mut Map<String, Value>) {
    paths.insert(
        "/ssf/inbound/{stream}".into(),
        json!({ "post": {
            "operationId": "pushInboundSet",
            "summary": "RFC 8935 push of one SET from the upstream transmitter `idp.upstream.register` declared as `stream` (OP-151 m.3 (l), TN-42). The SET is verified against the transmitter's JWKS (ES256 or RS256), its `iss`, `aud`, `iat` within 5 minutes and one declared event; it is taken once by `jti`. It becomes a Claim or ends the linked subject's sessions; it never revokes a Grant and never widens (§9.16.2 k.4).",
            "security": [],
            "parameters": [path("stream", &json!({ "type": "string", "format": "uuid" }))],
            "requestBody": {
                "required": true,
                "content": { "application/secevent+jwt": { "schema": { "type": "string" } } },
            },
            "responses": {
                "202": { "description": "Taken, or a `jti` taken before." },
                "400": {
                    "description": "Refused (RFC 8935 §2.3).",
                    "content": { "application/json": { "schema": r("SsfError") } },
                },
                "404": { "description": "No live push transmitter with this id in the realm." },
                "413": { "description": "The SET is larger than 64 KiB." },
                "503": { "description": "Temporarily unavailable; the transmitter retries." },
            },
        }}),
    );
    paths.insert(
        "/ssf/ack".into(),
        json!({ "post": {
            "operationId": "ackSet",
            "summary": "A receiver's semantic acknowledgement of a SET its stream was delivered, apart from the delivery ack (E30). By the stream's bearer credential.",
            "security": [{ "stream_bearer": [] }],
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("SemanticAck") } } },
            "responses": with_204(problems(&[
                ("400", "The body is not an acknowledgement."),
                ("401", "No live stream for the credential."),
                ("404", "The stream was never delivered this SET, or it was acknowledged before."),
                ("503", "Temporarily unavailable; retry."),
            ])),
        }}),
    );
}

fn with_204(mut responses: Map<String, Value>) -> Value {
    responses.insert("204".into(), json!({ "description": "Recorded." }));
    Value::Object(responses)
}

/// The stream credential scheme.
pub(super) fn scheme() -> Value {
    json!({
        "type": "http",
        "scheme": "bearer",
        "description": "A poll stream's bearer credential, shown once at creation (RFC 6750, OP-149 m.7).",
    })
}
