//! The platform product routes of the contract (OP-149 m.4, m.16 (a), m.17 (e), (g)): pairing
//! with a tenant by self-signed Exercises and the platform client's event streams. Their
//! caller is a platform client authenticated by `private_key_jwt`, not a client certificate.

use serde_json::{Map, Value, json};

use super::{json_ok, object, path, problems, r, text, with};

/// The security of a platform route.
fn security() -> Value {
    json!([{ "platform_client": [] }])
}

/// The security scheme of the platform routes.
pub(super) fn scheme() -> Value {
    json!({
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": "An RFC 7523 client assertion (private_key_jwt) of an active platform_product client, signed with its registered client key: iss = sub = client_id, aud = the platform realm's issuer (or the full URL of the endpoint called), exp at most 5 minutes ahead, jti used once. ES256 (OP-149 m.4).",
    })
}

pub(super) fn components() -> Value {
    let b64 =
        |d: &str| json!({ "type": "string", "pattern": "^[A-Za-z0-9_-]+$", "description": d });
    let uuid = |d: &str| {
        json!({
            "type": "string",
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            "description": d,
        })
    };
    let exercise = |what: &str| {
        object(
            &json!({
                "nonce": b64(&format!("The {what} nonce.")),
                "intent": b64(&format!("Digest of the {what} intent (L0-ENC-23): `access/{what}` on `access.party:[hex(party)]`, the payload digest in `opaque[\"payload\"]`, validity `valid_from`..`valid_until`.")),
            }),
            &["nonce", "intent"],
        )
    };
    json!({
        "PairingChallengeRequest": object(
            &json!({
                "realms": {
                    "type": "array",
                    "items": uuid("A live realm of the tenant, as the tenant snapshot names it."),
                    "minItems": 1,
                    "maxItems": 64,
                    "description": "The realms to pair with; every live realm of the tenant when absent (OP-149 m.16 (d)).",
                },
            }),
            &[],
        ),
        "PairingExercise": exercise("instance_create"),
        "PairingRegister": exercise("party_register"),
        "PairingTarget": object(
            &json!({
                "realm": uuid("The realm."),
                "status": { "type": "string", "enum": ["unpaired", "paired", "refused"] },
                "domain": b64("The realm's governing DomainID, 32 bytes."),
                "basis": b64("The Genesis bootstrap Grant the Exercises name as `public` basis (L0-META-7)."),
                "pep": text("The PEP the AIS addresses: the identity plane."),
                "party": b64("The product's system Party in the domain, 16 bytes; new until its party_register commits."),
                "instance": b64("The service Instance, 16 bytes (paired)."),
                "kid": b64("RFC 7638 thumbprint of the registered service key (CR-24)."),
                "challenge": b64("32 bytes: the instance_create nonce; party_register uses it followed by 0x01 (OP-149 m.17b (e))."),
                "valid_from": text("RFC 3339: start of the intents' validity."),
                "valid_until": text("RFC 3339: end of it; the challenge is not accepted later."),
                "instance_create": r("PairingExercise"),
                "party_register": r("PairingRegister"),
                "code": text("Why the authority plane refused (refused)."),
            }),
            &["realm", "status"],
        ),
        "PairingChallenges": object(
            &json!({
                "tenant": text("The tenant (`tnt_…`)."),
                "targets": { "type": "array", "items": r("PairingTarget") },
            }),
            &["tenant", "targets"],
        ),
        "PairingAnswer": object(
            &json!({
                "realm": uuid("The realm of the challenge."),
                "challenge": b64("The challenge answered."),
                "ais": b64("AIS (tagged COSE_Sign1) by the service key over the instance_create intent: nonce the challenge, mode commit, capacity own, the challenge's domain, basis and pep."),
                "register_ais": b64("AIS by the service key over the party_register intent (the Party roots itself, actor kind system); exactly when the challenge names party_register."),
            }),
            &["realm", "challenge", "ais"],
        ),
        "PairingRequest": object(
            &json!({
                "targets": { "type": "array", "items": r("PairingAnswer"), "minItems": 1, "maxItems": 64 },
            }),
            &["targets"],
        ),
        "PairingResult": object(
            &json!({
                "tenant": text("The tenant (`tnt_…`)."),
                "targets": { "type": "array", "items": r("PairingTarget") },
                "event_stream": uuid("The client's SSF push stream to its `suiss_event_receiver`, opened on its first pairing; the same for every tenant (OP-149 m.17 (e))."),
            }),
            &["tenant", "targets"],
        ),
        "PlatformStream": {
            "type": "object",
            "description": "An SSF 1.0 §8.1.1 stream configuration with `status`; its schema is `sdks/openapi/events/stream.schema.json`. At creation a webhook stream also carries its `secret` and a poll stream its `access_token`, shown once.",
        },
        "PlatformStreams": object(
            &json!({ "streams": { "type": "array", "items": r("PlatformStream") } }),
            &["streams"],
        ),
    })
}

pub(super) fn paths(paths: &mut Map<String, Value>) {
    let auth = (
        "401",
        "No valid client assertion of an active platform client.",
    );
    let down = ("503", "Temporarily unavailable; retry.");
    let tenant = path("tenant", &json!({ "type": "string" }));
    paths.insert(
        "/access/v1/tenants/{tenant}/pairing/challenges".into(),
        json!({ "post": {
            "operationId": "createPairingChallenges",
            "summary": "For each realm, the Instance an earlier pairing with the current service key opened, or a challenge and what the product's own party_register and instance_create name (OP-149 m.4, m.16 (a)). A challenge still valid is handed out again.",
            "security": security(),
            "parameters": [tenant.clone()],
            "requestBody": { "required": false, "content": { "application/json": { "schema": r("PairingChallengeRequest") } } },
            "responses": with(
                problems(&[("400", "invalid-request, realms or unknown-member."), auth, ("404", "tenant-unknown or realm-unknown."), down]),
                "201",
                json_ok("The targets.", "PairingChallenges"),
            ),
        }}),
    );
    paths.insert(
        "/access/v1/tenants/{tenant}/pairing".into(),
        json!({ "post": {
            "operationId": "pair",
            "summary": "The product's self-signed Exercises for the challenged realms (L0-META-7): Access binds the service key to the product's Party, forwards them to each governing domain and records the Instance. A target the authority plane refuses is reported, not retried. Once a target is paired, the client's SSF push stream to its suiss_event_receiver is opened, once (OP-149 m.17 (e)).",
            "security": security(),
            "parameters": [tenant],
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("PairingRequest") } } },
            "responses": with(
                problems(&[("400", "invalid-challenge, invalid-party, invalid-request, targets or unknown-member."), auth, ("404", "tenant-unknown or realm-unknown."), down]),
                "200",
                json_ok("Each target paired or refused.", "PairingResult"),
            ),
        }}),
    );
    paths.insert(
        "/access/v1/platform/streams".into(),
        json!({
            "post": {
                "operationId": "createPlatformStream",
                "summary": "A stream the platform client owns: it receives every tenant's events, each SET naming its tenant in access_tenant (OP-149 m.17 (e), (g)). The body is an SSF stream request (`sdks/openapi/events/stream-request.schema.json`).",
                "security": security(),
                "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object" } } } },
                "responses": with(
                    problems(&[("400", "The stream request is not valid."), auth, ("409", "stream-exists: a live stream to that endpoint."), down]),
                    "201",
                    json_ok("The stream.", "PlatformStream"),
                ),
            },
            "get": {
                "operationId": "listPlatformStreams",
                "summary": "The platform client's streams, live first.",
                "security": security(),
                "responses": with(problems(&[auth, down]), "200", json_ok("The streams.", "PlatformStreams")),
            },
        }),
    );
    let id = path(
        "id",
        &json!({ "type": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" }),
    );
    paths.insert(
        "/access/v1/platform/streams/{id}".into(),
        json!({
            "get": {
                "operationId": "getPlatformStream",
                "summary": "One stream the platform client owns.",
                "security": security(),
                "parameters": [id.clone()],
                "responses": with(problems(&[auth, ("404", "no-such-stream."), down]), "200", json_ok("The stream.", "PlatformStream")),
            },
            "delete": {
                "operationId": "closePlatformStream",
                "summary": "Disables a live stream the platform client owns; nothing is deleted (OP-73).",
                "security": security(),
                "parameters": [id],
                "responses": with(problems(&[auth, ("404", "no-such-stream."), down]), "204", json!({ "description": "Disabled." })),
            },
        }),
    );
}
