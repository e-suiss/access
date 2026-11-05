//! Stage 6 contract entries that are fixed but not served yet (OP-150 m.2): Claim Ingest
//! (CMP-8), the Token Status List endpoint (OP-150 m.3 (a), (s)) and the members the realm's
//! introspection answer adds for authority tokens. Each path carries `x-suiss-served: false`
//! until the lane that serves it flips it.

use serde_json::{Map, Value, json};

use access_internal_api::claims::UNAVAILABLE as INGEST_UNAVAILABLE;
use access_kernel::status::{CWT_CONTENT_TYPE, JWT_CONTENT_TYPE};

use super::{json_ok, object, path, problems, query, r, text, with};

pub(super) fn components() -> Value {
    let b64 =
        |d: &str| json!({ "type": "string", "pattern": "^[A-Za-z0-9_-]+$", "description": d });
    json!({
        "ClaimSubmission": object(
            &json!({
                "domain": r("DomainId"),
                "carrier": {
                    "type": "string",
                    "enum": ["cose", "unsigned", "webauthn", "oidc", "set"],
                    "description": "How the Claim arrived (§10.1.2). `unsigned` is an `unsigned-claim` whose channel is the caller's own client certificate: a PEP fact (L2-CLM-5).",
                },
                "claim": b64("The Claim as received: a COSE_Sign1 (`application/access-claim+cbor`) or an `unsigned-claim`, CBOR."),
                "body": b64("The body beside it when its class has one (`claim-body-binding`, L2-CLB-1); omitted, the Claim stays digest-valued."),
                "evidence": b64("SHA-256 of the raw carrier artefact kept in the PII vault; never the artefact."),
            }),
            &["domain", "carrier", "claim"],
        ),
        "ClaimVerdict": object(
            &json!({
                "claim": b64("The ClaimID, 16 bytes."),
                "position": r("Position"),
                "disposition": { "type": "string", "enum": ["admit", "quarantine"] },
                "reason": {
                    "type": "string",
                    "enum": ["source-not-accepted", "future", "quota"],
                    "description": "Why a quarantined Claim is held (L2-CLM-3).",
                },
                "replayed": { "type": "boolean", "description": "An earlier submission had already admitted it." },
            }),
            &["claim", "position", "disposition"],
        ),
        "StatusRef": object(
            &json!({
                "status_list": object(
                    &json!({
                        "idx": { "type": "integer", "minimum": 0 },
                        "uri": text("The list's URI."),
                    }),
                    &["idx", "uri"],
                ),
            }),
            &["status_list"],
        ),
        "IntrospectionExtensions": {
            "type": "object",
            "description": "Members an RFC 7662 answer adds for an authority token (OP-150 m.2, (l)); an inactive token answers `active: false` only.",
            "properties": {
                "authorization_details": { "type": "array", "items": { "type": "object" }, "description": "The token's RFC 9396 details: the `kind` (`intent` or `bounds`), the ActionRef type and schema digest, and the Access members." },
                "cnf": {
                    "type": "object",
                    "description": "The key the token is bound to: `jkt` (RFC 9449) or `x5t#S256` (RFC 8705).",
                    "properties": { "jkt": { "type": "string" }, "x5t#S256": { "type": "string" } },
                },
                "exercise": b64("The `projection.issue` ExerciseID."),
                "access_contract": b64("Digest of the token's ValidityContract."),
                "as_of": r("Position"),
                "status": r("StatusRef"),
            },
        },
    })
}

pub(super) fn paths(paths: &mut Map<String, Value>, common: &[(&str, &str); 4]) {
    paths.insert(
        "/access/v1/claims:ingest".into(),
        json!({ "post": {
            "operationId": "ingestClaim",
            "summary": "Records a Claim in a domain and answers its disposition: admitted, or held in quarantine with the reason (CMP-8, §9.13 rule 3). Ingest is not acceptance (INV-2). A Claim that does not verify is refused and not recorded.",
            "x-suiss-served": false,
            "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": true, "schema": { "type": "string" } }],
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("ClaimSubmission") } } },
            "responses": with(
                problems(&[
                    ("400", "claim-signature, claim-payload, claim-value, claim-body or claim-body-digest: refused, not recorded."),
                    common[1],
                    common[2],
                    ("503", &format!("{INGEST_UNAVAILABLE}: retry.")),
                ]),
                "200",
                json_ok("The disposition.", "ClaimVerdict"),
            ),
        }}),
    );
    paths.insert(
        "/access/v1/status-lists/{list}".into(),
        json!({ "get": {
            "operationId": "getStatusList",
            "summary": "A domain's Token Status List (IETF Token Status List, 1 bit per entry; OP-150 m.3 (s)). `iat` and `as_of` are the recorded_at and position the list reflects, not the publication time (T24). An information channel, never the safety mechanism (§9.12.4).",
            "x-suiss-served": false,
            "security": [],
            "parameters": [
                path("list", &json!({ "type": "string" })),
                query("domain", true, "DomainId", "The authority domain."),
            ],
            "responses": with(
                problems(&[common[0], ("404", "status-list-unknown."), common[2], common[3]]),
                "200",
                json!({
                    "description": "The signed list.",
                    "content": {
                        CWT_CONTENT_TYPE: { "schema": { "type": "string", "contentMediaType": "application/cose" }, "description": "COSE_Sign1 under usage `status-list` over `status-list-cwt` (kernel.cddl)." },
                        JWT_CONTENT_TYPE: { "schema": { "type": "string" }, "description": "The same claims as a compact JWS." },
                    },
                }),
            ),
        }}),
    );
}
