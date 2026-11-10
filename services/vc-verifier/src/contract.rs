//! The verifier contract (OP-65, OP-155 m.3 (p)): the routes of `/vc-verifier/v1/*` and their
//! `OpenAPI` 3.1 document, committed as `sdks/openapi/vc-verifier-v1.json`.

use serde_json::{Map, Value, json};

/// Version of the contract.
pub const VERSION: &str = "1.0.0";

/// A route's method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

impl Verb {
    /// The method in lower case.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Post => "post",
        }
    }
}

/// One route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// Method.
    pub verb: Verb,
    /// Path.
    pub path: &'static str,
    /// `operationId`.
    pub operation: &'static str,
    /// What it does.
    pub summary: &'static str,
    /// Whether a handler serves it.
    pub live: bool,
}

const fn live(
    verb: Verb,
    path: &'static str,
    operation: &'static str,
    summary: &'static str,
) -> Route {
    Route {
        verb,
        path,
        operation,
        summary,
        live: true,
    }
}

/// Every route.
pub const ROUTES: &[Route] = &[
    live(
        Verb::Post,
        "/vc-verifier/v1/presentations",
        "createPresentationRequest",
        "Starts a presentation request for a domain and subject Party (Authorization: Bearer caller key): the DCQL query naming exactly the claims asked, and same-device (with return_uri) or cross-device mode; answers the request URI and the openid4vp:// link the wallet opens, as a link or a QR code (HAIP).",
    ),
    live(
        Verb::Get,
        "/vc-verifier/v1/requests/{request}",
        "getRequestObject",
        "The signed request object the wallet fetches by request_uri (application/oauth-authz-req+jwt).",
    ),
    live(
        Verb::Post,
        "/vc-verifier/v1/responses/{request}",
        "postWalletResponse",
        "The wallet's encrypted direct_post.jwt response (form field response): SD-JWT VC or mdoc, ES256 only, disclosing nothing beyond the DCQL query; a same-device wallet gets a redirect_uri carrying a one-time response_code.",
    ),
    live(
        Verb::Get,
        "/vc-verifier/v1/presentations/{request}",
        "getPresentationResult",
        "The request's outcome for the caller that started it (Authorization: Bearer; same-device needs response_code): verified with the Claims sent to Claim Ingest and their dispositions, refused with a reason, pending or expired; never the disclosed values.",
    ),
    live(
        Verb::Get,
        "/vc-verifier/v1/trusted-lists",
        "getTrustedListState",
        "The trusted lists the verifier loaded (EU LoTL and TLs): sequence number, next update and whether the XAdES signature verified in the parser worker.",
    ),
];

fn parameters(path: &str) -> Vec<Value> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .map(|name| json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string", "maxLength": 255 } }))
        .collect()
}

/// `sdks/openapi/vc-verifier-v1.json`.
#[must_use]
pub fn openapi() -> Value {
    let mut paths = Map::new();
    for r in ROUTES {
        let mut responses = Map::new();
        if r.live {
            responses.insert(
                String::from("200"),
                json!({ "description": "OK", "content": { "application/json": { "schema": { "type": "object" } } } }),
            );
        } else {
            responses.insert(
                String::from("501"),
                json!({ "$ref": "#/components/responses/NotYetServed" }),
            );
        }
        responses.insert(
            String::from("default"),
            json!({ "$ref": "#/components/responses/Problem" }),
        );
        let mut op = Map::new();
        op.insert(String::from("operationId"), Value::from(r.operation));
        op.insert(String::from("summary"), Value::from(r.summary));
        op.insert(String::from("responses"), Value::Object(responses));
        let params = parameters(r.path);
        if !params.is_empty() {
            op.insert(String::from("parameters"), Value::Array(params));
        }
        if r.verb == Verb::Post {
            op.insert(
                String::from("requestBody"),
                json!({ "content": { "application/json": { "schema": { "type": "object" } } } }),
            );
        }
        if !r.live {
            op.insert(String::from("x-suiss-status"), Value::from("planned"));
        }
        let entry = paths
            .entry(String::from(r.path))
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(m) = entry {
            m.insert(String::from(r.verb.name()), Value::Object(op));
        }
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Access VC verifier API",
            "version": VERSION,
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
            "description": "The OID4VP verifier service (HAIP: SD-JWT VC and mdoc, ES256, direct_post.jwt). A verified presentation reaches Claim Ingest as a Claim signed with the verifier's Instance key and counts only where an Acceptance names the verifier. A planned route answers 501 not-yet-served.",
        },
        "paths": Value::Object(paths),
        "components": {
            "schemas": {
                "Problem": {
                    "type": "object",
                    "required": ["type", "title", "status", "code"],
                    "properties": {
                        "type": { "type": "string" },
                        "title": { "type": "string" },
                        "status": { "type": "integer" },
                        "code": { "type": "string" },
                        "detail": { "type": "string" },
                    },
                },
            },
            "responses": {
                "Problem": {
                    "description": "An RFC 9457 problem.",
                    "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } },
                },
                "NotYetServed": {
                    "description": "The route is declared and not served yet (OP-155 m.4).",
                    "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } },
                },
            },
        },
    })
}
