//! The Access Proxy contract (OP-65, OP-156 m.4, m.15 (c)): the paths the proxy reserves on each
//! application host and their `OpenAPI` 3.1 document, committed as `sdks/openapi/proxy-v1.json`.
//! The proxy runs no server of its own (Ek B 5369): the engine sends these paths to Access's
//! forward-auth check like every other request, and Access answers them there.

use serde_json::{Map, Value, json};

/// Version of the contract.
pub const VERSION: &str = "2.0.0";

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
    /// Path on the application host.
    pub path: &'static str,
    /// `operationId`.
    pub operation: &'static str,
    /// What it does.
    pub summary: &'static str,
}

/// Every route.
pub const ROUTES: &[Route] = &[Route {
    verb: Verb::Get,
    path: "/access-proxy/v1/callback",
    operation: "proxyCallback",
    summary: "The OIDC authorization code callback with PKCE: Access's forward-auth check redeems the code, sets the application host's __Host-access-proxy cookie and sends the browser back to the page it asked for (OP-156 m.15 (c)).",
}];

/// The `OpenAPI` document of [`ROUTES`].
#[must_use]
pub fn openapi() -> Value {
    let mut paths = Map::new();
    for r in ROUTES {
        let op = json!({
            "operationId": r.operation,
            "summary": r.summary,
            "parameters": [
                { "name": "code", "in": "query", "required": true, "schema": { "type": "string" } },
                { "name": "state", "in": "query", "required": true, "schema": { "type": "string" } },
            ],
            "responses": {
                "302": {
                    "description": "Signed in: Location is the page first asked for, Set-Cookie the proxy session.",
                    "headers": {
                        "Location": { "schema": { "type": "string" } },
                        "Set-Cookie": { "schema": { "type": "string" } },
                    },
                },
                "401": { "description": "Nginx only: the same answer as 302, which its error_page turns into the redirect." },
                "403": { "$ref": "#/components/responses/Problem" },
                "503": { "$ref": "#/components/responses/Problem" },
                "default": { "$ref": "#/components/responses/Problem" },
            },
            "x-suiss-served-by": "/proxy/v1/check/{engine}",
        });
        let entry = paths
            .entry(String::from(r.path))
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(m) = entry {
            m.insert(String::from(r.verb.name()), op);
        }
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Access Proxy API",
            "version": VERSION,
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
            "description": "The paths Access Proxy reserves on each application host. The engine (Envoy, Caddy, Traefik or Nginx) sends them to Access's forward-auth check like every other request; the proxy runs no server of its own. When Access cannot be reached, every request is refused.",
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
                    },
                },
            },
            "responses": {
                "Problem": {
                    "description": "An RFC 9457 problem.",
                    "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } },
                },
            },
        },
    })
}
