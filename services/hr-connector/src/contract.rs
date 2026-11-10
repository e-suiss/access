//! The HR connector contract (OP-65, OP-156 m.4): the routes of `/hr-connector/v1/*` and their `OpenAPI` 3.1
//! document, committed as `sdks/openapi/hr-connector-v1.json`. Every route is served
//! (OP-156 m.3 (q)).

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
        Verb::Get,
        "/hr-connector/v1/connectors",
        "listConnectors",
        "The configured connectors: vendor, the Access HR source they push to, last run.",
    ),
    live(
        Verb::Post,
        "/hr-connector/v1/connectors/{connector}/runs",
        "startRun",
        "Starts a pull from the HR system now, outside the schedule.",
    ),
    live(
        Verb::Get,
        "/hr-connector/v1/connectors/{connector}/runs/{run}",
        "getRun",
        "One run: records read, pushed and refused, never their content.",
    ),
    live(
        Verb::Get,
        "/hr-connector/v1/healthz",
        "connectorHealth",
        "Whether the service can reach Access and its database.",
    ),
];

fn parameters(path: &str) -> Vec<Value> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .map(|name| json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string" } }))
        .collect()
}

/// The `OpenAPI` document of [`ROUTES`].
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
    let problem = json!({
        "description": "An RFC 9457 problem.",
        "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } },
    });
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Access HR connector API",
            "version": VERSION,
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
            "description": "The HR connector service: its connectors, their runs and health. Records reach Access only through the HR batch API. A planned route answers 501 not-yet-served.",
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
                "Problem": problem,
                "NotYetServed": {
                    "description": "not-yet-served: the route is declared and its lane does not serve it yet (OP-156 m.4).",
                    "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } },
                },
            },
        },
    })
}
