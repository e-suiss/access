//! The executor contract (B21, OP-154 m.3 (u), OP-65): the routes of `/executor/v1/*` and
//! their `OpenAPI` 3.1 document, committed as `sdks/openapi/executor-v1.json`. A job runs one
//! allowed Exercise; its state is `running`, `paused`, `stopped` or `unknown`, and a stop or a
//! pause counts only once the executor confirms it (U5). An outcome is what the executor
//! reports, never truth: `done`, `not-done` or `unknown` (E64).

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
    /// Path, `{name}` for a parameter.
    pub path: &'static str,
    /// `operationId`.
    pub operation: &'static str,
    /// What it does.
    pub summary: &'static str,
    /// The response schema it will answer with.
    pub response: &'static str,
}

const fn route(
    verb: Verb,
    path: &'static str,
    operation: &'static str,
    summary: &'static str,
    response: &'static str,
) -> Route {
    Route {
        verb,
        path,
        operation,
        summary,
        response,
    }
}

/// Every route; none is served yet (OP-154 m.4).
pub const ROUTES: &[Route] = &[
    route(
        Verb::Post,
        "/executor/v1/jobs",
        "startJob",
        "Starts a job for one allowed Exercise of the calling agent Instance; the executor is an Instance of its operator Party and never decides (E62, OP-154 m.3 (u)).",
        "Job",
    ),
    route(
        Verb::Get,
        "/executor/v1/jobs/{job}",
        "getJob",
        "One job: its Exercise, its state (running, paused, stopped, unknown), whether a pause or stop is confirmed, and its steps.",
        "Job",
    ),
    route(
        Verb::Get,
        "/executor/v1/jobs/{job}/steps",
        "listJobSteps",
        "The job's steps: each with its StepRef, idempotency key and reported outcome; a step whose result could not be verified is unknown and is never retried on its own (E62 (3)).",
        "StepPage",
    ),
    route(
        Verb::Post,
        "/executor/v1/jobs/{job}/pause",
        "pauseJob",
        "Pauses the job at its next step; the pause counts once an executor_control Claim confirms it (U5).",
        "Job",
    ),
    route(
        Verb::Post,
        "/executor/v1/jobs/{job}/resume",
        "resumeJob",
        "Resumes a paused job; going on is a new Access decision, never the old one (E63 (2)).",
        "Job",
    ),
    route(
        Verb::Post,
        "/executor/v1/jobs/{job}/stop",
        "stopJob",
        "Stops the job; no further effect once the executor confirms it with an executor_control Claim (U5).",
        "Job",
    ),
    route(
        Verb::Post,
        "/executor/v1/jobs/{job}/steps/{step}/cancel",
        "cancelStep",
        "Cancels an irreversible step inside its delayed-commit window (15 s by default); silence is not approval (E47 (2)).",
        "Job",
    ),
];

fn parameters(path: &str) -> Vec<Value> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .map(|name| json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string", "maxLength": 255 } }))
        .collect()
}

fn schemas() -> Value {
    json!({
        "Problem": {
            "type": "object",
            "description": "RFC 9457 problem details.",
            "required": ["type", "title", "status", "code"],
            "properties": {
                "type": { "type": "string" },
                "title": { "type": "string" },
                "status": { "type": "integer" },
                "code": { "type": "string" },
                "detail": { "type": "string" },
            },
        },
        "Outcome": {
            "type": "string",
            "enum": ["done", "not-done", "unknown"],
            "description": "What the executor reports an effect came to (E64); `done` names at least one evidence kind.",
        },
        "Step": {
            "type": "object",
            "additionalProperties": false,
            "required": ["step", "idempotency_key"],
            "properties": {
                "step": { "type": "string", "description": "The StepRef, a digest." },
                "idempotency_key": { "type": "string", "description": "H(ExerciseID ‖ StepRef), forwarded upstream (E62 (2))." },
                "outcome": { "$ref": "#/components/schemas/Outcome" },
                "evidence": { "type": "array", "items": { "type": "string", "enum": ["upstream-confirmation", "independent-recheck", "browser-observation"] } },
                "commit_at": { "type": "string", "format": "date-time", "description": "When an irreversible step's delayed commit sends it." },
            },
        },
        "Job": {
            "type": "object",
            "additionalProperties": false,
            "required": ["job", "exercise", "state"],
            "properties": {
                "job": { "type": "string" },
                "exercise": { "type": "string", "description": "The ExerciseID the job runs." },
                "state": { "type": "string", "enum": ["running", "paused", "stopped", "unknown"] },
                "confirmed": { "type": "boolean", "description": "Whether an executor_control Claim confirms the pause or stop (U5)." },
                "steps": { "type": "array", "items": { "$ref": "#/components/schemas/Step" } },
            },
        },
        "StepPage": {
            "type": "object",
            "additionalProperties": false,
            "required": ["items"],
            "properties": { "items": { "type": "array", "items": { "$ref": "#/components/schemas/Step" } } },
        },
    })
}

/// `sdks/openapi/executor-v1.json`.
#[must_use]
pub fn openapi() -> Value {
    let mut paths = Map::new();
    for r in ROUTES {
        let mut op = Map::new();
        op.insert(String::from("operationId"), Value::from(r.operation));
        op.insert(String::from("summary"), Value::from(r.summary));
        op.insert(String::from("x-suiss-status"), Value::from("planned"));
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
        op.insert(
            String::from("responses"),
            json!({
                "200": {
                    "description": "OK",
                    "content": { "application/json": { "schema": { "$ref": format!("#/components/schemas/{}", r.response) } } },
                },
                "501": { "$ref": "#/components/responses/NotYetServed" },
                "default": { "$ref": "#/components/responses/Problem" },
            }),
        );
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
            "title": "Access Executor API",
            "version": VERSION,
            "description": "Jobs of a registered executor (B21, AG-40): each runs one allowed Exercise of an agent Instance durably and reports its effects as Claims. The executor decides nothing. A planned route answers 501 not-yet-served.",
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
        },
        "paths": Value::Object(paths),
        "components": {
            "schemas": schemas(),
            "responses": {
                "NotYetServed": {
                    "description": "not-yet-served: declared and not served yet; nothing was read or changed (OP-154 m.4).",
                    "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } },
                },
                "Problem": {
                    "description": "RFC 9457 problem details.",
                    "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } },
                },
            },
        },
    })
}
