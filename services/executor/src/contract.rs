//! The executor contract (B21, OP-154 m.3 (u), OP-65): the routes of `/executor/v1/*` and
//! their `OpenAPI` 3.1 document, committed as `sdks/openapi/executor-v1.json`. A job runs one
//! allowed Exercise; its state is `running`, `paused`, `stopped`, `unknown` or `completed`, and
//! a stop or a pause counts only once the executor confirms it (U5). An outcome is what the
//! executor reports, never truth: `done`, `not-done` or `unknown` (E64).

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
    /// The response schema it answers with.
    pub response: &'static str,
    /// The request body schema, if it takes one.
    pub request: Option<&'static str>,
}

const fn route(
    verb: Verb,
    path: &'static str,
    operation: &'static str,
    summary: &'static str,
    (response, request): (&'static str, Option<&'static str>),
) -> Route {
    Route {
        verb,
        path,
        operation,
        summary,
        response,
        request,
    }
}

/// Every route, each served by [`crate::adapters::router`].
pub const ROUTES: &[Route] = &[
    route(
        Verb::Post,
        "/executor/v1/jobs",
        "startJob",
        "Starts a job for one allowed Exercise of the calling agent Instance; the executor is an Instance of its operator Party and never decides (E62, OP-154 m.3 (u)).",
        ("Job", Some("StartJob")),
    ),
    route(
        Verb::Get,
        "/executor/v1/jobs/{job}",
        "getJob",
        "One job: its Exercise, its state (running, paused, stopped, unknown, completed), whether a pause or stop is confirmed, and its steps.",
        ("Job", None),
    ),
    route(
        Verb::Get,
        "/executor/v1/jobs/{job}/steps",
        "listJobSteps",
        "The job's steps: each with its StepRef, idempotency key and reported outcome; a step whose result could not be verified is unknown and is never retried on its own (E62 (3)).",
        ("StepPage", None),
    ),
    route(
        Verb::Post,
        "/executor/v1/jobs/{job}/pause",
        "pauseJob",
        "Pauses the job at its next step; the pause counts once an executor_control Claim confirms it (U5).",
        ("Job", None),
    ),
    route(
        Verb::Post,
        "/executor/v1/jobs/{job}/resume",
        "resumeJob",
        "Resumes a paused job with the actor's new continue statements; going on is a new Access decision, never the old one (E63 (2)).",
        ("Job", Some("Resume")),
    ),
    route(
        Verb::Post,
        "/executor/v1/jobs/{job}/stop",
        "stopJob",
        "Stops the job; no further effect once the executor confirms it with an executor_control Claim (U5).",
        ("Job", None),
    ),
    route(
        Verb::Post,
        "/executor/v1/jobs/{job}/steps/{step}/cancel",
        "cancelStep",
        "Cancels an irreversible step inside its delayed-commit window (15 s by default), and the job stops; silence is not approval (E47 (2)).",
        ("Job", None),
    ),
];

fn parameters(path: &str) -> Vec<Value> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .map(|name| json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string", "maxLength": 255 } }))
        .collect()
}

fn request_schemas() -> Value {
    json!({
        "StepSpec": {
            "type": "object",
            "additionalProperties": false,
            "required": ["name", "action", "resource", "reversibility", "call"],
            "properties": {
                "name": { "type": "string", "minLength": 1, "maxLength": 64 },
                "action": { "type": "string", "description": "`namespace/name`; the Exercise's action." },
                "resource": { "type": "string", "description": "`namespace:segment/segment`; one of the Exercise's resources." },
                "reversibility": { "type": "string", "enum": ["reversible", "compensable", "irreversible"] },
                "idempotent": { "type": "boolean", "description": "Whether the upstream honours the idempotency key; only then is a request whose answer a crash lost sent again, once, with the same key (TI-6)." },
                "call": {
                    "oneOf": [
                        {
                            "type": "object",
                            "required": ["driver", "method", "url"],
                            "properties": {
                                "driver": { "const": "http" },
                                "method": { "type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"] },
                                "url": { "type": "string", "description": "https only." },
                                "body": {},
                            },
                        },
                        {
                            "type": "object",
                            "required": ["driver", "server", "tool"],
                            "properties": {
                                "driver": { "const": "mcp" },
                                "server": { "type": "string", "description": "The MCP server's https endpoint." },
                                "tool": { "type": "string" },
                                "arguments": {},
                            },
                        },
                    ],
                },
            },
        },
        "StartJob": {
            "type": "object",
            "additionalProperties": false,
            "required": ["realm", "connection", "intent", "ais", "steps"],
            "properties": {
                "realm": { "type": "string", "description": "The realm whose token vault holds the connection." },
                "connection": { "type": "string", "description": "The vault connection the Exercise's token is released from." },
                "intent": { "type": "string", "description": "The intent envelope, canonical bytes, base64url." },
                "ais": { "type": "string", "description": "The actor Instance's commit statement naming this executor as PEP, base64url; the executor forwards it and is never the actor." },
                "steps": { "type": "array", "minItems": 1, "maxItems": 32, "items": { "$ref": "#/components/schemas/StepSpec" } },
                "continuations": { "type": "array", "maxItems": 64, "items": { "type": "string" }, "description": "The actor's continue statements for the checkpoints ahead, base64url; a checkpoint without one pauses the job." },
            },
        },
        "Resume": {
            "type": "object",
            "additionalProperties": false,
            "required": ["continuations"],
            "properties": { "continuations": { "type": "array", "minItems": 1, "maxItems": 64, "items": { "type": "string" } } },
        },
    })
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
            "required": ["step", "name", "idempotency_key"],
            "properties": {
                "step": { "type": "string", "description": "The StepRef, a digest." },
                "name": { "type": "string" },
                "idempotency_key": { "type": "string", "description": "H(ExerciseID ‖ StepRef), forwarded upstream (E62 (2))." },
                "outcome": { "$ref": "#/components/schemas/Outcome" },
                "evidence": { "type": "array", "items": { "type": "string", "enum": ["upstream-confirmation", "independent-recheck", "browser-observation"] } },
                "commit_at_ms": { "type": "integer", "description": "When an irreversible step's delayed commit sends it, Unix milliseconds; it can be cancelled until then." },
                "claim": { "type": "string", "description": "The ClaimID of the step's effect_attestation." },
                "report_refused": { "type": "string", "description": "Why Claim Ingest refused the attestation; the job then stops." },
            },
        },
        "Job": {
            "type": "object",
            "additionalProperties": false,
            "required": ["job", "exercise", "kind", "state", "confirmed", "steps"],
            "properties": {
                "job": { "type": "string" },
                "exercise": { "type": "string", "description": "The ExerciseID the job runs." },
                "kind": { "type": "string", "enum": ["cloud", "customer", "local"], "description": "The registered executor's kind; every kind follows the same rules (E57 (1))." },
                "state": { "type": "string", "enum": ["running", "paused", "stopped", "unknown", "completed"] },
                "confirmed": { "type": "boolean", "description": "Whether an executor_control Claim confirms the pause or stop (U5)." },
                "reason": { "type": "string", "description": "Why it stopped or waits: person, decision, horizon, envelope, silence, cancel, release, report, continuation, unknown, blocked or approval." },
                "handoff_until_ms": { "type": "integer", "description": "When a job waiting for a person stops if nobody answered; silence is not approval." },
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

fn merged() -> Value {
    let mut all = schemas();
    if let (Some(a), Value::Object(b)) = (all.as_object_mut(), request_schemas()) {
        a.extend(b);
    }
    all
}

/// `sdks/openapi/executor-v1.json`.
#[must_use]
pub fn openapi() -> Value {
    let mut paths = Map::new();
    for r in ROUTES {
        let mut op = Map::new();
        op.insert(String::from("operationId"), Value::from(r.operation));
        op.insert(String::from("summary"), Value::from(r.summary));
        op.insert(String::from("x-suiss-served"), Value::Bool(true));
        let params = parameters(r.path);
        if !params.is_empty() {
            op.insert(String::from("parameters"), Value::Array(params));
        }
        if let Some(req) = r.request {
            op.insert(
                String::from("requestBody"),
                json!({ "required": true, "content": { "application/json": { "schema": { "$ref": format!("#/components/schemas/{req}") } } } }),
            );
        }
        op.insert(
            String::from("responses"),
            json!({
                "200": {
                    "description": "OK",
                    "content": { "application/json": { "schema": { "$ref": format!("#/components/schemas/{}", r.response) } } },
                },
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
            "description": "Jobs of a registered executor (B21, AG-40): each runs one allowed Exercise of an agent Instance durably and reports its effects as Claims. The executor decides nothing. Problem codes: executor-malformed, executor-ais, executor-intent, executor-nonce, executor-steps, executor-step, executor-continuation (400); executor-not-allowed (403); executor-unknown-job (404); executor-job-ended, executor-not-paused, executor-unknown-step, executor-step-sent, executor-stale (409); executor-unavailable (503).",
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
        },
        "paths": Value::Object(paths),
        "components": {
            "schemas": merged(),
            "responses": {
                "Problem": {
                    "description": "RFC 9457 problem details.",
                    "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } },
                },
            },
        },
    })
}
