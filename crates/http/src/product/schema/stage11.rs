//! The Stage 11 routes declared before their lanes serve them (OP-156 m.4): each answers
//! `501 not-yet-served`.

use serde_json::{Map, Value, json};

use super::{object, problems, r};
use crate::stage11::{Method, PLANNED, PROXY_ENGINES, RELAY_STATUS};

/// The relay status schema.
pub(super) fn components() -> Value {
    json!({
        "RelayStatus": object(
            &json!({
                "relay_lag_ms": {
                    "type": ["integer", "null"],
                    "minimum": 0,
                    "description": "Age of the courier's oldest undelivered message in milliseconds; null when none waits.",
                },
                "notifications_delayed": { "type": "boolean", "description": "Whether relay_lag_ms is past 60 s (OP-156 m.3 (c))." },
            }),
            &["relay_lag_ms", "notifications_delayed"],
        ),
    })
}

/// The forward-auth checks, served (IDP-30, OP-156 m.3 (l)).
fn proxy_paths(paths: &mut Map<String, Value>) {
    let mut responses = problems(&[
        (
            "400",
            "invalid-forwarded-request: the engine's method, URI or host header is missing or malformed; refused.",
        ),
        (
            "401",
            "proxy-unregistered: no proxy transport identity, or none registered for the application host. For Nginx, also a sign-in: Location and Set-Cookie say where to.",
        ),
        (
            "503",
            "Access is unreachable; the request is refused (MD-8).",
        ),
    ]);
    responses.insert(
        "200".into(),
        json!({
            "description": "Allowed: Access-Identity carries the application token (access-app+jwt, ES256, 60 s); X-Access-User and X-Access-Email only under idp.proxy.plain_headers. The body is a proxy-decision (proxy.cddl).",
            "content": { "application/json": { "schema": { "type": "object" } } },
        }),
    );
    responses.insert(
        "302".into(),
        json!({ "description": "Sign in, or the end of one: Location and Set-Cookie (__Host-access-proxy-state, __Host-access-proxy) for the browser." }),
    );
    responses.insert(
        "403".into(),
        json!({ "description": "Refused by the domain's decision; the body is a proxy-decision." }),
    );
    let engine = json!([{
        "name": "engine",
        "in": "path",
        "required": true,
        "schema": { "type": "string", "enum": PROXY_ENGINES },
    }]);
    let op = |id: &str, summary: &str, params: &Value| {
        json!({
            "operationId": id,
            "summary": summary,
            "parameters": params,
            "responses": Value::Object(responses.clone()),
        })
    };
    paths.insert(
        "/proxy/v1/check/{engine}".into(),
        json!({
            "get": op("proxyCheck", "The forward-auth check of a registered proxy for one request, in the engine's own protocol (nginx auth_request, Traefik forwardAuth, Caddy forward_auth, Envoy ext_authz HTTP): a real eligibility check of the session's Party, cached by session, application, method and path pattern for at most min(horizon, 30 s); unreachable means refused (IDP-30, OP-156 m.3 (l)).", &engine),
            "post": op("proxyCheckPost", "The same check for an engine that forwards the original method; the body is never read.", &engine),
        }),
    );
    let path = json!([{
        "name": "path",
        "in": "path",
        "required": true,
        "schema": { "type": "string" },
        "description": "The original request's path, appended by Envoy ext_authz.",
    }]);
    paths.insert(
        "/proxy/v1/check/envoy/{path}".into(),
        json!({
            "get": op("proxyCheckEnvoy", "The check as Envoy ext_authz in HTTP service mode asks it: the original method and the original path after the check path; every method is answered alike.", &path),
        }),
    );
}

/// The MCP gateway's questions, served (AG-42, OP-156 m.3 (n)).
fn mcp_paths(paths: &mut Map<String, Value>) {
    let refused = [
        (
            "400",
            "invalid-mcp-call: not one commit of the agent's own statement on a tool of this proxy; nothing was decided.",
        ),
        (
            "401",
            "proxy-unregistered: no proxy transport identity, or none registered for the MCP server's host.",
        ),
        (
            "503",
            "Access is unreachable; the gateway shows and calls nothing (MD-8).",
        ),
    ];
    let mut tools = problems(&refused);
    tools.insert(
        "200".into(),
        json!({
            "description": "{pinned: [name]}: the tools that stand pinned with the definition the gateway sees; the others are not shown.",
            "content": { "application/json": { "schema": { "type": "object" } } },
        }),
    );
    paths.insert(
        crate::mcp_gateway::TOOLS_PATH.into(),
        json!({ "post": {
            "operationId": "mcpGatewayTools",
            "summary": "{host, tools: [{name, pin}]}: which of the tools the MCP server lists now stand pinned by idp.proxy.mcp_pin; a pin is the base64url SHA-256 of the RFC 8785 form of the tool's name, description, inputSchema and annotations (AG-42, OP-156 m.3 (n)).",
            "x-suiss-served": true,
            "responses": Value::Object(tools),
        }}),
    );
    let mut calls = problems(&refused);
    calls.insert(
        "200".into(),
        json!({
            "description": "The ADP's answer to the evaluation, as it gave it; the call is audited once as mcp_gateway.call with its decision, tool and pin, never its arguments.",
            "content": { "application/json": { "schema": { "type": "object" } } },
        }),
    );
    calls.insert(
        "409".into(),
        json!({
            "description": "mcp-tool-unpinned: the tool changed or is new; blocked before any decision until pinned again, audited as mcp_gateway.tool_blocked.",
            "content": { "application/problem+json": { "schema": r("Problem") } },
        }),
    );
    paths.insert(
        crate::mcp_gateway::CALLS_PATH.into(),
        json!({ "post": {
            "operationId": "mcpGatewayCall",
            "summary": "{host, tool, pin, evaluation}: one tool call, the evaluation being the AuthZEN evaluation body of the agent's own commit statement with the gateway as PEP; the actor is the agent's Instance (AG-42, E17, OP-156 m.3 (n)).",
            "x-suiss-served": true,
            "responses": Value::Object(calls),
        }}),
    );
}

/// Every declared route of [`PLANNED`], the served relay status (OP-156 m.3 (c)), the forward-auth
/// checks and the MCP gateway's questions.
pub(super) fn paths(paths: &mut Map<String, Value>) {
    proxy_paths(paths);
    mcp_paths(paths);
    let mut responses = problems(&[("503", "Temporarily unavailable; retry.")]);
    responses.insert(
        "200".into(),
        json!({
            "description": "The status.",
            "content": { "application/json": { "schema": r("RelayStatus") } },
        }),
    );
    paths.insert(
        RELAY_STATUS.into(),
        json!({ "get": {
            "operationId": "getRelayStatus",
            "summary": "{relay_lag_ms, notifications_delayed}: the age of the courier's oldest undelivered message, or null when none waits, and whether it is past 60 s; authority never waits on delivery (OP-156 m.3 (c), E30).",
            "x-suiss-served": true,
            "responses": Value::Object(responses),
        }}),
    );
    for p in PLANNED {
        let method = match p.method {
            Method::Get => "get",
            Method::Post => "post",
        };
        let mut responses = problems(&[
            ("400", "The request is refused; nothing is read."),
            ("503", "Temporarily unavailable; retry."),
        ]);
        responses.insert(
            "501".into(),
            json!({
                "description": "not-yet-served: the route is declared and its lane does not serve it yet; nothing was read or changed (OP-156 m.4).",
                "content": { "application/problem+json": { "schema": r("Problem") } },
            }),
        );
        let mut op = Map::new();
        op.insert("operationId".into(), p.operation.into());
        op.insert("summary".into(), p.summary.into());
        op.insert("x-suiss-status".into(), "planned".into());
        op.insert("responses".into(), Value::Object(responses));
        if p.path.contains("{engine}") {
            op.insert(
                "parameters".into(),
                json!([{
                    "name": "engine",
                    "in": "path",
                    "required": true,
                    "schema": { "type": "string", "enum": PROXY_ENGINES },
                }]),
            );
        }
        let entry = paths
            .entry(p.path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(m) = entry {
            m.insert(method.to_owned(), Value::Object(op));
        }
    }
}
