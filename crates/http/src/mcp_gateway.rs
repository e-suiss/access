//! `/proxy/v1/mcp/*` (AG-42, B22, IDP-30, OP-156 m.3 (n)): the MCP gateway, a proxy registered
//! for the MCP server's host, asks here before it shows or calls a tool.
//!
//! - `POST /proxy/v1/mcp/tools` `{host, tools: [{name, pin}]}`: which of the tools the server
//!   lists now stand pinned, `{pinned: [name]}`.
//! - `POST /proxy/v1/mcp/calls` `{host, tool, pin, evaluation}`: one call; `evaluation` is the
//!   `AuthZEN` evaluation body of the agent's own `commit` statement, as text. A tool that does
//!   not stand pinned is `409 mcp-tool-unpinned` before any decision; otherwise the evaluation's
//!   answer comes back as the ADP gave it.
//!
//! The gateway is named by its transport only, as in [`crate::proxy`].

use std::sync::Arc;

use access_identity_proxy::mcp::{Gateway, McpPorts, McpRefusal, Observed, ToolCall};
use access_kernel::json::{b64url_decode, b64url_encode};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde_json::{Value, json};

use crate::adp::adapters::Pep;
use crate::problem::codes;
use crate::tls::MtlsChain;

/// `POST`: the list check.
pub const TOOLS_PATH: &str = "/proxy/v1/mcp/tools";

/// `POST`: one call.
pub const CALLS_PATH: &str = "/proxy/v1/mcp/calls";

/// Largest body read.
pub const MAX_BODY: usize = 1 << 20;

fn pep_of(pep: Option<&Pep>, chain: Option<&MtlsChain>) -> Option<String> {
    pep.map(|p| p.0.clone()).or_else(|| {
        chain
            .and_then(|c| c.0.first())
            .map(|leaf| b64url_encode(&suiss_crypto::digest::sha256(leaf)))
    })
}

fn refused(r: McpRefusal) -> Response {
    // OP-67
    tracing::info!(event = "proxy.check.refused", engine = "mcp", reason = %r, "MCP gateway request refused");
    match r {
        McpRefusal::Unregistered => codes::realm::PROXY_UNREGISTERED.problem().into_response(),
        McpRefusal::Malformed(_) => codes::realm::INVALID_MCP_CALL.problem().into_response(),
        McpRefusal::Blocked(_) => codes::realm::MCP_TOOL_UNPINNED.problem().into_response(),
        McpRefusal::Unavailable => {
            let mut res = codes::UNAVAILABLE.problem().into_response();
            res.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from(crate::proxy::RETRY_AFTER_S),
            );
            res
        }
    }
}

fn malformed() -> Response {
    refused(McpRefusal::Malformed("body"))
}

fn pin_of(v: Option<&Value>) -> Option<[u8; 32]> {
    let b = b64url_decode(v?.as_str()?).ok()?;
    <[u8; 32]>::try_from(b.as_slice()).ok()
}

fn observed(v: &Value) -> Option<Vec<Observed>> {
    v.as_array()?
        .iter()
        .map(|t| {
            let m = t.as_object()?;
            (m.len() == 2).then_some(())?;
            Some(Observed {
                name: String::from(m.get("name")?.as_str()?),
                pin: pin_of(m.get("pin"))?,
            })
        })
        .collect()
}

struct Shared<P> {
    gateway: Arc<Gateway<P>>,
}

type Caller = (
    Option<axum::Extension<Pep>>,
    Option<axum::Extension<MtlsChain>>,
);

fn caller((pep, chain): &Caller) -> Option<String> {
    pep_of(
        pep.as_ref().map(|axum::Extension(p)| p),
        chain.as_ref().map(|axum::Extension(c)| c),
    )
}

fn parsed(body: &Bytes, members: &[&str]) -> Option<serde_json::Map<String, Value>> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let m = v.as_object()?;
    (m.len() == members.len() && members.iter().all(|k| m.contains_key(*k))).then(|| m.clone())
}

async fn tools<P: McpPorts + 'static>(
    State(s): State<Arc<Shared<P>>>,
    pep: Option<axum::Extension<Pep>>,
    chain: Option<axum::Extension<MtlsChain>>,
    body: Bytes,
) -> Response {
    let pep = caller(&(pep, chain));
    let Some(m) = parsed(&body, &["host", "tools"]) else {
        return malformed();
    };
    let (Some(host), Some(observed)) = (
        m.get("host").and_then(Value::as_str),
        m.get("tools").and_then(observed),
    ) else {
        return malformed();
    };
    match s.gateway.tools(pep.as_deref(), host, &observed).await {
        Ok(pinned) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            axum::Json(json!({ "pinned": pinned })),
        )
            .into_response(),
        Err(r) => refused(r),
    }
}

async fn calls<P: McpPorts + 'static>(
    State(s): State<Arc<Shared<P>>>,
    pep: Option<axum::Extension<Pep>>,
    chain: Option<axum::Extension<MtlsChain>>,
    body: Bytes,
) -> Response {
    let pep = caller(&(pep, chain));
    let Some(m) = parsed(&body, &["host", "tool", "pin", "evaluation"]) else {
        return malformed();
    };
    let (Some(host), Some(tool), Some(pin), Some(evaluation)) = (
        m.get("host").and_then(Value::as_str),
        m.get("tool").and_then(Value::as_str),
        pin_of(m.get("pin")),
        m.get("evaluation").and_then(Value::as_str),
    ) else {
        return malformed();
    };
    let Ok(decoded) = crate::adp::domain::decode(evaluation.as_bytes(), MAX_BODY) else {
        return malformed();
    };
    let call = ToolCall {
        pep: pep.as_deref(),
        host,
        tool,
        pin: &pin,
        domain: decoded.request.domain,
        mode: decoded.request.mode,
        nonce: &decoded.request.nonce,
        intent: &decoded.request.intent,
        statement: decoded.ais.is_some(),
        evaluation: evaluation.as_bytes(),
    };
    match s.gateway.call(&call).await {
        Ok(e) => {
            let mut res = (
                StatusCode::from_u16(e.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
                e.body,
            )
                .into_response();
            let h = res.headers_mut();
            if let Some(v) = e.content_type.and_then(|c| HeaderValue::from_str(&c).ok()) {
                h.insert(header::CONTENT_TYPE, v);
            }
            if let Some(v) = e.key_excerpt.and_then(|c| HeaderValue::from_str(&c).ok()) {
                h.insert("access-key-excerpt", v);
            }
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            res
        }
        Err(r) => refused(r),
    }
}

/// The MCP gateway routes over `gateway`.
pub fn router<P: McpPorts + 'static>(gateway: Arc<Gateway<P>>) -> Router {
    Router::new()
        .route(TOOLS_PATH, post(tools::<P>))
        .route(CALLS_PATH, post(calls::<P>))
        .with_state(Arc::new(Shared { gateway }))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
}
