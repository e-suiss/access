//! The drivers (OP-154 m.3 (u), AG-39): the generic OAuth HTTP driver for an upstream of the
//! vault's catalogue and the MCP client driver for an official MCP server. A driver shapes one
//! request and reads one answer; it holds no state and decides nothing. Every request carries
//! the step's idempotency key (E62 (2)); the released token is added only when it is sent.

use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use serde_json::{Value, json};

use crate::domain::history::Reading;
use crate::domain::step::{Call, StepSpec};
use crate::domain::webbot::USER_AGENT;

/// The MCP protocol version the client driver speaks.
pub const MCP_VERSION: &str = "2025-06-18";

/// The `_meta` name the MCP driver forwards the idempotency key under.
pub const MCP_IDEMPOTENCY: &str = "io.suiss.access/idempotency_key";

/// One upstream request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    /// Method.
    pub method: String,
    /// `https` URL.
    pub url: String,
    /// Headers, in order.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// The digest the outbox records: method, URL and body, never a credential (TI-6).
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(self.body.len().saturating_add(self.url.len()));
        bytes.extend_from_slice(self.method.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(self.url.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&self.body);
        suiss_crypto::digest::context_digest("access/executor/request/v1", &bytes).0
    }
}

/// The request of `spec`, keyed by `key`.
#[must_use]
pub fn request(spec: &StepSpec, key: &Digest) -> HttpRequest {
    let key = b64url_encode(&key.0);
    let mut headers = vec![
        (String::from("User-Agent"), String::from(USER_AGENT)),
        (String::from("Idempotency-Key"), key.clone()),
    ];
    match &spec.call {
        Call::Http { method, url, body } => {
            headers.push((String::from("Accept"), String::from("application/json")));
            let body = body.as_ref().map(Value::to_string).unwrap_or_default();
            if !body.is_empty() {
                headers.push((
                    String::from("Content-Type"),
                    String::from("application/json"),
                ));
            }
            HttpRequest {
                method: method.clone(),
                url: url.clone(),
                headers,
                body: body.into_bytes(),
            }
        }
        Call::Mcp {
            server,
            tool,
            arguments,
        } => {
            headers.extend([
                (
                    String::from("Accept"),
                    String::from("application/json, text/event-stream"),
                ),
                (
                    String::from("Content-Type"),
                    String::from("application/json"),
                ),
                (
                    String::from("MCP-Protocol-Version"),
                    String::from(MCP_VERSION),
                ),
            ]);
            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": tool, "arguments": arguments, "_meta": { MCP_IDEMPOTENCY: key } },
            });
            HttpRequest {
                method: String::from("POST"),
                url: server.clone(),
                headers,
                body: body.to_string().into_bytes(),
            }
        }
    }
}

const fn http_reading(status: u16) -> Reading {
    match status {
        200..=299 => Reading::Confirmed,
        403 | 429 => Reading::Blocked,
        409 | 412 => Reading::Conflict,
        400..=407 | 410..=411 | 413..=428 | 430..=499 => Reading::Refused,
        _ => Reading::Unclear,
    }
}

/// The JSON-RPC message of an MCP answer: the body, or the last `data:` line of an event stream.
fn mcp_message(body: &[u8]) -> Option<Value> {
    if let Ok(v) = serde_json::from_slice::<Value>(body) {
        return Some(v);
    }
    let text = std::str::from_utf8(body).ok()?;
    text.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
        .next_back()
}

/// How `spec`'s driver reads an answer of `status` with `body`.
#[must_use]
pub fn read(spec: &StepSpec, status: u16, body: &[u8]) -> Reading {
    match &spec.call {
        Call::Http { .. } => http_reading(status),
        Call::Mcp { .. } => {
            if status != 200 {
                return match http_reading(status) {
                    Reading::Confirmed => Reading::Unclear,
                    other => other,
                };
            }
            let Some(m) = mcp_message(body) else {
                return Reading::Unclear;
            };
            if m.get("error").is_some() {
                return Reading::Refused;
            }
            match m.get("result") {
                Some(r) if r.get("isError") == Some(&Value::Bool(true)) => Reading::Refused,
                Some(_) => Reading::Confirmed,
                None => Reading::Unclear,
            }
        }
    }
}
