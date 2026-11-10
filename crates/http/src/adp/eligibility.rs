//! `POST /access/v1/eligibility:set` (§7.9.5.3, E41, OP-156 m.3 (t)): who may approve a Gate
//! of a class, for a coordinator. The body is an `eligible-set` search (the reader's `check`
//! context with `query: {gate_class, resource, digest}`); the answer names the Parties holding
//! `approve:<class>` now, at most 1000, with `truncated` when more were left out. It is derived
//! and advisory, records nothing, and is answered only to a reader the domain allowed to see it.

use access_authority_core::query::Hit;
use access_kernel::json::{Json, b64url_encode};
use serde_json::{Value, json};

use crate::adp::app::{Reply, Service};
use crate::adp::domain::AdpError;
use crate::adp::ports::Pdp;

/// The route.
pub const PATH: &str = "/access/v1/eligibility:set";

/// The search kind behind it.
pub const KIND: &str = "eligible-set";

/// The longest resource reference a query names.
const MAX_RESOURCE: usize = 512;

/// A contribution class: an ident of at most 64 bytes (L0-META-30).
///
/// # Errors
/// [`AdpError`] `query`.
pub fn gate_class(v: &Json) -> Result<String, AdpError> {
    let s = v.as_str().ok_or(AdpError("query"))?;
    let ok = (1..=64).contains(&s.len())
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    ok.then(|| String::from(s)).ok_or(AdpError("query"))
}

/// The Gate's resource as the coordinator names it: opaque, bounded.
///
/// # Errors
/// [`AdpError`] `query`.
pub fn resource(s: String) -> Result<String, AdpError> {
    (!s.is_empty() && s.len() <= MAX_RESOURCE && !s.chars().any(char::is_control))
        .then_some(s)
        .ok_or(AdpError("query"))
}

/// The answer: `{parties, truncated, context: {advisory: true}}` from one search page.
#[must_use]
pub fn encode(hits: &[Hit], truncated: bool) -> Value {
    let parties: Vec<Value> = hits
        .iter()
        .filter_map(|h| match h {
            Hit::Party(p) => Some(Value::from(b64url_encode(&p.0))),
            _ => None,
        })
        .collect();
    json!({
        "parties": parties,
        "truncated": truncated,
        "context": { "advisory": true, "recorded": false },
    })
}

/// Serves one request.
pub async fn set<P: Pdp>(
    service: &Service<P>,
    body: &[u8],
    pep: Option<String>,
    requester: Option<String>,
) -> Reply {
    match service.search(KIND, body, pep, requester).await {
        Reply::Decision(v) => {
            let hits = v
                .get("results")
                .and_then(Value::as_array)
                .map(|r| {
                    r.iter()
                        .filter_map(|h| h.get("id").and_then(Value::as_str))
                        .filter_map(|id| access_kernel::json::b64url_decode(id).ok())
                        .filter_map(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
                        .map(|b| Hit::Party(access_kernel::model::Id(b)))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let truncated = v
                .get("page")
                .and_then(|p| p.get("next_token"))
                .and_then(Value::as_str)
                .is_some_and(|t| !t.is_empty());
            Reply::Decision(encode(&hits, truncated))
        }
        other => other,
    }
}

#[cfg(test)]
mod tests;
