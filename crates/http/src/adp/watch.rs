//! `GET /access/v1/domains/{domain}/watch?from=<pos>&wait=<ms>` (§9.7A.2, OP-158 m.3 (u)): long
//! polling for the records after `from`, each with its trusted time and the kinds of state it
//! changed, and `witnessed_through`. Only an authenticated PEP is answered; the answer is
//! advisory, never cached (`Cache-Control: no-store`) and never a source of ALLOW.

use std::time::Duration;

use access_authority_core::app::watch::{MAX_WAIT, Watched};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::Problem;
use access_identity_oauth::domain::request::Params;

/// The route.
pub const PATH: &str = "/access/v1/domains/{domain}/watch";

/// How long a request without `wait` waits, in milliseconds.
pub const DEFAULT_WAIT_MS: u64 = 10_000;

/// `from` and `wait` from the query string; a missing or malformed `from`, or a repeated
/// parameter, is refused.
///
/// # Errors
/// The name of the refused parameter.
pub fn query(query: Option<&str>) -> Result<(u64, Duration), &'static str> {
    let params = Params::parse(query.unwrap_or_default()).map_err(|_| "query")?;
    let from = params
        .get("from")
        .and_then(canonical_u64)
        .ok_or("from")?;
    let wait = match params.get("wait") {
        None => DEFAULT_WAIT_MS,
        Some(v) => canonical_u64(v).ok_or("wait")?,
    };
    Ok((from, Duration::from_millis(wait).min(MAX_WAIT)))
}

fn canonical_u64(v: &str) -> Option<u64> {
    let n: u64 = v.parse().ok()?;
    (n.to_string() == v).then_some(n)
}

/// The JSON answer.
#[must_use]
pub fn body(w: &Watched) -> Value {
    json!({
        "changes": w.changes.iter().map(|c| json!({
            "position": c.position,
            "recorded_at": c.recorded_at,
            "kinds": c.kinds.iter().collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "next": w.next,
        "head": w.head,
        "witnessed_through": w.witnessed_through,
        "advisory": true,
    })
}

/// The answer as sent.
#[must_use]
pub fn respond(w: &Watched) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body(w).to_string(),
    )
        .into_response()
}

/// A refused query parameter.
#[must_use]
pub fn bad(name: &'static str) -> Response {
    Problem::new(
        axum::http::StatusCode::BAD_REQUEST,
        "protocol",
        "Protocol Error",
    )
    .with_reason(Some(name))
    .into_response()
}

#[cfg(test)]
mod tests;
