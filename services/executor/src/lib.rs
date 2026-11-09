//! Access Executor (B21, AG-40, E62–E64, OP-154 m.3 (u)): a registered executor runs an
//! agent's allowed Exercises durably, one idempotent step at a time, reports each effect as an
//! `effect_attestation` Claim and confirms a stop with an `executor_control` Claim. It decides
//! nothing: every step is an Access decision, and Access never depends on it.
//!
//! This release declares the contract only: [`contract`] is the route table and its `OpenAPI`
//! document, and [`router`] answers every route `501 not-yet-served`.

pub mod contract;

use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, post};

/// The problem a declared route answers until it is served (OP-154 m.4).
#[must_use]
pub fn not_yet_served() -> Response {
    let body = serde_json::json!({
        "type": "urn:suiss:access:problem:not-yet-served",
        "title": "Not Implemented",
        "status": 501,
        "code": "not-yet-served",
        "detail": "The route is declared and not served yet; nothing was read or changed.",
    });
    let mut r = (StatusCode::NOT_IMPLEMENTED, body.to_string()).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

async fn unserved() -> Response {
    not_yet_served()
}

/// The executor's routes, each answering `501 not-yet-served`.
pub fn router() -> Router {
    let mut r = Router::new();
    for route in contract::ROUTES {
        let m: MethodRouter = match route.verb {
            contract::Verb::Get => get(unserved),
            contract::Verb::Post => post(unserved),
        };
        r = r.route(route.path, m);
    }
    r
}
