//! The OID4VP verifier service (OP-155 m.3 (p), IDP-21, E55): it asks a wallet for a
//! presentation under the HAIP profile (SD-JWT VC and mdoc, ES256, `direct_post.jwt`), checks it
//! against the trusted lists, and sends what it verified to Claim Ingest as a Claim signed with
//! its own Instance key; the presentation counts only where an Acceptance names the verifier. It
//! uses public crates only (OP-62) and holds no authority.
//!
//! Every route is declared in [`contract`] and answers `501 not-yet-served` until it is served.

pub mod contract;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::contract::{ROUTES, Verb};

/// The RFC 9457 problem a declared route answers before it is served.
fn not_yet_served() -> Response {
    let body = serde_json::json!({
        "type": "urn:suiss:access:problem:not-yet-served",
        "title": "Not Implemented",
        "status": 501,
        "code": "not-yet-served",
        "detail": "The route is declared and not served yet; nothing was read or changed (OP-155 m.4).",
    });
    (
        StatusCode::NOT_IMPLEMENTED,
        [(header::CONTENT_TYPE, "application/problem+json")],
        body.to_string(),
    )
        .into_response()
}

/// The service's routes.
pub fn router() -> Router {
    let mut r = Router::new();
    for route in ROUTES.iter().filter(|route| !route.live) {
        r = match route.verb {
            Verb::Get => r.route(route.path, get(async || not_yet_served())),
            Verb::Post => r.route(route.path, post(async || not_yet_served())),
        };
    }
    r
}
