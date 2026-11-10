//! The Stage 11 routes outside the realm-admin and Frontend API manifests, declared before
//! their lanes serve them (OP-156 m.4): the Relay callbacks and status. The forward-auth
//! checks are served by [`crate::proxy`]. Each answers `501 not-yet-served`; a lane that serves one removes its
//! row and mounts its own handler.

use axum::Router;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

/// How a declared route is called.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

/// One declared route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Planned {
    /// Method.
    pub method: Method,
    /// Path, `{name}` for a parameter.
    pub path: &'static str,
    /// `operationId`.
    pub operation: &'static str,
    /// What it will do.
    pub summary: &'static str,
}

const fn planned(
    method: Method,
    path: &'static str,
    operation: &'static str,
    summary: &'static str,
) -> Planned {
    Planned {
        method,
        path,
        operation,
        summary,
    }
}

/// The forward-auth engines (OP-156 m.3 (l)); Envoy is `ext_authz` in HTTP service mode.
pub const PROXY_ENGINES: [&str; 4] = ["nginx", "traefik", "caddy", "envoy"];

/// `GET /access/v1/relay-status`, served by the Relay courier's lane (OP-156 m.3 (c)): the age
/// of the courier's oldest undelivered message and whether notifications read as delayed.
pub const RELAY_STATUS: &str = "/access/v1/relay-status";

/// Every declared, not yet served route.
pub const PLANNED: &[Planned] = &[];

async fn not_yet_served() -> Response {
    crate::problem::codes::NOT_YET_SERVED
        .problem()
        .into_response()
}

/// The declared routes, each answering `501 not-yet-served`.
pub fn router() -> Router {
    PLANNED.iter().fold(Router::new(), |r, p| match p.method {
        Method::Get => r.route(p.path, get(not_yet_served)),
        Method::Post => r.route(p.path, post(not_yet_served)),
    })
}
