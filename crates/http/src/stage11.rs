//! The Stage 11 routes outside the realm-admin and Frontend API manifests, declared before
//! their lanes serve them (OP-156 m.4): the forward-auth checks and the Relay callbacks and
//! status. Each answers `501 not-yet-served`; a lane that serves one removes its
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

/// Every declared, not yet served route.
pub const PLANNED: &[Planned] = &[
    planned(
        Method::Get,
        "/proxy/v1/check/{engine}",
        "proxyCheck",
        "The forward-auth check of a registered proxy for one request, in the engine's own protocol (nginx auth_request, Traefik forwardAuth, Caddy forward_auth, Envoy ext_authz HTTP): a real AuthZEN evaluation, cached by session, application, method and path pattern for at most min(horizon, 30 s); unreachable means refused (IDP-30, OP-156 m.3 (l)).",
    ),
    planned(
        Method::Post,
        "/proxy/v1/check/{engine}",
        "proxyCheckPost",
        "The same check for an engine that forwards the original method; the body is never read.",
    ),
    planned(
        Method::Post,
        "/relay/v1/iys-status",
        "relayIysStatus",
        "Relay's report of an İYS consent record's registration state for a preference.changed event; it changes no preference (OP-156 m.3 (c)).",
    ),
    planned(
        Method::Get,
        "/access/v1/relay-status",
        "getRelayStatus",
        "{relay_lag_ms, notifications_delayed}: the age of the courier's oldest undelivered message, or null when none waits, and whether it is past 60 s; authority never waits on delivery (OP-156 m.3 (c), E30).",
    ),
];

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
