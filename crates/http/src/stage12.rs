//! The Stage 12 routes outside the realm-admin and Frontend API manifests, declared before
//! their lanes serve them (OP-157 m.4 (a)). Every Stage 12 route is a realm-admin or Frontend API
//! row today; a lane that needs another appends it here and serves it from its own handler.

use axum::Router;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

pub use crate::stage11::{Method, Planned};

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
