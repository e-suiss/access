//! The Stage 14 routes outside the realm-admin and Frontend API manifests, declared before their
//! lanes serve them (OP-159 m.4 (a)): the projection reference fetch, the post-quantum checkpoint
//! list and post-quantum inclusion bundles. Each answers `501 not-yet-served`; a lane that serves
//! one removes its row and mounts its own handler.

use axum::Router;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

pub use crate::stage11::{Method, Planned};

/// Every declared, not yet served route; the projection fetch is served by
/// [`crate::projections`] (OP-159 m.3 (q)).
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
