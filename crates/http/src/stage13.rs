//! The Stage 13 routes outside the realm-admin and Frontend API manifests, declared before their
//! lanes serve them (OP-158 m.4 (a)): the Replica Mirror, the streamed Record Export, the watch
//! stream, the checkpoint publication and inclusion bundles, and the divergence statement. Each
//! answers `501 not-yet-served`; a lane that serves one removes its row and mounts its own
//! handler. The rolling-upgrade check is a command of `access-server`, not a route.

use axum::Router;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

pub use crate::stage11::{Method, Planned};

/// Every declared, not yet served route.
pub const PLANNED: &[Planned] = &[
    Planned {
        method: Method::Get,
        path: "/access/v1/domains/{domain}/watch",
        operation: "watchDomain",
        summary: "Changes from `from` (a record position) by long polling, each with witnessed_through; advisory, never a source of ALLOW (OP-158 m.3 (u)).",
    },
    Planned {
        method: Method::Post,
        path: "/access/v1/domains/{domain}/divergence",
        operation: "declareDivergence",
        summary: "Records a signed divergence set (recovery.cddl) as a divergence_notice Claim for the domain's root and Security Party; it never stops an exit and writes no restriction (G32, G33, OP-158 m.3 (i)).",
    },
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
