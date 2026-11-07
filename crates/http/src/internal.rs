//! The internal listener's routes (OP-67 m.3, OP-151 m.3 (b)): `/livez`, `/readyz`, `/healthz`
//! and `/metrics`, on the internal network only. None of them is on the public or management
//! listener.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::problem::codes;
use crate::{Health, Limits, harden};

/// Whether the process takes traffic: set once every listener is bound and the background work
/// started; a process that is not ready answers `/readyz` with `503` (OP-67 m.3, MD-8).
#[derive(Clone, Debug, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    /// Marks the process ready.
    pub fn ready(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Marks the process not ready, as when it starts shutting down.
    pub fn unready(&self) {
        self.0.store(false, Ordering::Release);
    }

    /// Whether it is ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// The `/metrics` content type (Prometheus text exposition).
pub const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

async fn livez() -> &'static str {
    "ok\n"
}

fn readyz(ready: &Readiness) -> Response {
    if ready.is_ready() {
        (StatusCode::OK, "ok\n").into_response()
    } else {
        codes::UNAVAILABLE.problem().into_response()
    }
}

async fn metrics() -> Response {
    let mut r = (StatusCode::OK, "").into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(METRICS_CONTENT_TYPE),
    );
    r
}

async fn not_found() -> Response {
    codes::NOT_FOUND.problem().into_response()
}

/// The internal router: liveness, readiness, health with the lockdown state (SA-22) and the
/// metrics exposition.
pub fn router(health: Health, ready: Readiness, limits: Limits) -> Router {
    let routes = Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(move || std::future::ready(readyz(&ready))))
        .route(
            "/healthz",
            get(move || std::future::ready(Json(health.clone()))),
        )
        .route("/metrics", get(metrics))
        .fallback(not_found);
    harden(routes, limits)
}
