//! HTTP layer shared by both Access planes (OP-62).

mod problem;
mod security_txt;

use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

pub use problem::Problem;
pub use security_txt::SecurityTxt;

/// Explicit HTTP limits (R-5: framework defaults are never relied on). Values are PD.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum request body size in bytes (§13.7.4: Access requests ≤ 256 KB).
    pub max_body_bytes: usize,
    /// Whole-request timeout (§14.6: 10 s).
    pub request_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 256 * 1024,
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// What `/healthz` reports. The runtime lockdown state is part of health (SA-22: the
/// Landlock ABI is visible at `/healthz`; OP-92).
#[derive(Clone, Debug, Serialize)]
pub struct Health {
    /// Always `"ok"` when the process answers.
    pub status: &'static str,
    /// Runtime lockdown in force.
    pub sandbox: SandboxHealth,
}

/// Runtime lockdown state shown at `/healthz`.
#[derive(Clone, Debug, Serialize)]
pub struct SandboxHealth {
    /// Lockdown profile name.
    pub profile: &'static str,
    /// Seccomp phase in force (1 at start-up, 2 once narrowed).
    pub seccomp_phase: u8,
    /// Landlock ABI the process requires.
    pub landlock_required_abi: u32,
    /// Landlock ABI the kernel reports.
    pub landlock_kernel_abi: u32,
}

/// Builds the public router.
pub fn router(security_txt: SecurityTxt, health: Health, limits: Limits) -> Router {
    let routes = Router::new()
        .route(
            "/healthz",
            get(move || std::future::ready(Json(health.clone()))),
        )
        .route(
            "/.well-known/security.txt",
            get(move || std::future::ready(security_txt.response())),
        )
        .fallback(not_found);
    harden(routes, limits)
}

/// Wraps routes in the shared outer stack. Apply it last: axum layers cover only
/// routes added before them.
pub fn harden(routes: Router, limits: Limits) -> Router {
    routes
        .layer(RequestBodyLimitLayer::new(limits.max_body_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            limits.request_timeout,
        ))
        // SA-21, R-3
        .layer(CatchPanicLayer::custom(problem::from_panic))
}

async fn not_found() -> Problem {
    Problem::new(StatusCode::NOT_FOUND, "not_found", "Not Found")
}
