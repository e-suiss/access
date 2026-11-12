//! HTTP layer shared by both Access planes (OP-62).

#![recursion_limit = "256"]

pub mod account;
pub mod adp;
pub mod algorithms;
pub mod api;
pub mod audit;
pub mod console;
pub mod declarations;
pub mod divergence;
pub mod edge;
pub mod ingest;
pub mod internal;
pub mod linux;
pub mod login;
pub mod mcp_gateway;
pub mod mirror;
pub mod oauth;
pub mod path;
pub mod platform;
pub mod problem;
pub mod product;
pub mod proxy;
pub mod realm;
pub mod relay_callback;
pub mod scim;
mod security_txt;
pub mod ssf;
pub mod ssh;
pub mod stage11;
pub mod stage12;
pub mod stage13;
pub mod stage14;
pub mod status;
pub mod tls;
pub mod transparency;
// OP-158 m.3 (v)
pub mod quota;
// OP-158 m.3 (v)
pub mod layers;
// OP-158 m.3 (v)
pub mod forwarded;
// OP-158 m.3 (o)
pub mod placement;
// CR-40 m.3, OP-159 m.3 (s)
pub mod padding;

use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use serde::Serialize;
use tower_http::catch_panic::CatchPanicLayer;
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
    /// The listener's admission: its lane and per-address rate (SA-27, OP-53). Only the
    /// outermost [`harden`] of a listener sets it, so nothing is counted twice.
    pub admission: Option<layers::Admission>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 256 * 1024,
            request_timeout: Duration::from_secs(10),
            admission: None,
        }
    }
}

impl Limits {
    /// These limits as the outermost of a listener admitting under `admission`.
    #[must_use]
    pub const fn admitting(mut self, admission: layers::Admission) -> Self {
        self.admission = Some(admission);
        self
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

/// Builds the public router around `api`, the plane routes (e.g. ADP). Health and metrics are
/// on the internal listener only ([`internal::router`], OP-67 m.3, OP-151 m.3 (b)).
pub fn router(security_txt: SecurityTxt, limits: Limits, api: Router) -> Router {
    let routes = api
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
    // CR-40 m.3, SAI-43
    let routes = routes.layer(axum::middleware::from_fn(padding::pad));
    // SA-27, GHSA-84jc-3hj2-hwc7
    let routes = match limits.admission {
        Some(a) => routes.layer(axum::middleware::from_fn_with_state(
            layers::Lane::new(&a),
            layers::lane,
        )),
        None => routes,
    };
    let routes = routes
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            limits.request_timeout,
        ))
        // §13.7.4, OP-159 m.3 (mm)
        .layer(axum::middleware::from_fn_with_state(
            limits.max_body_bytes,
            layers::body_limit,
        ));
    let routes = match limits.admission {
        Some(a) => routes.layer(axum::middleware::from_fn_with_state(
            std::sync::Arc::new(layers::ClientRate::new(a.per_second, a.burst)),
            layers::client_rate,
        )),
        None => routes,
    };
    routes
        // IDI-11, P-ID-5
        .layer(axum::middleware::from_fn(edge::confine))
        // TN-113
        .layer(axum::middleware::from_fn(path::canonical))
        // RFC 9113 §8.3.1
        .layer(axum::middleware::from_fn(host_from_authority))
        // SA-21, R-3
        .layer(CatchPanicLayer::custom(problem::from_panic))
}

/// An HTTP/2 request names its host in `:authority`, which hyper keeps in the URI; the
/// handlers read `Host`, so it is filled from the authority when the request has none.
async fn host_from_authority(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !request.headers().contains_key(axum::http::header::HOST)
        && let Some(v) = request
            .uri()
            .authority()
            .and_then(|a| axum::http::HeaderValue::from_str(a.as_str()).ok())
    {
        request.headers_mut().insert(axum::http::header::HOST, v);
    }
    next.run(request).await
}

async fn not_found() -> Problem {
    not_found_problem()
}

fn not_found_problem() -> Problem {
    Problem::new(StatusCode::NOT_FOUND, "not-found", "Not Found")
}
