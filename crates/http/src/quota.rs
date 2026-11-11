//! The realm request quota of the identity routes (OP-35, OP-158 m.3 (v), TN-24): each request
//! to a realm's host draws from the realm's `rate_limit_rps` and its tenant's request quota,
//! exact counters in layer B. Over a quota the request is `429 quota-exceeded` with
//! `Retry-After`; a counter that cannot answer refuses with `503` (MD-8). Sign-out, logout,
//! revocation and every `DELETE` narrow and never draw (B3, B19); static assets draw nothing.

use std::future::Future;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::problem::Problem;

pub use access_identity_admin::domain::resilience::{BURST_S, DEFAULT_RPS, TENANT_RPS};

/// Path segments that end a session or revoke a token: narrowing, never counted (B3, B19).
pub const NARROWING: [&str; 8] = [
    "revoke",
    "revoke-all",
    "end-session",
    "logout",
    "sign-out",
    "sign-out-everywhere",
    "slo",
    "backchannel-logout",
];

/// The bucket the realm request quota shows on the dashboard (§12.5.4).
pub const BUCKET: &str = "realm-request";

/// What a request drew from its realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drawn {
    /// The realm's slug.
    pub realm: String,
    /// The highest share of a burst in use after the draw, percent.
    pub used_percent: u8,
}

/// What a counter says about one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Taken {
    /// Admitted.
    Admitted(Drawn),
    /// The host names no realm here; the route answers it.
    NoRealm,
    /// Over the quota of the named counter: `tenant` or `realm`.
    Refused(&'static str, Drawn),
}

/// The counter could not answer; the request is refused, never admitted (MD-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("quota unavailable")]
pub struct Unavailable;

/// The layer B request counters of the realms a host serves.
pub trait RequestQuotas: Send + Sync + 'static {
    /// Draws one request of the realm `authority` (and `slug`, for a path issuer) reaches.
    fn take(
        &self,
        authority: &str,
        slug: Option<&str>,
    ) -> impl Future<Output = Result<Taken, Unavailable>> + Send;
}

/// Whether a request draws no quota: it narrows, or it fetches a static asset.
#[must_use]
pub fn free(method: &Method, path: &str) -> bool {
    if method == Method::DELETE {
        return true;
    }
    let last = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    NARROWING.contains(&last) || path.split('/').any(|s| s == "assets")
}

/// The realm slug of a path issuer route (`/realms/{slug}/…`).
#[must_use]
pub fn slug_of(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/realms/")?;
    let slug = rest.split('/').next()?;
    (!slug.is_empty()).then_some(slug)
}

fn quota_exceeded(counter: &'static str) -> Response {
    let mut r = crate::problem::codes::durability::QUOTA_EXCEEDED
        .problem()
        .with_reason(Some(counter))
        .into_response();
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    r
}

/// The middleware: draws the request from its realm's counters before any extractor runs.
pub async fn metered<Q: RequestQuotas>(
    State(quotas): State<Arc<Q>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    if free(request.method(), &path) {
        return next.run(request).await;
    }
    let authority = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .or_else(|| request.uri().authority().map(|a| a.as_str().to_owned()));
    let Some(authority) = authority else {
        return next.run(request).await;
    };
    let slug = slug_of(&path).map(str::to_owned);
    let consumer = request
        .extensions()
        .get::<crate::login::Peer>()
        .map(|crate::login::Peer(ip)| suiss_crypto::digest::sha256(ip.to_string().as_bytes()));
    let seen = |d: &Drawn, refused| {
        access_telemetry::rate_board::RATE_BOARD.record(
            access_telemetry::rate_board::Seen {
                scope: &format!("realm:{}", d.realm),
                bucket: BUCKET,
                percent: d.used_percent,
                consumer,
                refused,
            },
            now_ms(),
        );
    };
    match quotas.take(&authority, slug.as_deref()).await {
        Ok(Taken::Admitted(d)) => {
            seen(&d, None);
            next.run(request).await
        }
        Ok(Taken::NoRealm) => next.run(request).await,
        Ok(Taken::Refused(counter, d)) => {
            seen(&d, Some("quota-exceeded"));
            quota_exceeded(counter)
        }
        Err(Unavailable) => Problem::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Service Unavailable",
        )
        .with_reason(Some("quota"))
        .into_response(),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// `routes` behind the realm request quota of `quotas`.
pub fn meter<Q: RequestQuotas>(routes: axum::Router, quotas: Arc<Q>) -> axum::Router {
    routes.layer(axum::middleware::from_fn_with_state(quotas, metered::<Q>))
}

#[cfg(test)]
mod tests {
    use super::*;

    // B3, B19
    #[test]
    fn narrowing_and_assets_draw_nothing() {
        for path in [
            "/revoke",
            "/realms/acme/end-session",
            "/login/api/v1/sessions/current/sign-out",
            "/login/assets/app.js",
        ] {
            assert!(free(&Method::POST, path), "{path}");
        }
        assert!(free(&Method::DELETE, "/me/devices/1"));
        for path in ["/token", "/realms/acme/authorize", "/login/api/v1/sessions"] {
            assert!(!free(&Method::POST, path), "{path}");
        }
    }

    #[test]
    fn a_path_issuer_names_its_slug() {
        assert_eq!(slug_of("/realms/acme/token"), Some("acme"));
        assert_eq!(slug_of("/realms/"), None);
        assert_eq!(slug_of("/token"), None);
    }
}
