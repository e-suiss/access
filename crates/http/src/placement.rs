//! Placement routing of the domain routes (TI-17, CMP-26, OP-158 m.3 (o)): a request for a
//! domain (in its path, or in the decision body's `context.domain`) the Placement Directory
//! places in another cell is answered `421 placement-mismatch`
//! with that cell's name in `access-cell` and, when known, its URL in `location`. The directory
//! is routing only and never a decision input: when it cannot answer, or names no other cell,
//! the request goes on and the commit path decides; a cell that does not lead the domain refuses
//! it there.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, Method, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};

use crate::problem::codes::BODY_TOO_LARGE;
use crate::problem::codes::durability::PLACEMENT_MISMATCH;

/// The prefix of the domain routes.
pub const DOMAINS: &str = "/access/v1/domains/";

/// The prefix of the decision routes, whose body names the domain.
pub const ADP: &str = "/access/v1/";

/// The header naming the cell a misdirected request belongs to.
pub const CELL_HEADER: &str = "access-cell";

/// Where a domain is served instead of this cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Elsewhere {
    /// The cell that serves it.
    pub cell: String,
    /// That cell's public URL, when the deployment declares one.
    pub url: Option<String>,
}

/// A lookup that failed; the request goes on (TI-17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unanswered;

/// The answer of one lookup.
pub type Lookup<'a> =
    Pin<Box<dyn Future<Output = Result<Option<Elsewhere>, Unanswered>> + Send + 'a>>;

/// The Placement Directory as routing sees it.
pub trait Directory: Send + Sync + 'static {
    /// The cell that serves `domain` when it is not this one.
    fn elsewhere(&self, domain: [u8; 32]) -> Lookup<'_>;
}

/// The domain id a path under [`DOMAINS`] names.
#[must_use]
pub fn domain_of(path: &str) -> Option<[u8; 32]> {
    let rest = path.strip_prefix(DOMAINS)?;
    let segment = rest.split('/').next()?;
    let bytes = access_kernel::json::b64url_decode(segment).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// The domain an ADP request body names in `context.domain`.
#[must_use]
pub fn body_domain(body: &[u8]) -> Option<[u8; 32]> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let text = v.get("context")?.get("domain")?.as_str()?;
    let bytes = access_kernel::json::b64url_decode(text).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

async fn routed(State(dir): State<Arc<dyn Directory>>, req: Request, next: Next) -> Response {
    let (req, domain) = match domain_of(req.uri().path()) {
        Some(d) => (req, Some(d)),
        None if req.method() == Method::POST && req.uri().path().starts_with(ADP) => {
            let (parts, body) = req.into_parts();
            let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
                return BODY_TOO_LARGE.problem().into_response();
            };
            let d = body_domain(&bytes);
            (Request::from_parts(parts, Body::from(bytes)), d)
        }
        None => (req, None),
    };
    let Some(domain) = domain else {
        return next.run(req).await;
    };
    match dir.elsewhere(domain).await {
        Ok(Some(e)) => misdirected(&e, req.uri().path()),
        Ok(None) => next.run(req).await,
        // TI-17
        Err(Unanswered) => {
            tracing::warn!(
                event = "placement.unanswered",
                "the placement directory did not answer; the commit path decides"
            );
            next.run(req).await
        }
    }
}

/// The `421 placement-mismatch` answer naming `e`.
#[must_use]
pub fn misdirected(e: &Elsewhere, path: &str) -> Response {
    let mut r = PLACEMENT_MISMATCH.problem().into_response();
    if let Ok(v) = HeaderValue::from_str(&e.cell) {
        r.headers_mut()
            .insert(HeaderName::from_static(CELL_HEADER), v);
    }
    if let Some(v) = e
        .url
        .as_deref()
        .and_then(|u| HeaderValue::from_str(&format!("{}{path}", u.trim_end_matches('/'))).ok())
    {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r
}

/// `router` with every domain route routed by `dir` first.
pub fn route(router: Router, dir: Arc<dyn Directory>) -> Router {
    router.layer(from_fn_with_state(dir, routed))
}

#[cfg(test)]
mod tests;
