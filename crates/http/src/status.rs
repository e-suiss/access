//! `GET /access/v1/status-lists/{list}?domain=` (OP-150 m.3 (a), (s)): a domain's latest
//! signed Token Status List, with its key excerpt. The list's `iat` and `as_of` are the
//! `recorded_at` and position it reflects (T24); the response is cacheable only briefly so a
//! revocation reaches verifiers at the publisher's pace. A list is an information channel,
//! never the safety mechanism (§9.12.4, PI-9): a verifier without a fresh one falls back to the
//! contract's horizon and Δ.

use std::future::Future;
use std::sync::Arc;

use access_identity_oauth::domain::request::Params;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::status::CWT_CONTENT_TYPE;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::Problem;
use crate::product::adapters::EXCERPT_HEADER;

/// The endpoint's path.
pub const PATH: &str = "/access/v1/status-lists/{list}";

/// `Cache-Control` of a list (PD): a minute, so a revocation the publisher signed at once is
/// fetched within a minute; never longer than the list's `ttl`.
pub const CACHE: &str = "public, max-age=60";

/// A list as served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served {
    /// The signed list, `COSE_Sign1`.
    pub token: Vec<u8>,
    /// The binding-signed excerpt of its key.
    pub excerpt: Option<Vec<u8>>,
    /// The position it reflects.
    pub as_of: u64,
}

/// The store could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("status lists unavailable")]
pub struct Unavailable;

/// Where the published lists are read.
pub trait StatusLists: Send + Sync {
    /// The latest publication of list `list_no` of `domain`.
    fn latest(
        &self,
        domain: Digest,
        list_no: u64,
    ) -> impl Future<Output = Result<Option<Served>, Unavailable>> + Send;
}

/// The status list route over `lists`.
pub fn router<L: StatusLists + 'static>(lists: L) -> Router {
    Router::new()
        .route(PATH, get(list::<L>))
        .with_state(Arc::new(lists))
}

fn unknown() -> Response {
    Problem::new(StatusCode::NOT_FOUND, "status-list-unknown", "Not Found").into_response()
}

fn etag(as_of: u64) -> String {
    format!("\"{as_of}\"")
}

async fn list<L: StatusLists>(
    State(lists): State<Arc<L>>,
    Path(list): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let params = Params::parse(uri.query().unwrap_or_default()).ok();
    let Some(domain) = params
        .as_ref()
        .and_then(|p| p.get("domain"))
        .and_then(crate::adp::adapters::domain_id)
    else {
        return Problem::new(StatusCode::BAD_REQUEST, "domain", "Bad Request").into_response();
    };
    let Some(list_no) = list.parse::<u64>().ok().filter(|n| n.to_string() == list) else {
        return unknown();
    };
    let served = match lists.latest(domain, list_no).await {
        Ok(Some(s)) => s,
        Ok(None) => return unknown(),
        Err(Unavailable) => {
            return Problem::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "status-list-unavailable",
                "Service Unavailable",
            )
            .into_response();
        }
    };
    let tag = etag(served.as_of);
    let Ok(tag_value) = HeaderValue::from_str(&tag) else {
        return unknown();
    };
    let mut out = if headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|v| v.as_bytes() == tag.as_bytes())
    {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(CWT_CONTENT_TYPE),
            )],
            served.token,
        )
            .into_response()
    };
    let h = out.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(CACHE));
    h.insert(header::ETAG, tag_value);
    if let Some(excerpt) = served
        .excerpt
        .as_deref()
        .and_then(|e| HeaderValue::from_str(&b64url_encode(e)).ok())
    {
        h.insert(EXCERPT_HEADER, excerpt);
    }
    out
}

#[cfg(test)]
mod tests;
