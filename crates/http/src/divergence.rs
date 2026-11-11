//! `POST /access/v1/domains/{domain}/divergence` (G32, G33, TI-RT1, OP-158 m.3 (h), (i)): a
//! replica agent declares a signed divergence set (`recovery.cddl`) it replayed. The set counts
//! only under the key the domain declares for that replica; it is kept as the domain's notice
//! for the root and the Security Party. It never stops an exit and writes no restriction:
//! quarantine is their own `policy.set`.

use std::future::Future;
use std::sync::Arc;

use access_authority_core::CoreError;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_decode;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use crate::Problem;
use crate::adp::app::failed;
use crate::adp::domain::Body as AdpBody;

/// The route.
pub const DIVERGENCE_PATH: &str = "/access/v1/domains/{domain}/divergence";

/// Longest signed divergence set.
pub const MAX_SET: usize = 1 << 20;

/// Who keeps a declared divergence set.
pub trait Declare: Send + Sync {
    /// Verifies the `signed-divergence-set` `set` for `domain` and keeps it; the notice id,
    /// `None` when the same set was declared before.
    fn declare(
        &self,
        domain: Digest,
        set: Vec<u8>,
    ) -> impl Future<Output = Result<Option<u64>, CoreError>> + Send;
}

impl<T: Declare> Declare for Arc<T> {
    fn declare(
        &self,
        domain: Digest,
        set: Vec<u8>,
    ) -> impl Future<Output = Result<Option<u64>, CoreError>> + Send {
        (**self).declare(domain, set)
    }
}

/// The route over `d`.
pub fn router<D: Declare + 'static>(d: D) -> Router {
    Router::new()
        .route(DIVERGENCE_PATH, post(declared::<D>))
        .with_state(Arc::new(d))
}

fn refused(status: StatusCode, code: &'static str) -> Response {
    Problem::new(status, code, "Divergence Set Refused").into_response()
}

async fn declared<D: Declare + 'static>(
    State(d): State<Arc<D>>,
    Path(domain): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(domain) = b64url_decode(&domain)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(Digest)
    else {
        return refused(StatusCode::BAD_REQUEST, "domain");
    };
    if body.is_empty() || body.len() > MAX_SET {
        return refused(StatusCode::BAD_REQUEST, "divergence-set");
    }
    match d.declare(domain, body.to_vec()).await {
        Ok(id) => (
            if id.is_some() {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            },
            axum::Json(serde_json::json!({ "notice": id, "stops": false })),
        )
            .into_response(),
        Err(CoreError::Protocol(code @ "divergence-set")) => refused(StatusCode::BAD_REQUEST, code),
        Err(CoreError::Protocol(code)) => refused(StatusCode::FORBIDDEN, code),
        Err(e) => crate::adp::adapters::respond(failed(e, AdpBody::Context), &headers),
    }
}
