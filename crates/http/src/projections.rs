//! `GET /access/v1/domains/{domain}/projections/{digest}` (CR-43, `projection-ref.cddl`, OP-159
//! m.3 (q)): the projection a `projection_ref` names, byte-identical, for an authenticated PEP
//! the artefact's `aud` names. Any other PEP is told there is none (`404`); an expired one
//! answers `410 projection-ref-expired`. The verifier recomputes the digest and verifies the
//! artefact in full.

use std::future::Future;
use std::sync::Arc;

use access_authority_core::CoreError;
use access_authority_core::adapters::{Domains, Fetched};
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::Problem;
use crate::adp::adapters::Pep;
use crate::problem::codes;

/// The fetch route.
pub const PROJECTION_PATH: &str = "/access/v1/domains/{domain}/projections/{digest}";

/// The content type of a fetched artefact.
pub const CONTENT_TYPE: &str = "application/cbor";

/// The kept projections of the decision point.
pub trait Projections: Send + Sync {
    /// The projection `digest` of `domain` for the PEP `pep`.
    fn projection(
        &self,
        domain: Digest,
        digest: [u8; 32],
        pep: String,
    ) -> impl Future<Output = Result<Fetched, CoreError>> + Send;
}

impl<K, B, S, C> Projections for Domains<K, B, S, C>
where
    K: Keys,
    B: Binding + Clone + Send + Sync,
    S: Salts + Clone + Send + Sync,
    C: Clock + Clone + Send + Sync,
{
    async fn projection(
        &self,
        domain: Digest,
        digest: [u8; 32],
        pep: String,
    ) -> Result<Fetched, CoreError> {
        Domains::projection(self, domain, &digest, &pep).await
    }
}

impl<P: Projections> Projections for Arc<P> {
    fn projection(
        &self,
        domain: Digest,
        digest: [u8; 32],
        pep: String,
    ) -> impl Future<Output = Result<Fetched, CoreError>> + Send {
        (**self).projection(domain, digest, pep)
    }
}

/// The fetch route over `projections`.
pub fn router<P: Projections + 'static>(projections: P) -> Router {
    Router::new()
        .route(PROJECTION_PATH, get(fetch::<P>))
        .with_state(Arc::new(projections))
}

/// A 32-byte value as the route names it: unpadded base64url, the domain also with its
/// `sha-256:` prefix.
fn id(text: &str) -> Option<[u8; 32]> {
    let b64 = text.strip_prefix("sha-256:").unwrap_or(text);
    let bytes = access_kernel::json::b64url_decode(b64).ok()?;
    let id = <[u8; 32]>::try_from(bytes).ok()?;
    (access_kernel::json::b64url_encode(&id) == b64).then_some(id)
}

// CR-43, OP-73, OP-159 m.3 (q)
async fn fetch<P: Projections>(
    State(p): State<Arc<P>>,
    Path((domain, digest)): Path<(String, String)>,
    pep: Option<axum::Extension<Pep>>,
) -> Response {
    let Some(axum::Extension(Pep(pep))) = pep else {
        return Problem::new(StatusCode::UNAUTHORIZED, "pep-required", "Unauthorized")
            .into_response();
    };
    let (Some(domain), Some(digest)) = (id(&domain), id(&digest)) else {
        return codes::NOT_FOUND.problem().into_response();
    };
    match p.projection(Digest(domain), digest, pep).await {
        Ok(Fetched::Artefact(bytes)) => {
            ([(header::CONTENT_TYPE, CONTENT_TYPE)], bytes).into_response()
        }
        Ok(Fetched::Expired) => codes::assurance::PROJECTION_REF_EXPIRED
            .problem()
            .into_response(),
        Ok(Fetched::None) => codes::NOT_FOUND.problem().into_response(),
        Err(_) => codes::UNAVAILABLE.problem().into_response(),
    }
}
