//! `POST /access/v1/audit/export` (AP-14, PI-4, U53, §17.6.13): the Record Export Package of an
//! allowed `access.audit_export` Exercise, on the ADP router. There is no separate audit read
//! path: the body is the very request that committed the export intent, with the actor's AIS,
//! and the decision point builds the package only for that Exercise and audits the export
//! before it answers. The answer is a CBOR sequence (RFC 8742) anyone verifies with the open
//! Kernel.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::adp::app::{Reply, Service, bad, failed};
use crate::adp::domain::{Body, decode};
use crate::adp::ports::Pdp;
use access_authority_core::app::Incoming;

/// The export route.
pub const EXPORT_PATH: &str = "/access/v1/audit/export";

/// Media type of a Record Export Package (RFC 8742).
pub const PACKAGE_CONTENT_TYPE: &str = "application/cbor-seq";

/// The package of the export the body commits to, or the refusal.
///
/// # Errors
/// The [`Reply`] of a refused request: unauthenticated PEP, protocol error, rate limit or an
/// unavailable domain.
pub async fn export<P: Pdp>(
    service: &Service<P>,
    body: &[u8],
    pep: Option<String>,
) -> Result<Vec<u8>, Reply> {
    let Some(pep) = pep else {
        return Err(Reply::Unauthenticated);
    };
    let decoded = decode(body, service.max_body()).map_err(|e| bad(e, Body::Context))?;
    let inc = Incoming {
        request: decoded.request,
        ais: decoded.ais,
        pep,
        requester: None,
        explain: false,
        status: None,
    };
    service
        .pdp()
        .export(inc)
        .await
        .map_err(|e| failed(e, Body::Context))
}

/// The HTTP answer of [`export`].
#[must_use]
pub fn respond(result: Result<Vec<u8>, Reply>, headers: &HeaderMap) -> Response {
    match result {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(PACKAGE_CONTENT_TYPE),
                ),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            bytes,
        )
            .into_response(),
        Err(reply) => crate::adp::adapters::respond(reply, headers),
    }
}
