//! The edge channel (OP-155 m.3 (c), MD-1, IDP-26, IDI-11): protocol gateways reach access-server
//! over mTLS with their own client certificate, whose single SAN URI is
//! `urn:suiss:access:gw:<kind>:<name>`. A gateway certificate opens the edge calls under
//! [`PREFIX`] and nothing else: any other route answers 403 (IDI-11), so a gateway never reaches
//! ADP, the management API or a browser flow. The gateway signs nothing; the realm issuer makes
//! the Claim (P-ID-5).

use std::sync::Arc;

use access_identity_edge::EdgeError;
use access_identity_edge::app::{Edge, Registry, Vaults};
use access_identity_edge::domain::Gateway;
use access_internal_api::edge::{
    Audit, CONTENT_TYPE, Call, GatewayUri, IssueClaim, MAX_BODY, PREFIX, SubjectLookup,
    decode_hello_request,
};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use crate::Problem;

/// The gateway a connection's verified client certificate names (OP-155 m.3 (c)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayCert {
    /// Its identity, from the certificate's SAN URI.
    pub uri: GatewayUri,
    /// SHA-256 of the leaf certificate.
    pub cert: [u8; 32],
}

/// The gateway `leaf` names: exactly one SAN URI, and that a gateway URI. Read after TLS
/// verified the chain to the operator's client CA.
#[must_use]
pub fn gateway_cert(leaf: &[u8]) -> Option<GatewayCert> {
    let uri = access_identity_attest::domain::svid::x509_uri(leaf)?;
    Some(GatewayCert {
        uri: GatewayUri::parse(&uri)?,
        cert: suiss_crypto::digest::sha256(leaf),
    })
}

/// IDI-11, P-ID-5: a request on a gateway certificate reaches the edge calls only. Applied to
/// every router by [`crate::harden`].
pub async fn confine(request: Request, next: Next) -> Response {
    if request.extensions().get::<GatewayCert>().is_some()
        && !request.uri().path().starts_with(PREFIX)
    {
        return Problem::new(StatusCode::FORBIDDEN, "edge-route-forbidden", "Forbidden")
            .into_response();
    }
    next.run(request).await
}

/// The SAML gateway's `session_attest` (OP-155 m.3 (c), IDI-7): the gateway redeems the one-use
/// handle access-server forwarded and gets the flow decided; a forged or used handle is refused.
pub trait SessionAttest: Send + Sync {
    /// Answers one `session_attest` body of gateway `g`.
    fn attest<'a>(
        &'a self,
        g: &'a Gateway,
        body: &'a [u8],
    ) -> core::pin::Pin<
        Box<dyn core::future::Future<Output = Result<Vec<u8>, EdgeError>> + Send + 'a>,
    >;
}

struct Shared<R, V> {
    edge: Edge<R, V>,
    saml: Option<Arc<dyn SessionAttest>>,
}

/// The edge calls over `edge`.
pub fn router<R, V>(edge: Edge<R, V>) -> Router
where
    R: Registry + 'static,
    V: Vaults + 'static,
{
    router_with(edge, None)
}

/// The edge calls over `edge`, with the SAML gateway's `session_attest` when `saml` is given.
pub fn router_with<R, V>(edge: Edge<R, V>, saml: Option<Arc<dyn SessionAttest>>) -> Router
where
    R: Registry + 'static,
    V: Vaults + 'static,
{
    let mut path = String::from(PREFIX);
    path.push_str("{call}");
    Router::new()
        .route(&path, post(handle::<R, V>))
        .with_state(Arc::new(Shared { edge, saml }))
}

fn problem(status: StatusCode, code: &'static str) -> Response {
    let title = status.canonical_reason().unwrap_or("Error");
    Problem::new(status, code, title).into_response()
}

fn refused(e: &EdgeError) -> Response {
    match e {
        EdgeError::Refused(r) => problem(StatusCode::FORBIDDEN, r.code()),
        EdgeError::NotRegistered => problem(StatusCode::FORBIDDEN, "edge-gateway-unknown"),
        EdgeError::Unavailable(_) => problem(StatusCode::SERVICE_UNAVAILABLE, "edge-unavailable"),
    }
}

fn cbor(body: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE))],
        body,
    )
        .into_response()
}

async fn handle<R: Registry, V: Vaults>(
    State(shared): State<Arc<Shared<R, V>>>,
    Path(call): Path<String>,
    cert: Option<axum::Extension<GatewayCert>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(axum::Extension(cert)) = cert else {
        return problem(StatusCode::UNAUTHORIZED, "edge-unauthenticated");
    };
    let Some(call) = Call::parse(&call) else {
        return problem(StatusCode::NOT_FOUND, "edge-call-unknown");
    };
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some(CONTENT_TYPE)
    {
        return problem(StatusCode::UNSUPPORTED_MEDIA_TYPE, "edge-media-type");
    }
    if body.len() > MAX_BODY {
        return problem(StatusCode::PAYLOAD_TOO_LARGE, "edge-too-large");
    }
    let gateway = match shared.edge.gateway(&cert.uri, &cert.cert).await {
        Ok(g) => g,
        Err(e) => return refused(&e),
    };
    if call == Call::SessionAttest {
        // IDI-7, §13.2
        let done = match (&shared.saml, gateway.uri.kind) {
            (Some(s), access_internal_api::edge::GatewayKind::Saml) => {
                s.attest(&gateway, &body).await
            }
            (Some(_), _) => Err(EdgeError::Refused(
                access_identity_edge::domain::Refusal::Method,
            )),
            (None, _) => return problem(StatusCode::NOT_IMPLEMENTED, "edge-call-not-served"),
        };
        return match done {
            Ok(body) => cbor(body),
            Err(e) => refused(&e),
        };
    }
    answer(&shared.edge, &gateway, call, &body).await
}

async fn answer<R: Registry, V: Vaults>(
    edge: &Edge<R, V>,
    g: &Gateway,
    call: Call,
    body: &[u8],
) -> Response {
    let malformed = || problem(StatusCode::BAD_REQUEST, "edge-malformed");
    let done = match call {
        Call::Hello => match decode_hello_request(body) {
            Ok(()) => Ok(Edge::<R, V>::hello(g).encode()),
            Err(_) => return malformed(),
        },
        Call::SubjectLookup => match SubjectLookup::decode(body) {
            Ok(q) => edge.subject_lookup(g, &q).await.map(|a| a.encode()),
            Err(_) => return malformed(),
        },
        Call::IssueClaim => match IssueClaim::decode(body) {
            Ok(q) => edge.issue_claim(g, &q).await.map(|a| a.encode()),
            Err(_) => return malformed(),
        },
        Call::Audit => match Audit::decode(body) {
            Ok(q) => edge.audit(g, &q).await.map(|a| a.encode()),
            Err(_) => return malformed(),
        },
        Call::Authenticate | Call::SessionAttest | Call::DirectoryRead => {
            return problem(StatusCode::NOT_IMPLEMENTED, "edge-call-not-served");
        }
    };
    match done {
        Ok(body) => cbor(body),
        Err(e) => refused(&e),
    }
}
