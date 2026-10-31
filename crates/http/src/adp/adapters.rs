//! The ADP surface on axum, and the authority core as its decision point.

use std::sync::Arc;

use crate::Problem;
use access_authority_core::CoreError;
use access_authority_core::adapters::Domains;
use access_authority_core::app::{Incoming, Response as Decided};
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_core::query::Query;
use access_authority_sequencer::ports::Clock;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::adp::app::{Reply, Service};
use crate::adp::ports::{Page, Pdp};

/// The PEP's transport-authenticated identity, set by the TLS or client-auth layer
/// (L1-ADP-2). The surface never derives it from the body.
#[derive(Clone, Debug)]
pub struct Pep(pub String);

const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Discovery document fields (L1-ADP-11).
#[derive(Clone, Debug)]
pub struct Discovery {
    /// The issuer the document is served for, without a trailing slash.
    pub issuer: String,
}

struct Shared<P: Pdp> {
    service: Service<P>,
    discovery: Discovery,
}

/// The ADP routes.
pub fn router<P: Pdp + 'static>(service: Service<P>, discovery: Discovery) -> Router {
    let shared = Arc::new(Shared { service, discovery });
    Router::new()
        .route("/access/v1/evaluation", post(evaluation::<P>))
        .route("/access/v1/evaluations", post(evaluations::<P>))
        .route("/access/v1/explain", post(explain::<P>))
        .route("/access/v1/search/{kind}", post(search::<P>))
        .route(
            "/.well-known/authzen-configuration",
            get(configuration::<P>),
        )
        .with_state(shared)
}

async fn evaluation<P: Pdp>(
    State(shared): State<Arc<Shared<P>>>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let reply = shared
        .service
        .evaluation(&body, pep.map(|axum::Extension(Pep(p))| p))
        .await;
    respond(reply, &headers)
}

async fn evaluations<P: Pdp>(
    State(shared): State<Arc<Shared<P>>>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let reply = shared
        .service
        .evaluations(&body, pep.map(|axum::Extension(Pep(p))| p))
        .await;
    respond(reply, &headers)
}

async fn explain<P: Pdp>(
    State(shared): State<Arc<Shared<P>>>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let reply = shared
        .service
        .explain(&body, pep.map(|axum::Extension(Pep(p))| p))
        .await;
    respond(reply, &headers)
}

async fn search<P: Pdp>(
    State(shared): State<Arc<Shared<P>>>,
    Path(kind): Path<String>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let reply = shared
        .service
        .search(&kind, &body, pep.map(|axum::Extension(Pep(p))| p))
        .await;
    respond(reply, &headers)
}

fn respond(reply: Reply, headers: &HeaderMap) -> Response {
    let mut response = match reply {
        Reply::Decision(v) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            v.to_string(),
        )
            .into_response(),
        Reply::Protocol(code) => {
            Problem::new(StatusCode::BAD_REQUEST, code, "Protocol Error").into_response()
        }
        Reply::Unauthenticated => Problem::new(
            StatusCode::UNAUTHORIZED,
            "pep-unauthenticated",
            "Unauthorized",
        )
        .into_response(),
        Reply::Conflict => Problem::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "nonce-conflict",
            "Nonce Conflict",
        )
        .into_response(),
        Reply::Unavailable => Problem::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Service Unavailable",
        )
        .into_response(),
        // OP-35, OP-141 m.23
        Reply::Limited => Problem::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate-limited",
            "Too Many Requests",
        )
        .into_response(),
    };
    // L1-ADP-4
    if let Some(id) = headers.get(&REQUEST_ID) {
        response.headers_mut().insert(REQUEST_ID, id.clone());
    }
    response
}

async fn configuration<P: Pdp>(State(shared): State<Arc<Shared<P>>>) -> Response {
    let issuer = &shared.discovery.issuer;
    let body = serde_json::json!({
        "policy_decision_point": issuer,
        "access_evaluation_endpoint": format!("{issuer}/access/v1/evaluation"),
        "access_evaluations_endpoint": format!("{issuer}/access/v1/evaluations"),
        "capabilities": [
            "urn:esuiss:access:adp:1",
            "urn:esuiss:access:explain:1",
            "urn:esuiss:access:consistency-token:1"
        ],
    });
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body.to_string(),
    )
        .into_response()
}

impl<K, B, S, C> Pdp for Domains<K, B, S, C>
where
    K: Keys,
    B: Binding + Clone + Send + Sync,
    S: Salts + Clone + Send + Sync,
    C: Clock + Clone + Send + Sync,
{
    async fn evaluate(&self, inc: Incoming) -> Result<Decided, CoreError> {
        self.exercise(&inc).await
    }

    async fn search(
        &self,
        inc: Incoming,
        query: Query,
        page: Option<String>,
    ) -> Result<Page, CoreError> {
        Domains::search(self, &inc, &query, page.as_deref()).await
    }
}
