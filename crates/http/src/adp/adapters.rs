//! The ADP surface on axum, and the authority core as its decision point.

use std::sync::Arc;

use crate::Problem;
use access_authority_core::CoreError;
use access_authority_core::adapters::Domains;
use access_authority_core::app::{Incoming, Response as Decided, Scope};
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_core::query::Query;
use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use access_kernel::model::Id;
use access_kernel::verify::key_scope::METADATA_CONTENT_TYPE;
use access_telemetry::signals::PROTOCOL_REJECTIONS;
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

/// Domain Metadata caching (§9.15.1): re-signed at each rotation, revalidated within minutes,
/// a stale copy served while the signer is unreachable, never past an hour in all: without a
/// witness the verifier's metadata cache is at most 1 hour old (§9.15, T29, TI-RT5, OP-150
/// m.3 (q), UDC).
pub const METADATA_CACHE: &str = "max-age=300, stale-while-revalidate=300, stale-if-error=3300";

/// The longest a cache may hold Domain Metadata, seconds (TI-RT5, OP-150 m.3 (q)).
pub const METADATA_MAX_AGE_S: u64 = 3_600;

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
        .route("/access/v1/eligibility:check", post(eligibility::<P>))
        .route(crate::audit::EXPORT_PATH, post(audit_export::<P>))
        .route(
            "/.well-known/authzen-configuration",
            get(configuration::<P>),
        )
        .route(
            "/.well-known/authzen-configuration/{domain}",
            get(domain_configuration::<P>),
        )
        .route(
            "/.well-known/access-domain-metadata/{domain}",
            get(domain_metadata::<P>),
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

async fn eligibility<P: Pdp>(
    State(shared): State<Arc<Shared<P>>>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let reply = shared
        .service
        .eligibility(&body, pep.map(|axum::Extension(Pep(p))| p))
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

async fn audit_export<P: Pdp>(
    State(shared): State<Arc<Shared<P>>>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result =
        crate::audit::export(&shared.service, &body, pep.map(|axum::Extension(Pep(p))| p)).await;
    crate::audit::respond(result, &headers)
}

pub(crate) fn respond(reply: Reply, headers: &HeaderMap) -> Response {
    // §17.8.2, RR-8
    match &reply {
        Reply::Protocol(code, _) => drop(PROTOCOL_REJECTIONS.incr(["adp", code])),
        Reply::Limited => drop(PROTOCOL_REJECTIONS.incr(["adp", "rate-limited"])),
        _ => {}
    }
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
        Reply::Protocol(code, errors) => {
            Problem::new(StatusCode::BAD_REQUEST, code, "Protocol Error")
                .with_errors(errors)
                .into_response()
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
        Reply::Unavailable(reason) => Problem::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Service Unavailable",
        )
        .with_reason(reason)
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

/// What the discovery documents declare (L1-ADP-11).
fn discovery(issuer: &str, pdp: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut body = serde_json::Map::new();
    body.insert(String::from("policy_decision_point"), pdp.into());
    body.insert(
        String::from("access_evaluation_endpoint"),
        format!("{issuer}/access/v1/evaluation").into(),
    );
    body.insert(
        String::from("access_evaluations_endpoint"),
        format!("{issuer}/access/v1/evaluations").into(),
    );
    body.insert(
        String::from("capabilities"),
        serde_json::json!([
            "urn:suiss:access:adp:1",
            "urn:suiss:access:explain:1",
            "urn:suiss:access:consistency-token:1"
        ]),
    );
    body
}

fn json(body: serde_json::Map<String, serde_json::Value>) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::Value::Object(body).to_string(),
    )
        .into_response()
}

async fn configuration<P: Pdp>(State(shared): State<Arc<Shared<P>>>) -> Response {
    let issuer = &shared.discovery.issuer;
    json(discovery(issuer, issuer))
}

/// A `DomainID` in its text form: `sha-256:` and the unpadded base64url of 32 bytes
/// (L0-ENC-20).
pub(crate) fn domain_id(text: &str) -> Option<Digest> {
    let b64 = text.strip_prefix("sha-256:")?;
    let bytes = access_kernel::json::b64url_decode(b64).ok()?;
    let id = <[u8; 32]>::try_from(bytes).ok().map(Digest)?;
    (access_kernel::json::b64url_encode(&id.0) == b64).then_some(id)
}

/// The domain's binding-signed Domain Metadata from the signer (§9.15.1, OP-143 m.4).
async fn signed_metadata<P: Pdp>(shared: &Shared<P>, text: &str) -> Option<Vec<u8>> {
    shared.service.metadata(domain_id(text)?).await
}

/// No signed document for the domain: never an unsigned one instead.
fn no_metadata() -> Response {
    Problem::new(
        StatusCode::NOT_FOUND,
        "domain-metadata-unavailable",
        "Not Found",
    )
    .into_response()
}

async fn domain_metadata<P: Pdp>(
    State(shared): State<Arc<Shared<P>>>,
    Path(domain): Path<String>,
) -> Response {
    let Some(cose) = signed_metadata(&shared, &domain).await else {
        return no_metadata();
    };
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(METADATA_CONTENT_TYPE),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static(METADATA_CACHE),
            ),
        ],
        cose,
    )
        .into_response()
}

/// §9.5.1 #6: the discovery document of one domain. Its PDP identifier is the issuer followed
/// by the `DomainID`, from which this address is built; `signed_metadata` is the base64url of
/// the domain's `COSE_Sign1` Domain Metadata (MD-3).
async fn domain_configuration<P: Pdp>(
    State(shared): State<Arc<Shared<P>>>,
    Path(domain): Path<String>,
) -> Response {
    let Some(cose) = signed_metadata(&shared, &domain).await else {
        return no_metadata();
    };
    let issuer = &shared.discovery.issuer;
    let mut body = discovery(issuer, &format!("{issuer}/{domain}"));
    body.insert(
        String::from("signed_metadata"),
        access_kernel::json::b64url_encode(&cose).into(),
    );
    json(body)
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

    async fn eligible(&self, inc: Incoming, subject: Id) -> Result<Decided, CoreError> {
        Domains::eligible(self, &inc, subject).await
    }

    async fn explain_recorded(
        &self,
        inc: Incoming,
        record: u64,
        scope: Scope,
    ) -> Result<Decided, CoreError> {
        Domains::explain_recorded(self, &inc, record, scope).await
    }

    async fn search(
        &self,
        inc: Incoming,
        query: Query,
        page: Option<String>,
    ) -> Result<Page, CoreError> {
        Domains::search(self, &inc, &query, page.as_deref()).await
    }

    async fn metadata(&self, domain: Digest) -> Option<Vec<u8>> {
        Domains::metadata(self, domain).await
    }

    async fn export(&self, inc: Incoming) -> Result<Vec<u8>, CoreError> {
        Domains::export(self, &inc)
            .await?
            .package
            .to_bytes()
            .map_err(|_| CoreError::Unavailable("export"))
    }

    async fn lab_explain(
        &self,
        inc: Incoming,
    ) -> Result<access_authority_core::app::lab::Explanation, CoreError> {
        Domains::lab_explain(self, &inc).await
    }

    async fn lab_replay(
        &self,
        inc: Incoming,
        record: u64,
    ) -> Result<access_authority_core::app::lab::Replay, CoreError> {
        Domains::lab_replay(self, &inc, record).await
    }
}
