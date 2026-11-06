//! The product client API on axum (OP-149 m.4, m.5, m.28 (c)), and the authority core as its
//! key and Party directory. The client is the one the TLS layer named from its certificate, as
//! for the ADP (OP-141 m.18 (b)).

use std::sync::Arc;

use access_authority_core::CoreError;
use access_authority_core::adapters::{Domains, ExerciseRecord, KeyAnswer, PartyAnswer};
use access_authority_core::keys::AsOf;
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_identity_oauth::domain::request::Params;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::model::Id;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use super::app::{Form, Reply, Service};
use super::ports::{Exercises, KeyDirectory, Subjects, Tenants};
use crate::Problem;
use crate::adp::adapters::Pep;

/// Content type of the signed key lookup answer (RFC 9052).
pub const COSE_CONTENT_TYPE: &str = "application/cose; cose-type=\"cose-sign1\"";

/// The response header carrying the signed answer's key excerpt, base64url (CR-58 m.1).
pub const EXCERPT_HEADER: HeaderName = HeaderName::from_static("access-key-excerpt");

const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

type Shared<K, T, S> = State<Arc<Service<K, T, S>>>;

/// The product client routes.
pub fn router<K, T, S>(service: Service<K, T, S>) -> Router
where
    K: KeyDirectory + Exercises + 'static,
    T: Tenants + 'static,
    S: Subjects + 'static,
{
    Router::new()
        .route("/access/v1/keys/{kid}", get(key::<K, T, S>))
        .route("/access/v1/keys:batchGet", post(keys::<K, T, S>))
        .route("/access/v1/parties/{party}", get(party::<K, T, S>))
        .route("/access/v1/parties:batchGet", post(parties::<K, T, S>))
        .route("/access/v1/tenants", get(tenants::<K, T, S>))
        .route(
            "/access/v1/tenants/{tenant}/snapshot",
            get(snapshot::<K, T, S>),
        )
        .route(
            "/access/v1/tenants/{tenant}/subjects:resolve",
            post(resolve::<K, T, S>),
        )
        .route("/access/v1/exercises/{id}", get(exercise::<K, T, S>))
        .route("/access/v1/exercises/{id}/agency", get(agency::<K, T, S>))
        .with_state(Arc::new(service))
}

/// The query parameters; a repeated one is refused.
fn query(uri: &Uri) -> Option<Params> {
    Params::parse(uri.query().unwrap_or_default()).ok()
}

fn client(pep: Option<axum::Extension<Pep>>) -> Option<String> {
    pep.map(|axum::Extension(Pep(p))| p)
}

/// The answer's form from `Accept`: JSON only when asked for; the canonical form otherwise.
fn form(headers: &HeaderMap) -> Form {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if accept.contains("application/json") && !accept.contains("application/cose") {
        Form::Json
    } else {
        Form::Cose
    }
}

async fn key<K: KeyDirectory, T: Tenants, S>(
    State(s): Shared<K, T, S>,
    Path(kid): Path<String>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
) -> Response {
    let Some(q) = query(&uri) else {
        return respond(Reply::Bad("query"), &headers);
    };
    let reply = s
        .key(
            client(pep),
            &kid,
            q.get("domain"),
            q.get("as_of"),
            form(&headers),
        )
        .await;
    respond(reply, &headers)
}

async fn keys<K: KeyDirectory, T: Tenants, S>(
    State(s): Shared<K, T, S>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let reply = s.keys(client(pep), &body, form(&headers)).await;
    respond(reply, &headers)
}

async fn party<K: KeyDirectory, T: Tenants, S>(
    State(s): Shared<K, T, S>,
    Path(party): Path<String>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
) -> Response {
    let Some(q) = query(&uri) else {
        return respond(Reply::Bad("query"), &headers);
    };
    let reply = s
        .party(
            client(pep),
            &party,
            q.get("domain"),
            q.get("as_of"),
            form(&headers),
        )
        .await;
    respond(reply, &headers)
}

async fn parties<K: KeyDirectory, T: Tenants, S>(
    State(s): Shared<K, T, S>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let reply = s.parties(client(pep), &body, form(&headers)).await;
    respond(reply, &headers)
}

async fn snapshot<K: KeyDirectory, T: Tenants, S>(
    State(s): Shared<K, T, S>,
    Path(tenant): Path<String>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
) -> Response {
    let reply = s.snapshot(client(pep), &tenant).await;
    respond(reply, &headers)
}

async fn tenants<K: KeyDirectory, T: Tenants, S>(
    State(s): Shared<K, T, S>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
) -> Response {
    let Some(q) = query(&uri) else {
        return respond(Reply::Bad("query"), &headers);
    };
    let reply = s.tenants(client(pep), q.get("cursor")).await;
    respond(reply, &headers)
}

async fn resolve<K: KeyDirectory + Exercises, T: Tenants, S: Subjects>(
    State(s): Shared<K, T, S>,
    Path(tenant): Path<String>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let reply = s.resolve(client(pep), &tenant, &body).await;
    respond(reply, &headers)
}

async fn exercise<K: KeyDirectory + Exercises, T: Tenants, S: Subjects>(
    State(s): Shared<K, T, S>,
    Path(id): Path<String>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
) -> Response {
    let Some(q) = query(&uri) else {
        return respond(Reply::Bad("query"), &headers);
    };
    let reply = s.exercise(client(pep), &id, q.get("domain")).await;
    respond(reply, &headers)
}

async fn agency<K: KeyDirectory + Exercises, T: Tenants, S: Subjects>(
    State(s): Shared<K, T, S>,
    Path(id): Path<String>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
) -> Response {
    let Some(q) = query(&uri) else {
        return respond(Reply::Bad("query"), &headers);
    };
    let reply = s.agency(client(pep), &id, q.get("domain")).await;
    respond(reply, &headers)
}

fn respond(reply: Reply, headers: &HeaderMap) -> Response {
    let mut response = match reply {
        Reply::Json(v) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            v.to_string(),
        )
            .into_response(),
        Reply::Keys {
            body,
            form,
            excerpt,
            position,
            cache,
        } => {
            let content_type = match form {
                Form::Cose => COSE_CONTENT_TYPE,
                Form::Json => "application/json",
            };
            let mut r = (
                [
                    (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
                    (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
                    (header::VARY, HeaderValue::from_static("Accept")),
                ],
                body,
            )
                .into_response();
            if let Ok(tag) = HeaderValue::from_str(&format!("\"{position}\"")) {
                r.headers_mut().insert(header::ETAG, tag);
            }
            if let Some(e) = excerpt.and_then(|e| HeaderValue::from_str(&b64url_encode(&e)).ok()) {
                r.headers_mut().insert(EXCERPT_HEADER, e);
            }
            r
        }
        Reply::Bad(code) => {
            Problem::new(StatusCode::BAD_REQUEST, code, "Bad Request").into_response()
        }
        Reply::Unauthenticated => Problem::new(
            StatusCode::UNAUTHORIZED,
            "pep-unauthenticated",
            "Unauthorized",
        )
        .into_response(),
        Reply::NotFound(code) => {
            Problem::new(StatusCode::NOT_FOUND, code, "Not Found").into_response()
        }
        Reply::Unavailable(reason) => Problem::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Service Unavailable",
        )
        .with_reason(reason)
        .into_response(),
        Reply::Limited => Problem::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate-limited",
            "Too Many Requests",
        )
        .into_response(),
    };
    if let Some(id) = headers.get(&REQUEST_ID) {
        response.headers_mut().insert(REQUEST_ID, id.clone());
    }
    response
}

impl<K, B, S, C> KeyDirectory for Domains<K, B, S, C>
where
    K: Keys,
    B: Binding + Clone + Send + Sync,
    S: Salts + Clone + Send + Sync,
    C: Clock + Clone + Send + Sync,
{
    async fn lookup(
        &self,
        domain: Digest,
        kids: Vec<[u8; 32]>,
        as_of: AsOf,
        sign: bool,
    ) -> Result<KeyAnswer, CoreError> {
        self.lookup_keys(domain, &kids, as_of, sign).await
    }

    async fn parties(
        &self,
        domain: Digest,
        parties: Vec<Id>,
        as_of: AsOf,
        sign: bool,
    ) -> Result<PartyAnswer, CoreError> {
        self.lookup_parties(domain, &parties, as_of, sign).await
    }
}

impl<K, B, S, C> Exercises for Domains<K, B, S, C>
where
    K: Keys,
    B: Binding + Clone + Send + Sync,
    S: Salts + Clone + Send + Sync,
    C: Clock + Clone + Send + Sync,
{
    async fn exercise(
        &self,
        domain: Digest,
        exercise: Digest,
    ) -> Result<Option<ExerciseRecord>, CoreError> {
        self.exercise_record(domain, exercise).await
    }
}
