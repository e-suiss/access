//! The product client API on axum (OP-149 m.4, m.5, m.28 (c), m.37), and the authority core as
//! its key and Party directory. The caller is the PEP the TLS layer named from its certificate,
//! as for the ADP (OP-141 m.18 (b)), or a platform client by the RFC 7523 assertion it bears,
//! verified by the platform API as on the pairing routes (OP-149 m.19 (e)).

use std::sync::Arc;

use access_authority_core::CoreError;
use access_authority_core::adapters::{Domains, ExerciseRecord, KeyAnswer, PartyAnswer};
use access_authority_core::keys::AsOf;
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_identity_admin::app::platform::{PlatformApi, PlatformError};
use access_identity_admin::ports::Instances;
use access_identity_oauth::domain::request::Params;
use access_identity_oauth::ports::Directory;
use access_identity_oauth::ports::oauth::ClientKeys;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::model::Id;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use super::app::{Credentials, Form, Reply, Service};
use super::ports::{
    AssertionRefused, Caller, ClientAssertions, Exercises, KeyDirectory, PlatformClient, Subjects,
    Tenants,
};
use crate::Problem;
use crate::adp::adapters::Pep;

/// Content type of the signed key lookup answer (RFC 9052).
pub const COSE_CONTENT_TYPE: &str = "application/cose; cose-type=\"cose-sign1\"";

/// The response header carrying the signed answer's key excerpt, base64url (CR-58 m.1).
pub const EXCERPT_HEADER: HeaderName = HeaderName::from_static("access-key-excerpt");

const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

type Shared<K, T, S, A> = State<Arc<Service<K, T, S, A>>>;

/// The product client routes.
pub fn router<K, T, S, A>(service: Service<K, T, S, A>) -> Router
where
    K: KeyDirectory + Exercises + 'static,
    T: Tenants + 'static,
    S: Subjects + 'static,
    A: ClientAssertions + 'static,
{
    Router::new()
        .route("/access/v1/keys/{kid}", get(key::<K, T, S, A>))
        .route("/access/v1/keys:batchGet", post(keys::<K, T, S, A>))
        .route("/access/v1/parties/{party}", get(party::<K, T, S, A>))
        .route("/access/v1/parties:batchGet", post(parties::<K, T, S, A>))
        .route("/access/v1/tenants", get(tenants::<K, T, S, A>))
        .route(
            "/access/v1/tenants/{tenant}/snapshot",
            get(snapshot::<K, T, S, A>),
        )
        .route(
            "/access/v1/tenants/{tenant}/subjects:resolve",
            post(resolve::<K, T, S, A>),
        )
        .route("/access/v1/exercises/{id}", get(exercise::<K, T, S, A>))
        .route(
            "/access/v1/exercises/{id}/agency",
            get(agency::<K, T, S, A>),
        )
        .with_state(Arc::new(service))
}

/// The query parameters; a repeated one is refused.
fn query(uri: &Uri) -> Option<Params> {
    Params::parse(uri.query().unwrap_or_default()).ok()
}

fn client(pep: Option<axum::Extension<Pep>>) -> Option<String> {
    pep.map(|axum::Extension(Pep(p))| p)
}

/// What the request carries to name its caller (OP-149 m.37). An `Authorization` header that
/// is not one bearer value is carried as an assertion that will not verify.
fn credentials(pep: Option<axum::Extension<Pep>>, headers: &HeaderMap, uri: &Uri) -> Credentials {
    let assertion = if headers.contains_key(header::AUTHORIZATION) {
        Some(
            crate::platform::bearer(headers)
                .map(String::from)
                .unwrap_or_default(),
        )
    } else {
        None
    };
    Credentials {
        pep: client(pep),
        assertion,
        path: uri.path().to_owned(),
    }
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

/// Runs `route` for the authenticated caller, or answers why there is none.
async fn with_caller<K, T, S, A: ClientAssertions>(
    s: &Service<K, T, S, A>,
    pep: Option<axum::Extension<Pep>>,
    headers: &HeaderMap,
    uri: &Uri,
    route: impl AsyncFnOnce(Caller) -> Reply,
) -> Response {
    let reply = match s.caller(credentials(pep, headers, uri)).await {
        Ok(caller) => route(caller).await,
        Err(reply) => reply,
    };
    respond(reply, headers)
}

async fn key<K: KeyDirectory, T: Tenants, S, A: ClientAssertions>(
    State(s): Shared<K, T, S, A>,
    Path(kid): Path<String>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
) -> Response {
    let Some(q) = query(&uri) else {
        return respond(Reply::Bad("query"), &headers);
    };
    with_caller(&s, pep, &headers, &uri, async |c| {
        s.key(&c, &kid, q.get("domain"), q.get("as_of"), form(&headers))
            .await
    })
    .await
}

async fn keys<K: KeyDirectory, T: Tenants, S, A: ClientAssertions>(
    State(s): Shared<K, T, S, A>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    with_caller(&s, pep, &headers, &uri, async |c| {
        s.keys(&c, &body, form(&headers)).await
    })
    .await
}

async fn party<K: KeyDirectory, T: Tenants, S, A: ClientAssertions>(
    State(s): Shared<K, T, S, A>,
    Path(party): Path<String>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
) -> Response {
    let Some(q) = query(&uri) else {
        return respond(Reply::Bad("query"), &headers);
    };
    with_caller(&s, pep, &headers, &uri, async |c| {
        s.party(&c, &party, q.get("domain"), q.get("as_of"), form(&headers))
            .await
    })
    .await
}

async fn parties<K: KeyDirectory, T: Tenants, S, A: ClientAssertions>(
    State(s): Shared<K, T, S, A>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    with_caller(&s, pep, &headers, &uri, async |c| {
        s.parties(&c, &body, form(&headers)).await
    })
    .await
}

async fn snapshot<K: KeyDirectory, T: Tenants, S, A: ClientAssertions>(
    State(s): Shared<K, T, S, A>,
    Path(tenant): Path<String>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
) -> Response {
    with_caller(&s, pep, &headers, &uri, async |c| {
        s.snapshot(&c, &tenant).await
    })
    .await
}

async fn tenants<K: KeyDirectory, T: Tenants, S, A: ClientAssertions>(
    State(s): Shared<K, T, S, A>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
) -> Response {
    let Some(q) = query(&uri) else {
        return respond(Reply::Bad("query"), &headers);
    };
    with_caller(&s, pep, &headers, &uri, async |c| {
        s.tenants(&c, q.get("cursor")).await
    })
    .await
}

async fn resolve<K: KeyDirectory + Exercises, T: Tenants, S: Subjects, A: ClientAssertions>(
    State(s): Shared<K, T, S, A>,
    Path(tenant): Path<String>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    with_caller(&s, pep, &headers, &uri, async |c| {
        s.resolve(&c, &tenant, &body).await
    })
    .await
}

async fn exercise<K: KeyDirectory + Exercises, T: Tenants, S: Subjects, A: ClientAssertions>(
    State(s): Shared<K, T, S, A>,
    Path(id): Path<String>,
    uri: Uri,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
) -> Response {
    let Some(q) = query(&uri) else {
        return respond(Reply::Bad("query"), &headers);
    };
    with_caller(&s, pep, &headers, &uri, async |c| {
        s.exercise(&c, &id, q.get("domain")).await
    })
    .await
}

async fn agency<K: KeyDirectory + Exercises, T: Tenants, S: Subjects, A>(
    State(s): Shared<K, T, S, A>,
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
        Reply::ClientUnauthenticated => {
            let mut r = Problem::new(
                StatusCode::UNAUTHORIZED,
                "client-unauthenticated",
                "Unauthorized",
            )
            .into_response();
            r.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer error=\"invalid_token\""),
            );
            r
        }
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
        // OP-158 m.3 (u)
        Reply::Refused(code) => crate::problem::catalogued(code).into_response(),
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

// OP-149 m.37, m.19 (e)
impl<D, C, I, K, R, T> ClientAssertions for PlatformApi<D, C, I, K, R, T>
where
    D: Directory,
    C: ClientKeys,
    I: Instances,
    K: access_identity_events::ports::Sealer,
    R: access_identity_events::ports::Random,
    T: access_identity_events::ports::Clock + Send + Sync,
{
    async fn authenticate(
        &self,
        assertion: &str,
        endpoint: &str,
    ) -> Result<PlatformClient, AssertionRefused> {
        match PlatformApi::authenticate(self, assertion, endpoint).await {
            Ok(c) => Ok(PlatformClient {
                tenant: *c.tenant.as_bytes(),
                realm: *c.realm.as_bytes(),
                client_id: c.client_id,
                product: c.product.name().to_owned(),
            }),
            Err(PlatformError::Unavailable) => Err(AssertionRefused::Unavailable),
            Err(_) => Err(AssertionRefused::Unauthenticated),
        }
    }
}
