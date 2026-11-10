//! Handles on axum (E56, OP-156 m.4 Q20): the `frontend-v1` `/v1/me/handles` routes at the
//! realm's host and under `/realms/{slug}`, on the session cookie and the same-origin rule, and
//! `GET /.well-known/access-handle` on any host, which answers the DID a verified Suiss handle of
//! that host points at. Writes take an `Idempotency-Key`.

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::app::handle::HandleClaim;
use access_identity_ui::domain::handle::{Handle, WELL_KNOWN};
use access_identity_ui::ports::{Clock, HandleDirectory, HandleHosts, Kits, Messages};
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};

use super::web::{Jar, json_only, problem, realm, same_origin, send};
use super::{Peer, Shared, idempotency};

/// Largest request body.
const MAX_BODY: usize = 1024;

struct Svc<D, K, KI, C, M, H> {
    login: Shared<D, K, KI, C, M>,
    hosts: H,
}

type St<D, K, KI, C, M, H> = State<Arc<Svc<D, K, KI, C, M, H>>>;
type Params = Path<HashMap<String, String>>;

/// `GET /.well-known/access-handle` on any host, answered from `directory`.
pub fn well_known_router<R: HandleDirectory + Clone + 'static>(directory: R) -> Router {
    Router::new()
        .route(WELL_KNOWN, get(well_known::<R>))
        .with_state(directory)
}

/// The handle routes of lane Q20, the well-known answer from `directory` with them; `hosts`
/// reaches the hosts of handles people own.
pub fn router<D, K, KI, C, M, H, R>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
    directory: R,
    hosts: H,
) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
    H: HandleHosts + 'static,
    R: HandleDirectory + Clone + 'static,
{
    let svc = Arc::new(Svc {
        login: Shared {
            discovery,
            hosted: hosted.into(),
            assets: None,
        },
        hosts,
    });
    let mut writes = Router::new();
    let mut reads = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        writes = writes
            .route(
                &format!("{prefix}/v1/me/handles"),
                post(claim::<D, K, KI, C, M, H>),
            )
            .route(
                &format!("{prefix}/v1/me/handles/{{handle}}/verify"),
                post(verify::<D, K, KI, C, M, H>),
            )
            .route(
                &format!("{prefix}/v1/me/handles/{{handle}}/retire"),
                post(retire::<D, K, KI, C, M, H>),
            );
        reads = reads.route(
            &format!("{prefix}/v1/me/handles"),
            get(list::<D, K, KI, C, M, H>),
        );
    }
    let cache = Arc::new(idempotency::Cache::default());
    writes
        .route_layer(axum::middleware::from_fn_with_state(
            cache,
            idempotency::layer,
        ))
        .merge(reads)
        .with_state(svc)
        .merge(well_known_router(directory))
}

fn bad() -> Response {
    problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request")
}

/// `GET /.well-known/access-handle` (E56 (2)): the DID, as plain text, of the verified Suiss
/// handle that is this request's host; `404` for any other host.
async fn well_known<R: HandleDirectory>(
    State(directory): State<R>,
    headers: HeaderMap,
) -> Response {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h));
    let Some(handle) = host.and_then(Handle::parse) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match directory.did_of_host(handle.as_str()).await {
        Ok(Some(did)) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(header::CACHE_CONTROL, "max-age=300")
            .body(Body::from(did))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// `GET /v1/me/handles`.
async fn list<D, K, KI, C, M, H>(
    State(s): St<D, K, KI, C, M, H>,
    Path(p): Params,
    peer: Option<Extension<Peer>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    K: Keys,
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
    H: HandleHosts,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let jar = Jar::of(&headers, peer);
    let reply = s.login.hosted.handles(&entry, &jar.browser()).await;
    send(reply, &headers).await
}

/// `POST /v1/me/handles`.
async fn claim<D, K, KI, C, M, H>(
    State(s): St<D, K, KI, C, M, H>,
    Path(p): Params,
    peer: Option<Extension<Peer>>,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response
where
    D: Directory,
    K: Keys,
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
    H: HandleHosts,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = same_origin(&headers) {
        return r;
    }
    if let Err(r) = json_only(&headers) {
        return r;
    }
    if bytes.len() > MAX_BODY {
        return bad();
    }
    let Ok(body) = serde_json::from_slice::<HandleClaim>(&bytes) else {
        return bad();
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .claim_handle(&entry, &jar.browser(), &body)
        .await;
    send(reply, &headers).await
}

fn id_of(p: &HashMap<String, String>) -> Option<&str> {
    p.get("handle")
        .map(String::as_str)
        .filter(|h| !h.is_empty() && h.len() <= 64)
}

/// `POST /v1/me/handles/{handle}/verify`.
async fn verify<D, K, KI, C, M, H>(
    State(s): St<D, K, KI, C, M, H>,
    Path(p): Params,
    peer: Option<Extension<Peer>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    K: Keys,
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
    H: HandleHosts,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = same_origin(&headers) {
        return r;
    }
    let Some(id) = id_of(&p) else {
        return bad();
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .verify_handle(&s.hosts, &entry, &jar.browser(), id)
        .await;
    send(reply, &headers).await
}

/// `POST /v1/me/handles/{handle}/retire`.
async fn retire<D, K, KI, C, M, H>(
    State(s): St<D, K, KI, C, M, H>,
    Path(p): Params,
    peer: Option<Extension<Peer>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    K: Keys,
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
    H: HandleHosts,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = same_origin(&headers) {
        return r;
    }
    let Some(id) = id_of(&p) else {
        return bad();
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .retire_handle(&entry, &jar.browser(), id)
        .await;
    send(reply, &headers).await
}
