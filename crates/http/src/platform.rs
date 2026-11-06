//! The platform product API over HTTP (OP-149 m.4, m.16 (a), m.17 (e), (g)): pairing with a
//! tenant and the platform client's event streams. The caller is a platform client
//! authenticated by `private_key_jwt` (RFC 7523): `Authorization: Bearer` carries a client
//! assertion whose `aud` is its realm's issuer. Answers are `no-store`. The contract is
//! `sdks/openapi/access-v1.json`.

use std::sync::Arc;

use access_identity_admin::app::platform::{Caller, PlatformApi, PlatformError};
use access_identity_admin::ports::Instances;
use access_identity_events::ports::{Clock, Random, Sealer};
use access_identity_oauth::ports::Directory;
use access_identity_oauth::ports::oauth::ClientKeys;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::Value;

use crate::Problem;

/// `POST`: a pairing challenge per realm of a tenant.
pub const CHALLENGES_PATH: &str = "/access/v1/tenants/{tenant}/pairing/challenges";
/// `POST`: the product's signed Exercises for those realms.
pub const PAIRING_PATH: &str = "/access/v1/tenants/{tenant}/pairing";
/// `POST` creates, `GET` lists the platform client's streams.
pub const STREAMS_PATH: &str = "/access/v1/platform/streams";
/// `GET` reads, `DELETE` disables one of them.
pub const STREAM_PATH: &str = "/access/v1/platform/streams/{id}";
/// `GET` reads, `POST` sets one's status (SSF 1.0 §8.1.2, OP-149 m.26 (c)).
pub const STREAM_STATUS_PATH: &str = "/access/v1/platform/streams/{id}/status";

/// Largest request body.
pub const MAX_BODY: usize = 128 * 1024;

struct Shared<D, C, I, K, R, T> {
    api: Arc<PlatformApi<D, C, I, K, R, T>>,
    base: String,
}

type St<D, C, I, K, R, T> = State<Arc<Shared<D, C, I, K, R, T>>>;

/// The platform routes over `api`, which the product routes share as their assertion verifier
/// (OP-149 m.37); `api_base` is the deployment's base URL, which the assertion may also name as
/// its endpoint audience.
pub fn router<D, C, I, K, R, T>(api: Arc<PlatformApi<D, C, I, K, R, T>>, api_base: String) -> Router
where
    D: Directory + 'static,
    C: ClientKeys + 'static,
    I: Instances + 'static,
    K: Sealer + 'static,
    R: Random + 'static,
    T: Clock + Send + Sync + 'static,
{
    Router::new()
        .route(CHALLENGES_PATH, post(challenges::<D, C, I, K, R, T>))
        .route(PAIRING_PATH, post(pair::<D, C, I, K, R, T>))
        .route(
            STREAMS_PATH,
            post(create_stream::<D, C, I, K, R, T>).get(list_streams::<D, C, I, K, R, T>),
        )
        .route(
            STREAM_PATH,
            get(read_stream::<D, C, I, K, R, T>).delete(close_stream::<D, C, I, K, R, T>),
        )
        .route(
            STREAM_STATUS_PATH,
            get(stream_status::<D, C, I, K, R, T>).post(set_stream_status::<D, C, I, K, R, T>),
        )
        .with_state(Arc::new(Shared {
            api,
            base: api_base,
        }))
}

/// The bearer value, when `Authorization` is sent once.
pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    let mut all = headers.get_all(header::AUTHORIZATION).iter();
    let first = all.next()?;
    if all.next().is_some() {
        return None;
    }
    let (scheme, token) = first.to_str().ok()?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token.trim())
}

async fn caller<D, C, I, K, R, T>(
    s: &Shared<D, C, I, K, R, T>,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<Caller, PlatformError>
where
    D: Directory,
    C: ClientKeys,
    I: Instances,
    K: Sealer,
    R: Random,
    T: Clock + Send + Sync,
{
    let assertion = bearer(headers).ok_or(PlatformError::Unauthenticated)?;
    let endpoint = format!("{}{}", s.base, uri.path());
    s.api.authenticate(assertion, &endpoint).await
}

fn problem(e: PlatformError) -> Response {
    let (status, code) = e.problem();
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut r = Problem::new(status, code, "Platform request refused").into_response();
    if status == StatusCode::UNAUTHORIZED {
        r.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer error=\"invalid_token\""),
        );
    }
    r
}

fn reply(status: StatusCode, r: Result<Value, PlatformError>) -> Response {
    let mut response = match r {
        Ok(v) => (
            status,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            serde_json::to_vec(&v).unwrap_or_default(),
        )
            .into_response(),
        Err(e) => problem(e),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn too_large(body: &Bytes) -> Result<(), PlatformError> {
    if body.len() > MAX_BODY {
        Err(PlatformError::Invalid("too-large"))
    } else {
        Ok(())
    }
}

async fn challenges<D, C, I, K, R, T>(
    State(s): St<D, C, I, K, R, T>,
    Path(tenant): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    C: ClientKeys,
    I: Instances,
    K: Sealer,
    R: Random,
    T: Clock + Send + Sync,
{
    let r = async {
        too_large(&body)?;
        let c = caller(&s, &headers, &uri).await?;
        s.api.challenges(&c, &tenant, &body).await
    };
    reply(StatusCode::CREATED, r.await)
}

async fn pair<D, C, I, K, R, T>(
    State(s): St<D, C, I, K, R, T>,
    Path(tenant): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    C: ClientKeys,
    I: Instances,
    K: Sealer,
    R: Random,
    T: Clock + Send + Sync,
{
    let r = async {
        too_large(&body)?;
        let c = caller(&s, &headers, &uri).await?;
        s.api.pair(&c, &tenant, &body).await
    };
    reply(StatusCode::OK, r.await)
}

async fn create_stream<D, C, I, K, R, T>(
    State(s): St<D, C, I, K, R, T>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    C: ClientKeys,
    I: Instances,
    K: Sealer,
    R: Random,
    T: Clock + Send + Sync,
{
    let r = async {
        too_large(&body)?;
        let c = caller(&s, &headers, &uri).await?;
        s.api.create_stream(&c, &body).await
    };
    reply(StatusCode::CREATED, r.await)
}

async fn list_streams<D, C, I, K, R, T>(
    State(s): St<D, C, I, K, R, T>,
    uri: Uri,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    C: ClientKeys,
    I: Instances,
    K: Sealer,
    R: Random,
    T: Clock + Send + Sync,
{
    let r = async {
        let c = caller(&s, &headers, &uri).await?;
        s.api.streams(&c).await
    };
    reply(StatusCode::OK, r.await)
}

async fn read_stream<D, C, I, K, R, T>(
    State(s): St<D, C, I, K, R, T>,
    Path(id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    C: ClientKeys,
    I: Instances,
    K: Sealer,
    R: Random,
    T: Clock + Send + Sync,
{
    let r = async {
        let c = caller(&s, &headers, &uri).await?;
        s.api.stream(&c, &id).await
    };
    reply(StatusCode::OK, r.await)
}

async fn stream_status<D, C, I, K, R, T>(
    State(s): St<D, C, I, K, R, T>,
    Path(id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    C: ClientKeys,
    I: Instances,
    K: Sealer,
    R: Random,
    T: Clock + Send + Sync,
{
    let r = async {
        let c = caller(&s, &headers, &uri).await?;
        s.api.stream_status(&c, &id).await
    };
    reply(StatusCode::OK, r.await)
}

async fn set_stream_status<D, C, I, K, R, T>(
    State(s): St<D, C, I, K, R, T>,
    Path(id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    C: ClientKeys,
    I: Instances,
    K: Sealer,
    R: Random,
    T: Clock + Send + Sync,
{
    let r = async {
        too_large(&body)?;
        let c = caller(&s, &headers, &uri).await?;
        s.api.set_stream_status(&c, &id, &body).await
    };
    reply(StatusCode::OK, r.await)
}

async fn close_stream<D, C, I, K, R, T>(
    State(s): St<D, C, I, K, R, T>,
    Path(id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    C: ClientKeys,
    I: Instances,
    K: Sealer,
    R: Random,
    T: Clock + Send + Sync,
{
    let r = async {
        let c = caller(&s, &headers, &uri).await?;
        s.api.close_stream(&c, &id).await
    };
    match r.await {
        Ok(()) => {
            let mut resp = StatusCode::NO_CONTENT.into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Err(e) => reply(StatusCode::OK, Err(e)),
    }
}
