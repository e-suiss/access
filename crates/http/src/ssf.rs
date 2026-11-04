//! The realm's SSF transmitter over HTTP (OP-149 m.7, SSF 1.0, RFC 8936): the metadata at
//! `/.well-known/ssf-configuration`, the stream a bearer credential names at `/ssf/streams`
//! (`GET`, `PATCH`, `DELETE` disables it), and poll at `/ssf/poll`; at the host root for a
//! subdomain issuer and under `/realms/{slug}` for a path issuer. Stream and poll answers are
//! `no-store`.

use std::sync::Arc;

use access_identity_events::app::ssf::{SsfReply, StreamCall, Transmitter};
use access_identity_events::ports::{Clock, Random, Sealer, TokenSigner};
use access_identity_oauth::ports::Directory;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::Problem;

/// Largest poll or stream request body.
pub const MAX_BODY: usize = 64 * 1024;

type Shared<T> = State<Arc<T>>;

/// The transmitter routes.
pub fn router<D, K, R, S, C>(service: Transmitter<D, K, R, S, C>) -> Router
where
    D: Directory + 'static,
    K: Sealer + 'static,
    R: Random + 'static,
    S: TokenSigner + 'static,
    C: Clock + Send + Sync + 'static,
{
    type T<D, K, R, S, C> = Transmitter<D, K, R, S, C>;
    let shared = Arc::new(service);
    Router::new()
        .route(
            "/.well-known/ssf-configuration",
            get(
                |s: Shared<T<D, K, R, S, C>>, u: Uri, h: HeaderMap| async move {
                    reply(s.0.configuration(authority(&u, &h), None).await, false)
                },
            ),
        )
        .route(
            "/.well-known/ssf-configuration/realms/{slug}",
            get(
                |s: Shared<T<D, K, R, S, C>>, p: Path<String>, u: Uri, h: HeaderMap| async move {
                    reply(
                        s.0.configuration(authority(&u, &h), Some(&p.0)).await,
                        false,
                    )
                },
            ),
        )
        .route(
            "/realms/{slug}/.well-known/ssf-configuration",
            get(
                |s: Shared<T<D, K, R, S, C>>, p: Path<String>, u: Uri, h: HeaderMap| async move {
                    reply(
                        s.0.configuration(authority(&u, &h), Some(&p.0)).await,
                        false,
                    )
                },
            ),
        )
        .route(
            "/ssf/streams",
            get(streams::<D, K, R, S, C>)
                .patch(streams::<D, K, R, S, C>)
                .delete(streams::<D, K, R, S, C>),
        )
        .route(
            "/realms/{slug}/ssf/streams",
            get(streams_under::<D, K, R, S, C>)
                .patch(streams_under::<D, K, R, S, C>)
                .delete(streams_under::<D, K, R, S, C>),
        )
        .route("/ssf/poll", post(poll::<D, K, R, S, C>))
        .route("/realms/{slug}/ssf/poll", post(poll_under::<D, K, R, S, C>))
        .with_state(shared)
}

fn authority<'a>(uri: &'a Uri, headers: &'a HeaderMap) -> &'a str {
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str))
        .unwrap_or_default()
}

/// The RFC 6750 bearer credential, when sent once.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let mut all = headers.get_all(header::AUTHORIZATION).iter();
    let first = all.next()?;
    if all.next().is_some() {
        return None;
    }
    let v = first.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token.trim())
}

fn too_large(body: &Bytes) -> bool {
    body.len() > MAX_BODY
}

async fn stream_call<D, K, R, S, C>(
    s: &Transmitter<D, K, R, S, C>,
    slug: Option<&str>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Bytes,
) -> Response
where
    D: Directory,
    K: Sealer,
    R: Random,
    S: TokenSigner,
    C: Clock,
{
    if too_large(body) {
        return reply(SsfReply::Problem(413, "too-large"), true);
    }
    let call = match *method {
        Method::PATCH => StreamCall::Update(body),
        Method::DELETE => StreamCall::Disable,
        _ => StreamCall::Read,
    };
    reply(
        s.stream(authority(uri, headers), slug, bearer(headers), call)
            .await,
        true,
    )
}

async fn streams<D, K, R, S, C>(
    State(s): Shared<Transmitter<D, K, R, S, C>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    K: Sealer,
    R: Random,
    S: TokenSigner,
    C: Clock,
{
    stream_call(&s, None, &method, &uri, &headers, &body).await
}

async fn streams_under<D, K, R, S, C>(
    State(s): Shared<Transmitter<D, K, R, S, C>>,
    Path(slug): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    K: Sealer,
    R: Random,
    S: TokenSigner,
    C: Clock,
{
    stream_call(&s, Some(&slug), &method, &uri, &headers, &body).await
}

async fn poll<D, K, R, S, C>(
    State(s): Shared<Transmitter<D, K, R, S, C>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    K: Sealer,
    R: Random,
    S: TokenSigner,
    C: Clock,
{
    if too_large(&body) {
        return reply(SsfReply::Problem(413, "too-large"), true);
    }
    reply(
        s.poll(authority(&uri, &headers), None, bearer(&headers), &body)
            .await,
        true,
    )
}

async fn poll_under<D, K, R, S, C>(
    State(s): Shared<Transmitter<D, K, R, S, C>>,
    Path(slug): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    K: Sealer,
    R: Random,
    S: TokenSigner,
    C: Clock,
{
    if too_large(&body) {
        return reply(SsfReply::Problem(413, "too-large"), true);
    }
    reply(
        s.poll(
            authority(&uri, &headers),
            Some(&slug),
            bearer(&headers),
            &body,
        )
        .await,
        true,
    )
}

fn reply(r: SsfReply, no_store: bool) -> Response {
    let mut response = match r {
        SsfReply::Json(v) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            serde_json::to_vec(&v).unwrap_or_default(),
        )
            .into_response(),
        SsfReply::NoContent => StatusCode::NO_CONTENT.into_response(),
        SsfReply::Problem(status, code) => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let mut p = Problem::new(status, code, "SSF request refused").into_response();
            if status == StatusCode::UNAUTHORIZED {
                p.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer error=\"invalid_token\""),
                );
            }
            p
        }
    };
    if no_store {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}
