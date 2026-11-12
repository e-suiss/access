//! Support access on axum (MD-9, TN-137, OP-157 m.3 (f), (g)): the `frontend-v1` `/v1/support/*`,
//! `/v1/me/support-access*` and `/v1/me/support-block` routes at the realm's host and under
//! `/realms/{slug}`. They ride on the session cookie and the same-origin rule; every grant,
//! revoke, upload and read carries the device Instance's own signed Exercise. Writes take an
//! `Idempotency-Key`.

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::app::support::{Ask, Block, Signed};
use access_identity_ui::ports::{Clock, Kits, Messages};
use access_internal_api::support::SupportAuthority;
use access_kernel::json::b64url_decode;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::{Extension, Router};
use serde::de::DeserializeOwned;

use super::web::{Jar, json_only, problem, realm, same_origin, send};
use super::{Peer, Shared, idempotency};

/// Largest JSON body other than an artifact upload.
const MAX_BODY: usize = 48 * 1024;

/// The header an artifact read carries the reader's signed Exercise in, base64url JSON.
pub const EXERCISE_HEADER: &str = "access-exercise";

struct Svc<D, K, KI, C, M, A> {
    login: Shared<D, K, KI, C, M>,
    authority: A,
    pep: String,
    /// The streamed uploads' `Idempotency-Key` answers (OP-159 m.3 (mm)).
    uploads: idempotency::Cache,
}

type St<D, K, KI, C, M, A> = State<Arc<Svc<D, K, KI, C, M, A>>>;
type Params = Path<HashMap<String, String>>;

/// The support access routes of lane V2; `pep` is the identity plane's PEP name in the
/// governing domain.
pub fn router<D, K, KI, C, M, A>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
    authority: A,
    pep: String,
) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
    A: SupportAuthority + 'static,
{
    let svc = Arc::new(Svc {
        login: Shared {
            discovery,
            hosted: hosted.into(),
            assets: None,
        },
        authority,
        pep,
        uploads: idempotency::Cache::default(),
    });
    let mut writes = Router::new();
    let mut reads = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        writes = writes
            .route(
                &format!("{prefix}/v1/support/requests"),
                post(ask::<D, K, KI, C, M, A>),
            )
            .route(
                &format!("{prefix}/v1/support/requests/{{request}}/decline"),
                post(decline::<D, K, KI, C, M, A>),
            )
            .route(
                &format!("{prefix}/v1/support/requests/{{request}}/give"),
                post(give::<D, K, KI, C, M, A>),
            )
            .route(
                &format!("{prefix}/v1/me/support-access/{{grant}}/revoke"),
                post(revoke::<D, K, KI, C, M, A>),
            )
            .route(
                &format!("{prefix}/v1/me/support-block"),
                put(block::<D, K, KI, C, M, A>),
            );
        reads = reads
            .route(
                &format!("{prefix}/v1/support/artifacts"),
                post(upload::<D, K, KI, C, M, A>),
            )
            .route(
                &format!("{prefix}/v1/support/requests"),
                get(list::<D, K, KI, C, M, A>),
            )
            .route(
                &format!("{prefix}/v1/support/artifacts/{{artifact}}"),
                get(artifact::<D, K, KI, C, M, A>),
            )
            .route(
                &format!("{prefix}/v1/me/support-access"),
                get(access::<D, K, KI, C, M, A>),
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
}

fn bad() -> Response {
    problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request")
}

#[expect(
    clippy::result_large_err,
    reason = "the refusal is the response itself"
)]
fn body<T: DeserializeOwned>(
    headers: &HeaderMap,
    bytes: &Bytes,
    max: usize,
) -> Result<T, Response> {
    json_only(headers)?;
    if bytes.len() > max {
        return Err(problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            "artifact-too-large",
            "Payload Too Large",
        ));
    }
    serde_json::from_slice::<T>(bytes).map_err(|_| bad())
}

fn param<'a>(p: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    p.get(name)
        .map(String::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 64)
}

macro_rules! entry {
    ($s:expr, $p:expr, $uri:expr, $headers:expr, $write:expr) => {{
        let e = match realm(&$s.login, &$p, &$uri, &$headers).await {
            Ok(e) => e,
            Err(r) => return r,
        };
        if $write && let Err(r) = same_origin(&$headers) {
            return r;
        }
        e
    }};
}

/// `POST /v1/support/requests`.
async fn ask<D, K, KI, C, M, A>(
    State(s): St<D, K, KI, C, M, A>,
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
    A: SupportAuthority,
{
    let entry = entry!(s, p, uri, headers, true);
    let b: Ask = match body(&headers, &bytes, MAX_BODY) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let jar = Jar::of(&headers, peer);
    let reply = s.login.hosted.ask_support(&entry, &jar.browser(), &b).await;
    send(reply, &headers).await
}

/// `GET /v1/support/requests`.
async fn list<D, K, KI, C, M, A>(
    State(s): St<D, K, KI, C, M, A>,
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
    A: SupportAuthority,
{
    let entry = entry!(s, p, uri, headers, false);
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .support_requests(&s.authority, &s.pep, &entry, &jar.browser())
        .await;
    send(reply, &headers).await
}

/// `POST /v1/support/requests/{request}/decline`.
async fn decline<D, K, KI, C, M, A>(
    State(s): St<D, K, KI, C, M, A>,
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
    A: SupportAuthority,
{
    let entry = entry!(s, p, uri, headers, true);
    let Some(request) = param(&p, "request") else {
        return bad();
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .decline_support(&entry, &jar.browser(), request)
        .await;
    send(reply, &headers).await
}

/// `POST /v1/support/requests/{request}/give`.
async fn give<D, K, KI, C, M, A>(
    State(s): St<D, K, KI, C, M, A>,
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
    A: SupportAuthority,
{
    let entry = entry!(s, p, uri, headers, true);
    let Some(request) = param(&p, "request") else {
        return bad();
    };
    let b: Signed = match body(&headers, &bytes, MAX_BODY) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .give_support(&s.authority, &s.pep, &entry, &jar.browser(), request, &b)
        .await;
    send(reply, &headers).await
}

/// `GET /v1/me/support-access`.
async fn access<D, K, KI, C, M, A>(
    State(s): St<D, K, KI, C, M, A>,
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
    A: SupportAuthority,
{
    let entry = entry!(s, p, uri, headers, false);
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .support_access(&s.authority, &s.pep, &entry, &jar.browser())
        .await;
    send(reply, &headers).await
}

/// `POST /v1/me/support-access/{grant}/revoke`.
async fn revoke<D, K, KI, C, M, A>(
    State(s): St<D, K, KI, C, M, A>,
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
    A: SupportAuthority,
{
    let entry = entry!(s, p, uri, headers, true);
    let Some(grant) = param(&p, "grant") else {
        return bad();
    };
    let b: Signed = match body(&headers, &bytes, MAX_BODY) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .revoke_support(&s.authority, &s.pep, &entry, &jar.browser(), grant, &b)
        .await;
    send(reply, &headers).await
}

/// `PUT /v1/me/support-block`.
async fn block<D, K, KI, C, M, A>(
    State(s): St<D, K, KI, C, M, A>,
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
    A: SupportAuthority,
{
    let entry = entry!(s, p, uri, headers, true);
    let b: Block = match body(&headers, &bytes, MAX_BODY) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .put_support_block(&entry, &jar.browser(), b)
        .await;
    send(reply, &headers).await
}

/// The query member naming the support request an artifact is for.
const REQUEST_QUERY: &str = "request";

fn query_param<'a>(uri: &'a Uri, name: &str) -> Option<&'a str> {
    uri.query()?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty() && v.len() <= 64)
}

fn too_large() -> Response {
    problem(
        StatusCode::PAYLOAD_TOO_LARGE,
        "artifact-too-large",
        "Payload Too Large",
    )
}

/// Reads `body` up to `limit` bytes as it streams in, and the SHA-256 of what it read
/// (OP-159 m.3 (mm)); one byte more is `413` and nothing after it is read.
#[expect(
    clippy::result_large_err,
    reason = "the refusal is the response itself"
)]
async fn stream_in(mut body: Body, limit: usize) -> Result<(Vec<u8>, [u8; 32]), Response> {
    use http_body_util::BodyExt as _;
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                let over = std::error::Error::source(&e)
                    .is_some_and(<dyn std::error::Error>::is::<http_body_util::LengthLimitError>)
                    || e.to_string().contains("length limit");
                return Err(if over { too_large() } else { bad() });
            }
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if out.len().saturating_add(data.len()) > limit {
            return Err(too_large());
        }
        out.extend_from_slice(&data);
    }
    let digest = suiss_crypto::digest::sha256(&out);
    Ok((out, digest))
}

/// `POST /v1/support/artifacts?request={request}` (OP-157 m.3 (g), OP-159 m.3 (mm)): the body
/// is the artifact itself (`application/json`, `application/har+json` or `text/plain`), and the
/// person's signed `idp.account.artifact_upload` Exercise rides in the [`EXERCISE_HEADER`]
/// header. An image or video answers 415, and the session, the realm's artifact policy and the
/// person's own request are checked, before a byte of the body is read
/// (GHSA-84jc-3hj2-hwc7). The body then streams in under the realm's `max_bytes`, and the
/// `Idempotency-Key` covers its content digest.
async fn upload<D, K, KI, C, M, A>(
    State(s): St<D, K, KI, C, M, A>,
    Path(p): Params,
    peer: Option<Extension<Peer>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response
where
    D: Directory,
    K: Keys,
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
    A: SupportAuthority,
{
    let entry = entry!(s, p, uri, headers, true);
    let media = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    // TN-74, OP-157 m.3 (g)
    if media.starts_with("image/") || media.starts_with("video/") {
        return problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "artifact-format-refused",
            "Unsupported Media Type",
        );
    }
    if let Err(r) = idempotency::key(&headers) {
        return r;
    }
    let jar = Jar::of(&headers, peer);
    // GHSA-84jc-3hj2-hwc7, OP-159 m.3 (mm)
    let gate = match s
        .login
        .hosted
        .open_upload(
            &entry,
            &jar.browser(),
            query_param(&uri, REQUEST_QUERY).unwrap_or_default(),
        )
        .await
    {
        Ok(g) => g,
        Err(reply) => return send(reply, &headers).await,
    };
    let limit = gate.limit();
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| usize::try_from(n).map_or(true, |n| n > limit)) {
        return too_large();
    }
    let raw_exercise = headers
        .get(EXERCISE_HEADER)
        .map(HeaderValue::as_bytes)
        .unwrap_or_default();
    let exercise: Option<Signed> = std::str::from_utf8(raw_exercise)
        .ok()
        .filter(|v| v.len() <= MAX_BODY)
        .and_then(|v| b64url_decode(v).ok())
        .and_then(|b| serde_json::from_slice(&b).ok());
    let (content, digest) = match stream_in(body, limit).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (Some(exercise), Ok(text)) = (exercise, String::from_utf8(content)) else {
        return bad();
    };
    let content = suiss_crypto::digest::sha256(
        &[
            media.as_bytes(),
            b"\n",
            &suiss_crypto::digest::sha256(raw_exercise),
            &digest,
        ]
        .concat(),
    );
    let run = async {
        let reply = s
            .login
            .hosted
            .finish_upload(
                &s.authority,
                &s.pep,
                gate,
                &jar.browser(),
                (&media, &text, &exercise),
            )
            .await;
        send(reply, &headers).await
    };
    idempotency::once(&s.uploads, (&method, &uri, &headers), content, run).await
}

/// `GET /v1/support/artifacts/{artifact}`: the reader's signed `idp.account.artifact_read`
/// Exercise rides in the [`EXERCISE_HEADER`] header.
async fn artifact<D, K, KI, C, M, A>(
    State(s): St<D, K, KI, C, M, A>,
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
    A: SupportAuthority,
{
    let entry = entry!(s, p, uri, headers, false);
    let Some(artifact) = param(&p, "artifact") else {
        return bad();
    };
    let exercise: Option<Signed> = headers
        .get(EXERCISE_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= MAX_BODY)
        .and_then(|v| b64url_decode(v).ok())
        .and_then(|b| serde_json::from_slice(&b).ok());
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .read_artifact(
            &s.authority,
            &s.pep,
            &entry,
            &jar.browser(),
            artifact,
            exercise.as_ref(),
        )
        .await;
    send(reply, &headers).await
}
