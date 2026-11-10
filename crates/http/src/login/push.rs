//! Push verification and approvers on axum (OP-156 m.3 (d), §10.2.3): the `frontend-v1` push and
//! approver routes, at the realm's host and under `/realms/{slug}`. Sending a push and the approver
//! routes ride on the login surface's cookies and same-origin rule; an approver's answer carries
//! its own signature and no cookie. Writes take an `Idempotency-Key`.

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::app::push::SameDeviceWire;
use access_identity_ui::ports::{Clock, Kits, Messages};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;

use super::web::{Jar, json_only, problem, realm, same_origin, send};
use super::{Peer, Shared, idempotency};

type St<D, K, KI, C, M> = State<Arc<Shared<D, K, KI, C, M>>>;
type Params = Path<HashMap<String, String>>;

/// Largest request body.
const MAX_BODY: usize = 4 * 1024;

/// The push and approver routes.
pub fn router<D, K, KI, C, M>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
{
    let shared = Arc::new(Shared {
        discovery,
        hosted: hosted.into(),
        assets: None,
    });
    let mut writes = Router::new();
    let mut reads = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        writes = writes
            .route(
                &format!("{prefix}/v1/push/challenge"),
                post(challenge::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/approvers"),
                post(register::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/approvers/{{device}}/retire"),
                post(retire::<D, K, KI, C, M>),
            );
        reads = reads
            .route(
                &format!("{prefix}/v1/push/answer"),
                post(answer::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/approvers"),
                get(list::<D, K, KI, C, M>),
            );
    }
    let cache = Arc::new(idempotency::Cache::default());
    writes
        .route_layer(axum::middleware::from_fn_with_state(
            cache,
            idempotency::layer,
        ))
        .merge(reads)
        .with_state(shared)
}

fn bad() -> Response {
    problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SameDeviceBody {
    device_key: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeBody {
    flow: String,
    #[serde(default)]
    same_device: Option<SameDeviceBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerBody {
    answer: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    name: String,
    public_key: String,
    proof: String,
}

#[expect(
    clippy::result_large_err,
    reason = "the refusal is the response itself"
)]
fn body<T: for<'de> Deserialize<'de>>(headers: &HeaderMap, bytes: &Bytes) -> Result<T, Response> {
    json_only(headers)?;
    if bytes.len() > MAX_BODY {
        return Err(bad());
    }
    serde_json::from_slice::<T>(bytes).map_err(|_| bad())
}

/// `POST /v1/push/challenge`.
async fn challenge<D, K, KI, C, M>(
    State(s): St<D, K, KI, C, M>,
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
{
    let entry = match realm(&s, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = same_origin(&headers) {
        return r;
    }
    let b: ChallengeBody = match body(&headers, &bytes) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let jar = Jar::of(&headers, peer);
    let same = b.same_device.as_ref().map(|d| SameDeviceWire {
        device_key: &d.device_key,
        signature: &d.signature,
    });
    let reply = s
        .hosted
        .push_challenge(&entry, &jar.browser(), &b.flow, same)
        .await;
    send(reply, &headers).await
}

/// `POST /v1/push/answer`.
async fn answer<D, K, KI, C, M>(
    State(s): St<D, K, KI, C, M>,
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
{
    let entry = match realm(&s, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let b: AnswerBody = match body(&headers, &bytes) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .hosted
        .push_answer(&entry, &jar.browser(), &b.answer, &b.signature)
        .await;
    send(reply, &headers).await
}

/// `GET /v1/approvers`.
async fn list<D, K, KI, C, M>(
    State(s): St<D, K, KI, C, M>,
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
{
    let entry = match realm(&s, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let jar = Jar::of(&headers, peer);
    let reply = s.hosted.approvers(&entry, &jar.browser()).await;
    send(reply, &headers).await
}

/// `POST /v1/approvers`.
async fn register<D, K, KI, C, M>(
    State(s): St<D, K, KI, C, M>,
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
{
    let entry = match realm(&s, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = same_origin(&headers) {
        return r;
    }
    let b: RegisterBody = match body(&headers, &bytes) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .hosted
        .register_approver(&entry, &jar.browser(), &b.name, &b.public_key, &b.proof)
        .await;
    send(reply, &headers).await
}

/// `POST /v1/approvers/{device}/retire`.
async fn retire<D, K, KI, C, M>(
    State(s): St<D, K, KI, C, M>,
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
{
    let entry = match realm(&s, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = same_origin(&headers) {
        return r;
    }
    if !bytes.is_empty()
        && let Err(r) = json_only(&headers)
    {
        return r;
    }
    if bytes.len() > MAX_BODY {
        return bad();
    }
    let device = p.get("device").map(String::as_str).unwrap_or_default();
    if device.is_empty() || device.len() > 64 {
        return bad();
    }
    let jar = Jar::of(&headers, peer);
    let reply = s
        .hosted
        .retire_approver(&entry, &jar.browser(), device)
        .await;
    send(reply, &headers).await
}
