//! One's cloud key permissions on axum (OP-156 m.3 (w), (g), E59): the `frontend-v1`
//! `/v1/me/cloud-key-permissions` routes at the realm's host and under `/realms/{slug}`. They ride
//! on the session cookie and the same-origin rule; a grant carries the device Instance's own
//! signed Exercise. Writes take an `Idempotency-Key`.

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::app::cloud_key::SignedExercise;
use access_identity_ui::ports::{Clock, Kits, Messages};
use access_internal_api::one::CloudKeyAuthority;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};

use super::web::{Jar, json_only, problem, realm, same_origin, send};
use super::{Peer, Shared, idempotency};

/// Largest request body.
const MAX_BODY: usize = 24 * 1024;

struct Svc<D, K, KI, C, M, A> {
    login: Shared<D, K, KI, C, M>,
    authority: A,
    pep: String,
}

type St<D, K, KI, C, M, A> = State<Arc<Svc<D, K, KI, C, M, A>>>;
type Params = Path<HashMap<String, String>>;

/// The cloud key permission routes of lane Q20; `pep` is the identity plane's PEP name in the
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
    A: CloudKeyAuthority + 'static,
{
    let svc = Arc::new(Svc {
        login: Shared {
            discovery,
            hosted: hosted.into(),
            assets: None,
        },
        authority,
        pep,
    });
    let mut writes = Router::new();
    let mut reads = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        writes = writes
            .route(
                &format!("{prefix}/v1/me/cloud-key-permissions"),
                post(grant::<D, K, KI, C, M, A>),
            )
            .route(
                &format!("{prefix}/v1/me/cloud-key-permissions/{{permission}}/revoke"),
                post(revoke::<D, K, KI, C, M, A>),
            );
        reads = reads.route(
            &format!("{prefix}/v1/me/cloud-key-permissions"),
            get(list::<D, K, KI, C, M, A>),
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
fn body(headers: &HeaderMap, bytes: &Bytes) -> Result<SignedExercise, Response> {
    json_only(headers)?;
    if bytes.len() > MAX_BODY {
        return Err(bad());
    }
    serde_json::from_slice::<SignedExercise>(bytes).map_err(|_| bad())
}

/// `GET /v1/me/cloud-key-permissions`.
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
    A: CloudKeyAuthority,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .cloud_keys(&s.authority, &entry, &jar.browser())
        .await;
    send(reply, &headers).await
}

/// `POST /v1/me/cloud-key-permissions`.
async fn grant<D, K, KI, C, M, A>(
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
    A: CloudKeyAuthority,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = same_origin(&headers) {
        return r;
    }
    let b = match body(&headers, &bytes) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .grant_cloud_key(&s.authority, &s.pep, &entry, &jar.browser(), &b)
        .await;
    send(reply, &headers).await
}

/// `POST /v1/me/cloud-key-permissions/{permission}/revoke`.
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
    A: CloudKeyAuthority,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = same_origin(&headers) {
        return r;
    }
    let permission = p.get("permission").map(String::as_str).unwrap_or_default();
    if permission.is_empty() || permission.len() > 64 {
        return bad();
    }
    let signed = if bytes.is_empty() {
        None
    } else {
        match body(&headers, &bytes) {
            Ok(b) => Some(b),
            Err(r) => return r,
        }
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .revoke_cloud_key(
            &s.authority,
            &s.pep,
            &entry,
            &jar.browser(),
            permission,
            signed.as_ref(),
        )
        .await;
    send(reply, &headers).await
}
