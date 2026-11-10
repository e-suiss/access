//! Directory app passwords on axum (S11, §10.6.3, OP-155 m.3 (n)): the `frontend-v1` routes of
//! the LDAP credential class, at the realm's host and under `/realms/{slug}`, on the login
//! surface's session, cookies and same-origin rule. Writes take an `Idempotency-Key`.

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
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

/// The LDAP credential routes.
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
                &format!("{prefix}/v1/account/ldap-credentials"),
                post(create::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/ldap-credentials/{{credential}}/revoke"),
                post(revoke::<D, K, KI, C, M>),
            );
        reads = reads.route(
            &format!("{prefix}/v1/account/ldap-credentials"),
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
struct CreateBody {
    application: String,
}

/// `GET /v1/account/ldap-credentials`.
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
    let reply = s.hosted.ldap_credentials(&entry, &jar.browser()).await;
    send(reply, &headers).await
}

/// `POST /v1/account/ldap-credentials`.
async fn create<D, K, KI, C, M>(
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
    if let Err(r) = json_only(&headers) {
        return r;
    }
    if bytes.len() > MAX_BODY {
        return bad();
    }
    let Ok(body) = serde_json::from_slice::<CreateBody>(&bytes) else {
        return bad();
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .hosted
        .create_ldap_credential(&entry, &jar.browser(), &body.application)
        .await;
    send(reply, &headers).await
}

/// `POST /v1/account/ldap-credentials/{credential}/revoke`.
async fn revoke<D, K, KI, C, M>(
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
    let credential = p.get("credential").map(String::as_str).unwrap_or_default();
    if credential.is_empty() || credential.len() > 64 {
        return bad();
    }
    let jar = Jar::of(&headers, peer);
    let reply = s
        .hosted
        .revoke_ldap_credential(&entry, &jar.browser(), credential)
        .await;
    send(reply, &headers).await
}
