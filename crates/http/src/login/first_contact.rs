//! First-contact tokens on axum (E58, OP-156 m.3 (z)): the realm's public issuer directory and
//! the signed-in person's blind issuance, at the realm's host and under `/realms/{slug}`, on the
//! login surface's session, cookies and same-origin rule. Issuance takes an `Idempotency-Key`.

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::app::first_contact::TokenRequestBody;
use access_identity_ui::ports::{Clock, Kits, Messages};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};

use super::web::{Jar, json_only, problem, realm, same_origin, send};
use super::{Peer, Shared, idempotency};

type St<D, K, KI, C, M> = State<Arc<Shared<D, K, KI, C, M>>>;
type Params = Path<HashMap<String, String>>;

/// Largest request body: one 256-byte blinded message in base64url and its two numbers.
const MAX_BODY: usize = 1024;

/// The first-contact routes.
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
        writes = writes.route(
            &format!("{prefix}/v1/first-contact/tokens"),
            post(issue::<D, K, KI, C, M>),
        );
        reads = reads.route(
            &format!("{prefix}/v1/first-contact/keys"),
            get(keys::<D, K, KI, C, M>),
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

/// `GET /v1/first-contact/keys`.
async fn keys<D, K, KI, C, M>(
    State(s): St<D, K, KI, C, M>,
    Path(p): Params,
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
    let reply = s.hosted.first_contact_keys(&entry).await;
    send(reply, &headers).await
}

/// `POST /v1/first-contact/tokens`.
async fn issue<D, K, KI, C, M>(
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
    let body = (bytes.len() <= MAX_BODY)
        .then(|| serde_json::from_slice::<TokenRequestBody>(&bytes).ok())
        .flatten();
    let Some(body) = body else {
        return problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request");
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .hosted
        .issue_first_contact_token(&entry, &jar.browser(), &body)
        .await;
    send(reply, &headers).await
}
