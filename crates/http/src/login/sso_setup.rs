//! The organization SSO setup portal on axum (TN-134, OP-155 m.3 (i)): `GET` and `POST
//! /v1/sso-setup/{link}` at the realm's host and under `/realms/{slug}`, on the login surface's
//! same-origin rule. The link is bound to one browser by its own cookie. Steps take an
//! `Idempotency-Key`.

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::app::sso_setup::SetupStep;
use access_identity_ui::domain::sso_setup::SETUP_COOKIE;
use access_identity_ui::ports::{Clock, Kits, Messages};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};

use super::web::{cookies, json_only, problem, realm, same_origin, send};
use super::{Shared, idempotency};

type St<D, K, KI, C, M> = State<Arc<Shared<D, K, KI, C, M>>>;
type Params = Path<HashMap<String, String>>;

/// Largest request body.
const MAX_BODY: usize = 8 * 1024;

/// Longest link token: 256 bits as base64url.
const MAX_LINK: usize = 64;

/// The setup portal routes.
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
        let path = format!("{prefix}/v1/sso-setup/{{link}}");
        writes = writes.route(&path, post(submit::<D, K, KI, C, M>));
        reads = reads.route(&path, get(read::<D, K, KI, C, M>));
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

fn link_of(p: &HashMap<String, String>) -> Option<&str> {
    p.get("link")
        .map(String::as_str)
        .filter(|l| !l.is_empty() && l.len() <= MAX_LINK)
}

fn bound(headers: &HeaderMap) -> Option<String> {
    cookies(headers)
        .find(|(name, _)| *name == SETUP_COOKIE)
        .map(|(_, v)| v.to_owned())
}

/// `GET /v1/sso-setup/{link}`.
async fn read<D, K, KI, C, M>(
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
    let Some(link) = link_of(&p) else {
        return bad();
    };
    let cookie = bound(&headers);
    let reply = s.hosted.sso_setup(&entry, cookie.as_deref(), link).await;
    send(reply, &headers).await
}

/// `POST /v1/sso-setup/{link}`.
async fn submit<D, K, KI, C, M>(
    State(s): St<D, K, KI, C, M>,
    Path(p): Params,
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
    let Some(link) = link_of(&p) else {
        return bad();
    };
    if bytes.len() > MAX_BODY {
        return bad();
    }
    let Ok(step) = serde_json::from_slice::<SetupStep>(&bytes) else {
        return bad();
    };
    let cookie = bound(&headers);
    let reply = s
        .hosted
        .submit_sso_setup(&entry, cookie.as_deref(), link, step)
        .await;
    send(reply, &headers).await
}
