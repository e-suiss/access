//! Payment-class authentication on axum (OP-156 m.3 (e), (f)): the SMS activation code and the
//! activation of an approver as the app-controlled factor, at the realm's host and under
//! `/realms/{slug}`. Both ride on the login surface's cookies and same-origin rule and take an
//! `Idempotency-Key`.

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::app::payment::{ActivationBody, AppFactorRoots};
use access_identity_ui::ports::{Clock, Kits, Messages};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::post;
use axum::{Extension, Router};

use super::web::{Jar, json_only, problem, realm, same_origin, send};
use super::{Peer, Shared, idempotency};

type Params = Path<HashMap<String, String>>;

/// Largest request body: an attestation chain of up to eight certificates.
const MAX_BODY: usize = 96 * 1024;

struct PaymentState<D, K, KI, C, M> {
    shared: Shared<D, K, KI, C, M>,
    roots: AppFactorRoots,
}

type St<D, K, KI, C, M> = State<Arc<PaymentState<D, K, KI, C, M>>>;

/// The SMS activation and approver activation routes.
pub fn router<D, K, KI, C, M>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
    roots: AppFactorRoots,
) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
{
    let state = Arc::new(PaymentState {
        shared: Shared {
            discovery,
            hosted: hosted.into(),
            assets: None,
        },
        roots,
    });
    let mut writes = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        writes = writes
            .route(
                &format!("{prefix}/v1/sms/activation"),
                post(activation::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/approvers/{{device}}/activate"),
                post(activate::<D, K, KI, C, M>),
            );
    }
    let cache = Arc::new(idempotency::Cache::default());
    writes
        .route_layer(axum::middleware::from_fn_with_state(
            cache,
            idempotency::layer,
        ))
        .with_state(state)
}

fn bad() -> Response {
    problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request")
}

/// `POST /v1/sms/activation`.
async fn activation<D, K, KI, C, M>(
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
    let entry = match realm(&s.shared, &p, &uri, &headers).await {
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
    if bytes.len() > 64 {
        return bad();
    }
    let jar = Jar::of(&headers, peer);
    let reply = s.shared.hosted.sms_activation(&entry, &jar.browser()).await;
    send(reply, &headers).await
}

/// `POST /v1/approvers/{device}/activate`.
async fn activate<D, K, KI, C, M>(
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
    let entry = match realm(&s.shared, &p, &uri, &headers).await {
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
    let Ok(body) = serde_json::from_slice::<ActivationBody>(&bytes) else {
        return bad();
    };
    let device = p.get("device").map(String::as_str).unwrap_or_default();
    if device.is_empty() || device.len() > 64 {
        return bad();
    }
    let jar = Jar::of(&headers, peer);
    let reply = s
        .shared
        .hosted
        .activate_approver(&entry, &jar.browser(), device, &body, &s.roots)
        .await;
    send(reply, &headers).await
}
