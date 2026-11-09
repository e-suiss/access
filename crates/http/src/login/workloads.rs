//! Workload Instances and their runtime attestation on axum (OP-154 m.3 (d), (s)):
//! `POST /v1/workloads/instances` and `POST /v1/workloads/attestations` at the realm's host and
//! under `/realms/{slug}`. A workload is no browser: there is no session or cookie; its key's
//! own signature over `instance_create` is the proof of possession, and an attestation binds
//! only the Instance's own key.

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::app::workloads::{AttestRoots, AttestationBody, WorkloadInstanceBody};
use access_identity_ui::ports::{Clock, Kits, Messages, PartyKeys, WorkloadInstances};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::post;

use super::Shared;
use super::web::{json_only, problem, realm, send};

/// Largest request body.
const MAX_BODY: usize = 16 * 1024;

/// Largest attestation body: a certificate chain.
const MAX_ATTESTATION: usize = 96 * 1024;

struct Svc<D, K, KI, C, M, W> {
    login: Shared<D, K, KI, C, M>,
    workloads: W,
    roots: AttestRoots,
}

type St<D, K, KI, C, M, W> = State<Arc<Svc<D, K, KI, C, M, W>>>;

/// The workload routes of lane L4; attestations verify against `roots`.
pub fn router<D, K, KI, C, M, W>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
    workloads: W,
    roots: AttestRoots,
) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
    W: WorkloadInstances + PartyKeys + 'static,
{
    let svc = Arc::new(Svc {
        login: Shared {
            discovery,
            hosted: hosted.into(),
            assets: None,
        },
        workloads,
        roots,
    });
    let mut r = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        r = r.route(
            &format!("{prefix}/v1/workloads/instances"),
            post(open::<D, K, KI, C, M, W>),
        );
        r = r.route(
            &format!("{prefix}/v1/workloads/attestations"),
            post(attest::<D, K, KI, C, M, W>),
        );
    }
    r.with_state(svc)
}

/// `POST /v1/workloads/instances`.
async fn open<D, K, KI, C, M, W>(
    State(s): St<D, K, KI, C, M, W>,
    Path(p): Path<HashMap<String, String>>,
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
    W: WorkloadInstances + PartyKeys,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = json_only(&headers) {
        return r;
    }
    let bad = || problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request");
    if bytes.len() > MAX_BODY {
        return bad();
    }
    let Ok(body) = serde_json::from_slice::<WorkloadInstanceBody>(&bytes) else {
        return bad();
    };
    let reply = s
        .login
        .hosted
        .open_workload_instance(&entry, &body, &s.workloads)
        .await;
    send(reply, &headers).await
}

/// `POST /v1/workloads/attestations`.
async fn attest<D, K, KI, C, M, W>(
    State(s): St<D, K, KI, C, M, W>,
    Path(p): Path<HashMap<String, String>>,
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
    W: WorkloadInstances + PartyKeys,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = json_only(&headers) {
        return r;
    }
    let bad = || problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request");
    if bytes.len() > MAX_ATTESTATION {
        return bad();
    }
    let Ok(body) = serde_json::from_slice::<AttestationBody>(&bytes) else {
        return bad();
    };
    let reply = s
        .login
        .hosted
        .attest_workload(&entry, &body, (&s.workloads, &s.roots))
        .await;
    send(reply, &headers).await
}
