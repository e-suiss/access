//! The realm's Linux client routes on axum (OP-156 m.3 (p), IDP-32). Only a live Linux host of
//! the realm calls them, named by the client certificate the public listener verified
//! (`x5t#S256`, B22):
//! - `POST /linux/v1/nss` answers the host's NSS snapshot: who may sign in to it, from the
//!   `ssh.login` Grants on its server group, and how long it may answer offline;
//! - `POST /linux/v1/auth` decides a console sign-in for the person whose DPoP-bound access
//!   token the host polled for;
//! - `POST /linux/v1/sudo` decides a `sudo` step-up, CT2 by default.
//!
//! The routes are at the realm's host and under `/realms/{slug}`.

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use access_identity_oauth::app::oauth::{OAuth, RealmHolder};
use access_identity_oauth::ports::RealmEntry;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Router};
use serde_json::Value;

use crate::adp::adapters::Pep;
use crate::oauth::render;
use crate::problem::Code;
use crate::problem::codes::realm as r;

/// Largest request body.
pub const MAX_BODY: usize = 4 * 1024;

/// What the realm answers a Linux host.
#[derive(Clone, Debug, PartialEq)]
pub enum LinuxReply {
    /// `200` with this body.
    Ok(Value),
    /// A refusal.
    Refused(&'static Code),
    /// A port could not answer; `503`.
    Unavailable,
}

/// The realm's Linux client behind these routes (access-server).
pub trait LinuxFront: Send + Sync + 'static {
    /// The NSS snapshot of the host with client certificate `host`.
    fn nss(&self, realm: &RealmEntry, host: &str) -> impl Future<Output = LinuxReply> + Send;

    /// A console sign-in on `host` for `holder`.
    fn sign_in(
        &self,
        realm: &RealmEntry,
        host: &str,
        holder: RealmHolder,
        body: Value,
    ) -> impl Future<Output = LinuxReply> + Send;

    /// A `sudo` step-up on `host` for `holder`.
    fn sudo(
        &self,
        realm: &RealmEntry,
        host: &str,
        holder: RealmHolder,
        body: Value,
    ) -> impl Future<Output = LinuxReply> + Send;
}

struct Svc<E: access_identity_oauth::app::oauth::Env, S> {
    oauth: Arc<OAuth<E>>,
    front: Arc<S>,
}

type St<E, S> = State<Arc<Svc<E, S>>>;
type Params0 = Path<HashMap<String, String>>;

/// The Linux routes over the realm's authorization server (its tokens) and `front`.
pub fn router<E, S>(oauth: Arc<OAuth<E>>, front: impl Into<Arc<S>>) -> Router
where
    E: access_identity_oauth::app::oauth::Env + 'static,
    S: LinuxFront,
{
    let svc = Arc::new(Svc {
        oauth,
        front: front.into(),
    });
    let mut out = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        out = out
            .route(&format!("{prefix}/linux/v1/nss"), post(nss::<E, S>))
            .route(&format!("{prefix}/linux/v1/auth"), post(auth::<E, S>))
            .route(&format!("{prefix}/linux/v1/sudo"), post(sudo::<E, S>));
    }
    out.with_state(svc)
}

fn unavailable() -> Response {
    crate::problem::codes::UNAVAILABLE.problem().into_response()
}

fn reply(r: LinuxReply) -> Response {
    let mut out = match r {
        LinuxReply::Ok(v) => (StatusCode::OK, axum::Json(v)).into_response(),
        LinuxReply::Refused(code) => code.problem().into_response(),
        LinuxReply::Unavailable => unavailable(),
    };
    out.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    out
}

/// The realm and the host's certificate name, or the refusal.
async fn host_of<E: access_identity_oauth::app::oauth::Env, S>(
    s: &Svc<E, S>,
    params: &HashMap<String, String>,
    uri: &Uri,
    headers: &HeaderMap,
    pep: Option<Extension<Pep>>,
    bytes: &Bytes,
) -> Result<(RealmEntry, String, Value), Response> {
    let authority = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str))
        .unwrap_or_default();
    let realm = match s
        .oauth
        .realm(authority, params.get("slug").map(String::as_str))
        .await
    {
        Ok(Some(realm)) => realm,
        Ok(None) => return Err(crate::not_found_problem().into_response()),
        Err(_) => return Err(unavailable()),
    };
    let Some(Extension(Pep(host))) = pep else {
        return Err(reply(LinuxReply::Refused(&r::LINUX_HOST_UNKNOWN)));
    };
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| c.starts_with("application/json"));
    let body = serde_json::from_slice::<Value>(bytes).ok();
    match body {
        Some(b @ Value::Object(_)) if json && bytes.len() <= MAX_BODY => Ok((realm, host, b)),
        _ => Err(reply(LinuxReply::Refused(&r::INVALID_LINUX_REQUEST))),
    }
}

async fn holder<E: access_identity_oauth::app::oauth::Env, S>(
    s: &Svc<E, S>,
    realm: &RealmEntry,
    headers: &HeaderMap,
    path: &str,
) -> Result<RealmHolder, Response> {
    let authorization: Vec<&str> = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let [authorization] = authorization.as_slice() else {
        return Err(render(access_identity_oauth::app::oauth::Reply::Json {
            status: 401,
            body: String::from(r#"{"error":"invalid_token"}"#),
            dpop_nonce: None,
            challenge: Some(String::from(r#"DPoP error="invalid_token""#)),
        }));
    };
    let proofs: Vec<&str> = headers
        .get_all("dpop")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let htu = realm.issuer.endpoint(path);
    match s
        .oauth
        .realm_holder(realm, "POST", &htu, Some(authorization), &proofs)
        .await
    {
        Ok(Ok(h)) => Ok(h),
        Ok(Err(reply)) => Err(render(reply)),
        Err(_) => Err(unavailable()),
    }
}

async fn nss<E: access_identity_oauth::app::oauth::Env, S: LinuxFront>(
    State(s): St<E, S>,
    Path(p): Params0,
    pep: Option<Extension<Pep>>,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let (realm, host, body) = match host_of(&s, &p, &uri, &headers, pep, &bytes).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    if body.as_object().is_some_and(|m| !m.is_empty()) {
        return reply(LinuxReply::Refused(&r::INVALID_LINUX_REQUEST));
    }
    reply(s.front.nss(&realm, &host).await)
}

async fn auth<E: access_identity_oauth::app::oauth::Env, S: LinuxFront>(
    State(s): St<E, S>,
    Path(p): Params0,
    pep: Option<Extension<Pep>>,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let (realm, host, body) = match host_of(&s, &p, &uri, &headers, pep, &bytes).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    let who = match holder(&s, &realm, &headers, "/linux/v1/auth").await {
        Ok(h) => h,
        Err(e) => return e,
    };
    reply(s.front.sign_in(&realm, &host, who, body).await)
}

async fn sudo<E: access_identity_oauth::app::oauth::Env, S: LinuxFront>(
    State(s): St<E, S>,
    Path(p): Params0,
    pep: Option<Extension<Pep>>,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let (realm, host, body) = match host_of(&s, &p, &uri, &headers, pep, &bytes).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    let who = match holder(&s, &realm, &headers, "/linux/v1/sudo").await {
        Ok(h) => h,
        Err(e) => return e,
    };
    reply(s.front.sudo(&realm, &host, who, body).await)
}
