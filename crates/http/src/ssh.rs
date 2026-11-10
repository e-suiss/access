//! The realm's SSH certificate authority on axum (OP-156 m.3 (o), IDP-32): the CA public key a
//! server's `TrustedUserCAKeys` reads, the KRL its `RevokedKeys` reads, and the certificate of an
//! ephemeral key. A certificate request carries the holder's DPoP-bound access token of the
//! realm and its proof; the first call answers a draft `projection.issue` drawn from the
//! holder's `ssh.login` Grant, the second carries that draft and the holder's AIS over it. The
//! routes are at the realm's host and under `/realms/{slug}`.

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use access_identity_oauth::app::oauth::{OAuth, RealmHolder};
use access_identity_oauth::ports::RealmEntry;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::Value;

use crate::oauth::render;
use crate::problem::Code;
use crate::problem::codes::realm as r;

/// Largest certificate request body.
pub const MAX_BODY: usize = 16 * 1024;

/// How long a server may keep `ca.pub` and the KRL before it asks again, seconds.
pub const CACHE_S: u32 = 60;

/// What the CA answers a certificate request.
#[derive(Clone, Debug, PartialEq)]
pub enum SshReply {
    /// `200` with this body: a draft, or the certificate.
    Ok(Value),
    /// A refusal; nothing was issued.
    Refused(&'static Code),
    /// The decision was not ALLOW: `deny` or `require_action`.
    NotAllowed(&'static str),
    /// A port could not answer; `503`.
    Unavailable,
}

/// The realm's SSH certificate authority behind these routes (access-server).
pub trait SshFront: Send + Sync + 'static {
    /// The CA keys servers trust now, one `authorized_keys` line each; `None` while the CA is
    /// off.
    fn ca_pub(&self, realm: &RealmEntry)
    -> impl Future<Output = Result<Option<String>, ()>> + Send;

    /// The realm's KRL.
    fn krl(&self, realm: &RealmEntry) -> impl Future<Output = Result<Vec<u8>, ()>> + Send;

    /// A draft or a certificate for `holder`.
    fn certificate(
        &self,
        realm: &RealmEntry,
        holder: RealmHolder,
        body: Value,
    ) -> impl Future<Output = SshReply> + Send;
}

struct Svc<E: access_identity_oauth::app::oauth::Env, S> {
    oauth: Arc<OAuth<E>>,
    front: Arc<S>,
}

type St<E, S> = State<Arc<Svc<E, S>>>;
type Params0 = Path<HashMap<String, String>>;

/// The CA routes over the realm's authorization server (its tokens) and `front`.
pub fn router<E, S>(oauth: Arc<OAuth<E>>, front: impl Into<Arc<S>>) -> Router
where
    E: access_identity_oauth::app::oauth::Env + 'static,
    S: SshFront,
{
    let svc = Arc::new(Svc {
        oauth,
        front: front.into(),
    });
    let mut out = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        out = out
            .route(&format!("{prefix}/ssh/ca.pub"), get(ca_pub::<E, S>))
            .route(&format!("{prefix}/ssh/krl"), get(krl::<E, S>))
            .route(
                &format!("{prefix}/ssh/certificate"),
                post(certificate::<E, S>),
            );
    }
    out.with_state(svc)
}

fn authority<'a>(uri: &'a Uri, headers: &'a HeaderMap) -> &'a str {
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str))
        .unwrap_or_default()
}

fn unavailable() -> Response {
    crate::problem::codes::UNAVAILABLE.problem().into_response()
}

async fn realm_of<E: access_identity_oauth::app::oauth::Env, S>(
    s: &Svc<E, S>,
    params: &HashMap<String, String>,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<RealmEntry, Response> {
    match s
        .oauth
        .realm(
            authority(uri, headers),
            params.get("slug").map(String::as_str),
        )
        .await
    {
        Ok(Some(realm)) => Ok(realm),
        Ok(None) => Err(crate::not_found_problem().into_response()),
        Err(_) => Err(unavailable()),
    }
}

fn cached(mut r: Response, content_type: &'static str) -> Response {
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(v) = HeaderValue::from_str(&format!("public, max-age={CACHE_S}")) {
        h.insert(header::CACHE_CONTROL, v);
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

async fn ca_pub<E: access_identity_oauth::app::oauth::Env, S: SshFront>(
    State(s): St<E, S>,
    Path(p): Params0,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let realm = match realm_of(&s, &p, &uri, &headers).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    match s.front.ca_pub(&realm).await {
        Ok(Some(lines)) => cached(
            (StatusCode::OK, lines).into_response(),
            "text/plain; charset=utf-8",
        ),
        Ok(None) => r::SSH_CA_OFF.problem().into_response(),
        Err(()) => unavailable(),
    }
}

async fn krl<E: access_identity_oauth::app::oauth::Env, S: SshFront>(
    State(s): St<E, S>,
    Path(p): Params0,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let realm = match realm_of(&s, &p, &uri, &headers).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    match s.front.krl(&realm).await {
        Ok(bytes) => cached(
            (StatusCode::OK, bytes).into_response(),
            "application/octet-stream",
        ),
        Err(()) => unavailable(),
    }
}

async fn certificate<E: access_identity_oauth::app::oauth::Env, S: SshFront>(
    State(s): St<E, S>,
    Path(p): Params0,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let realm = match realm_of(&s, &p, &uri, &headers).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| c.starts_with("application/json"));
    if !json || bytes.len() > MAX_BODY {
        return r::INVALID_SSH_REQUEST.problem().into_response();
    }
    let authorization: Vec<&str> = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let [authorization] = authorization.as_slice() else {
        return render(access_identity_oauth::app::oauth::Reply::Json {
            status: 401,
            body: String::from(r#"{"error":"invalid_token"}"#),
            dpop_nonce: None,
            challenge: Some(String::from(r#"DPoP error="invalid_token""#)),
        });
    };
    let proofs: Vec<&str> = headers
        .get_all("dpop")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let htu = realm.issuer.endpoint("/ssh/certificate");
    let holder = match s
        .oauth
        .realm_holder(&realm, "POST", &htu, Some(authorization), &proofs)
        .await
    {
        Ok(Ok(h)) => h,
        Ok(Err(reply)) => return render(reply),
        Err(_) => return unavailable(),
    };
    let Ok(body) = serde_json::from_slice::<Value>(&bytes) else {
        return r::INVALID_SSH_REQUEST.problem().into_response();
    };
    let mut out = match s.front.certificate(&realm, holder, body).await {
        SshReply::Ok(v) => (StatusCode::OK, axum::Json(v)).into_response(),
        SshReply::Refused(code) => code.problem().into_response(),
        SshReply::NotAllowed(outcome) => {
            let mut p = r::SSH_DENIED.problem().into_response();
            p.headers_mut()
                .insert("access-decision", HeaderValue::from_static(outcome));
            p
        }
        SshReply::Unavailable => unavailable(),
    };
    out.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    out
}
