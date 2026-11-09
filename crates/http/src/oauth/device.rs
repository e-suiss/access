//! The device authorization grant's verification routes (RFC 8628 §3.3, OP-154 m.3 (p)): the
//! page reads what a user code asks for and the CSRF token, then approves or declines it, the
//! person signed in. Same-origin JSON only, nothing framed, no cookie set; every wrong code
//! answers alike.

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::sync::Arc;

use access_identity_oauth::app::oauth::{DeviceRefused, Env, OAuth, device_csrf};
use axum::Extension;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::post;
use serde::Deserialize;
use serde_json::json;

use super::approval::{CSRF_HEADER, json_reply, realm_of, refused, same_origin_json};
use super::session_cookie;
use crate::login::Peer;

type Shared<E> = State<Arc<OAuth<E>>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    user_code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decide {
    user_code: String,
    approve: bool,
}

/// The verification routes, at the host root and under `/realms/{slug}`.
pub(super) fn routes<E: Env>() -> Router<Arc<OAuth<E>>> {
    let mut r = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        r = r
            .route(&format!("{prefix}/v1/device/preview"), post(preview::<E>))
            .route(&format!("{prefix}/v1/device/approval"), post(decide::<E>));
    }
    r
}

fn refusal(r: DeviceRefused) -> Response {
    match r {
        DeviceRefused::SignIn => refused(
            StatusCode::UNAUTHORIZED,
            "session-required",
            "Sign in first",
        ),
        // OP-154 m.3 (p), CR-39
        DeviceRefused::Wait => refused(
            StatusCode::TOO_MANY_REQUESTS,
            "device-code-wait",
            "Too many codes that didn't work; try again later",
        ),
        DeviceRefused::NoCode => refused(
            StatusCode::NOT_FOUND,
            "device-code-invalid",
            "This code didn't work",
        ),
        DeviceRefused::Off => refused(StatusCode::NOT_FOUND, "not-found", "Not Found"),
    }
}

fn code_ok(c: &str) -> bool {
    !c.is_empty() && c.len() <= 32 && !c.chars().any(char::is_control)
}

/// `POST /v1/device/preview`.
async fn preview<E: Env>(
    State(s): Shared<E>,
    p: Option<Path<String>>,
    peer: Option<Extension<Peer>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = same_origin_json(&headers) {
        return r;
    }
    let realm = match realm_of(&s, &uri, &headers, p.map(|Path(x)| x).as_deref()).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Ok(ask) = serde_json::from_slice::<Preview>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request");
    };
    if !code_ok(&ask.user_code) {
        return refusal(DeviceRefused::NoCode);
    }
    let cookie = session_cookie(&headers);
    let ip = peer.map(|Extension(Peer(ip))| ip);
    match s
        .device_preview(&realm, cookie.as_deref(), &ask.user_code, ip)
        .await
    {
        Ok(Ok(v)) => {
            let csrf = cookie
                .as_deref()
                .and_then(|c| device_csrf(c, &ask.user_code))
                .unwrap_or_default();
            json_reply(
                StatusCode::OK,
                &json!({
                    "client": v.client,
                    "scopes": v.scopes,
                    "ip_prefix": v.ip_prefix,
                    "country": v.country,
                    "csrf": csrf,
                }),
            )
        }
        Ok(Err(r)) => refusal(r),
        Err(_) => super::approval::unavailable(),
    }
}

/// `POST /v1/device/approval`.
async fn decide<E: Env>(
    State(s): Shared<E>,
    p: Option<Path<String>>,
    peer: Option<Extension<Peer>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = same_origin_json(&headers) {
        return r;
    }
    let realm = match realm_of(&s, &uri, &headers, p.map(|Path(x)| x).as_deref()).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Ok(d) = serde_json::from_slice::<Decide>(&body) else {
        return refused(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request");
    };
    if !code_ok(&d.user_code) {
        return refusal(DeviceRefused::NoCode);
    }
    let cookie = session_cookie(&headers);
    let sent = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok());
    let expected = cookie.as_deref().and_then(|c| device_csrf(c, &d.user_code));
    if sent.is_none() || sent != expected.as_deref() {
        return refused(
            StatusCode::FORBIDDEN,
            "csrf-mismatch",
            "The page is out of date",
        );
    }
    let ip = peer.map(|Extension(Peer(ip))| ip);
    match s
        .device_decide(&realm, cookie.as_deref(), &d.user_code, d.approve, ip)
        .await
    {
        Ok(Ok(())) => json_reply(
            StatusCode::OK,
            &json!({ "decision": if d.approve { "approved" } else { "denied" } }),
        ),
        Ok(Err(r)) => refusal(r),
        Err(_) => super::approval::unavailable(),
    }
}
