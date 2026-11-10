//! The Approval Surface's CIBA routes (OP-155 m.3 (l), §9.14.5 k.2): the page reads what a
//! backchannel request asks and the CSRF token, runs the hosted approval with the person's device
//! and passkey, then answers the request with the approval it pushed, or declines. Same-origin
//! JSON only, nothing framed, no cookie set; every unknown request answers alike.

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::sync::Arc;

use access_identity_oauth::app::oauth::{CibaRefused, Env, OAuth, ciba_csrf};
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

type Shared<E> = State<Arc<OAuth<E>>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    request: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decide {
    request: String,
    approve: bool,
    #[serde(default)]
    approval: Option<String>,
}

/// The CIBA routes, at the host root and under `/realms/{slug}`.
pub(super) fn routes<E: Env>() -> Router<Arc<OAuth<E>>> {
    let mut r = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        r = r
            .route(&format!("{prefix}/v1/ciba/preview"), post(preview::<E>))
            .route(&format!("{prefix}/v1/ciba/approval"), post(decide::<E>));
    }
    r
}

fn refusal(r: CibaRefused) -> Response {
    match r {
        CibaRefused::SignIn => refused(
            StatusCode::UNAUTHORIZED,
            "session-required",
            "Sign in first",
        ),
        CibaRefused::NoRequest => refused(
            StatusCode::NOT_FOUND,
            "ciba-request-unknown",
            "This request is not waiting for you",
        ),
        CibaRefused::Expired => refused(
            StatusCode::GONE,
            "ciba-request-expired",
            "This request has expired",
        ),
        // IDI-9, §9.14.5 k.2
        CibaRefused::NotApproved => refused(
            StatusCode::CONFLICT,
            "ciba-not-approved",
            "Nothing was approved for this request",
        ),
        CibaRefused::Off => refused(StatusCode::NOT_FOUND, "not-found", "Not Found"),
    }
}

fn text_ok(t: &str, max: usize) -> bool {
    !t.is_empty() && t.len() <= max && !t.chars().any(char::is_control)
}

/// `POST /v1/ciba/preview`.
async fn preview<E: Env>(
    State(s): Shared<E>,
    p: Option<Path<String>>,
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
    if !text_ok(&ask.request, 64) {
        return refusal(CibaRefused::NoRequest);
    }
    let cookie = session_cookie(&headers);
    match s
        .ciba_preview(&realm, cookie.as_deref(), &ask.request)
        .await
    {
        Ok(Ok(v)) => {
            let csrf = cookie
                .as_deref()
                .and_then(|c| ciba_csrf(c, &ask.request))
                .unwrap_or_default();
            json_reply(
                StatusCode::OK,
                &json!({
                    "client": v.client,
                    "binding_message": v.binding_message,
                    "scopes": v.scopes,
                    "expires_at": v.expires_at_ms,
                    "request": v.request,
                    "redirect_uri": v.redirect_uri,
                    "csrf": csrf,
                }),
            )
        }
        Ok(Err(r)) => refusal(r),
        Err(_) => super::approval::unavailable(),
    }
}

/// `POST /v1/ciba/approval`.
async fn decide<E: Env>(
    State(s): Shared<E>,
    p: Option<Path<String>>,
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
    let approval = match (d.approve, d.approval.as_deref()) {
        (true, Some(a)) if text_ok(a, 512) => Some(a),
        (false, None) => None,
        _ => return refused(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request"),
    };
    if !text_ok(&d.request, 64) {
        return refusal(CibaRefused::NoRequest);
    }
    let cookie = session_cookie(&headers);
    let sent = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok());
    let expected = cookie.as_deref().and_then(|c| ciba_csrf(c, &d.request));
    if sent.is_none() || sent != expected.as_deref() {
        return refused(
            StatusCode::FORBIDDEN,
            "csrf-mismatch",
            "The page is out of date",
        );
    }
    match s
        .ciba_decide(&realm, cookie.as_deref(), &d.request, approval)
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
