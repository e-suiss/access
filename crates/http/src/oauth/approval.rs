//! The hosted consent of a client the realm did not register (§11.6, P58, EI-18, OP-154 m.3 (k)):
//! the consent page reads what it shows and the `grant.issue` it has the person's device Instance
//! sign, then names the allowed Exercise to keep the consent record, or declines. Same-origin
//! JSON only, every write with the session-bound CSRF token, nothing framed, no cookie set
//! (§11.4.5 #6, #27, #28).

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::sync::Arc;

use access_identity_oauth::app::oauth::{
    ApprovalDraft, ApprovalView, Env, NotApproved, OAuth, Realm, consent_csrf,
};
use access_kernel::json::{b64url_decode, b64url_encode};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{authority, session_cookie};
use crate::Problem;

/// The CSRF header of the consent writes.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Longest `return_to`.
const MAX_RETURN_TO: usize = 2048;

type Shared<E> = State<Arc<OAuth<E>>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ask {
    return_to: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approve {
    return_to: String,
    domain: String,
    exercise: String,
}

/// The consent routes, at the host root and under `/realms/{slug}`.
pub(super) fn routes<E: Env>() -> Router<Arc<OAuth<E>>> {
    let mut r = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        r = r
            .route(
                &format!("{prefix}/v1/login/approval/preview"),
                post(preview::<E>),
            )
            .route(&format!("{prefix}/v1/login/approval"), post(approve::<E>))
            .route(
                &format!("{prefix}/v1/login/approval/decline"),
                post(decline::<E>),
            );
    }
    r
}

fn framed_never(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // §11.4.5 Ek B 4538
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

pub(super) fn refused(status: StatusCode, code: &'static str, title: &'static str) -> Response {
    framed_never(Problem::new(status, code, title).into_response())
}

fn bad() -> Response {
    refused(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request")
}

pub(super) fn json_reply(status: StatusCode, body: &Value) -> Response {
    framed_never(
        (
            status,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            body.to_string(),
        )
            .into_response(),
    )
}

/// §11.4.5 #28: only this origin's own page, as JSON.
pub(super) fn same_origin_json(headers: &HeaderMap) -> Result<(), Response> {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let cross = || {
        refused(
            StatusCode::FORBIDDEN,
            "cross-site",
            "The request did not come from this site",
        )
    };
    let origin_ok = headers.get(header::ORIGIN).is_none_or(|o| {
        o.to_str()
            .ok()
            .and_then(|o| o.strip_prefix("https://"))
            .is_some_and(|o| !o.is_empty() && o.eq_ignore_ascii_case(host))
    });
    let site_ok = headers
        .get("sec-fetch-site")
        .is_none_or(|s| s.to_str().is_ok_and(|s| s == "same-origin"));
    if !origin_ok || !site_ok {
        return Err(cross());
    }
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"));
    if json {
        Ok(())
    } else {
        Err(refused(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "json-required",
            "Unsupported Media Type",
        ))
    }
}

/// The session's CSRF token for `return_to` must come back in [`CSRF_HEADER`] (§11.4.5 #28).
fn csrf_ok(headers: &HeaderMap, cookie: Option<&str>, return_to: &str) -> bool {
    let sent = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok());
    match (sent, cookie.and_then(|c| consent_csrf(c, return_to))) {
        (Some(a), Some(b)) => {
            a.len() == b.len()
                && a.bytes()
                    .zip(b.bytes())
                    .fold(0_u8, |acc, (x, y)| acc | (x ^ y))
                    == 0
        }
        _ => false,
    }
}

pub(super) async fn realm_of<E: Env>(
    s: &OAuth<E>,
    uri: &Uri,
    headers: &HeaderMap,
    slug: Option<&str>,
) -> Result<Realm, Response> {
    match s.realm(authority(uri, headers), slug).await {
        Ok(Some(r)) => Ok(r),
        Ok(None) => Err(framed_never(crate::not_found_problem().into_response())),
        Err(_) => Err(unavailable()),
    }
}

pub(super) fn unavailable() -> Response {
    let mut r = refused(
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "Service Unavailable",
    );
    r.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from(access_identity_oauth::app::oauth::RETRY_AFTER_S),
    );
    r
}

fn not_approved(n: NotApproved) -> Response {
    match n {
        NotApproved::SignIn => refused(
            StatusCode::UNAUTHORIZED,
            "session-required",
            "Sign in first",
        ),
        NotApproved::NoRequest => refused(
            StatusCode::NOT_FOUND,
            "no-such-app",
            "That app isn't asking for anything here",
        ),
        NotApproved::NoGrant => refused(
            StatusCode::FORBIDDEN,
            "consent-grant-required",
            "Approve with this device first",
        ),
    }
}

fn draft_json(d: &ApprovalDraft) -> Value {
    let envelope = access_kernel::codec::Canonical::to_bytes(&d.envelope).unwrap_or_default();
    json!({
        "domain": b64url_encode(&d.domain),
        "intent": crate::console::drafts::wire(&d.envelope),
        "envelope": b64url_encode(&envelope),
        "payload": b64url_encode(&d.payload),
        "basis": { "holding": {
            "grant": b64url_encode(&d.basis.grant.0),
            "holder": b64url_encode(&d.basis.holder.0),
            "since": d.basis.since,
        } },
    })
}

fn view_json(v: &ApprovalView, csrf: &str) -> Value {
    json!({
        "client_id": v.client_id,
        "client_host": v.client_host,
        "client_says": v.client_says,
        "logo": v.logo,
        "redirect_hosts": v.redirect_hosts,
        "loopback_only": v.loopback_only,
        "new_app": v.new_app,
        "visual_changed": v.visual_changed,
        "resource": v.resource,
        "scopes": v.scopes,
        "csrf": csrf,
        "draft": v.draft.as_ref().map(draft_json),
    })
}

fn bounded(text: &str) -> Result<&str, Response> {
    if text.is_empty() || text.len() > MAX_RETURN_TO || text.chars().any(char::is_control) {
        Err(bad())
    } else {
        Ok(text)
    }
}

fn slug_of(p: Option<Path<String>>) -> Option<String> {
    p.map(|Path(s)| s)
}

/// `POST /v1/login/approval/preview`: what the consent screen shows, the draft to sign and the
/// CSRF token, for the signed-in person (§11.6, AS-M14).
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
    let realm = match realm_of(&s, &uri, &headers, slug_of(p).as_deref()).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Ok(ask) = serde_json::from_slice::<Ask>(&body) else {
        return bad();
    };
    let return_to = match bounded(&ask.return_to) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let cookie = session_cookie(&headers);
    match s.approval_view(&realm, cookie.as_deref(), return_to).await {
        Ok(Ok(v)) => {
            let Some(csrf) = cookie.as_deref().and_then(|c| consent_csrf(c, return_to)) else {
                return not_approved(NotApproved::SignIn);
            };
            json_reply(StatusCode::OK, &view_json(&v, &csrf))
        }
        Ok(Err(n)) => not_approved(n),
        Err(_) => unavailable(),
    }
}

/// `POST /v1/login/approval`: keeps the consent record once the named Exercise is the person's
/// own allowed `grant.issue` (EI-18), and sends the browser back to the request.
async fn approve<E: Env>(
    State(s): Shared<E>,
    p: Option<Path<String>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = same_origin_json(&headers) {
        return r;
    }
    let realm = match realm_of(&s, &uri, &headers, slug_of(p).as_deref()).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Ok(a) = serde_json::from_slice::<Approve>(&body) else {
        return bad();
    };
    let return_to = match bounded(&a.return_to) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let decode = |t: &str| {
        b64url_decode(t)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
    };
    let (Some(domain), Some(exercise)) = (decode(&a.domain), decode(&a.exercise)) else {
        return bad();
    };
    let cookie = session_cookie(&headers);
    if !csrf_ok(&headers, cookie.as_deref(), return_to) {
        return refused(
            StatusCode::FORBIDDEN,
            "csrf-mismatch",
            "The page is out of date",
        );
    }
    match s
        .approve(&realm, cookie.as_deref(), return_to, domain, exercise)
        .await
    {
        Ok(Ok(to)) => json_reply(StatusCode::OK, &json!({ "redirect_to": to })),
        Ok(Err(n)) => not_approved(n),
        Err(_) => unavailable(),
    }
}

/// `POST /v1/login/approval/decline` (X-L8): the request goes back with `access_denied`.
async fn decline<E: Env>(
    State(s): Shared<E>,
    p: Option<Path<String>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = same_origin_json(&headers) {
        return r;
    }
    let realm = match realm_of(&s, &uri, &headers, slug_of(p).as_deref()).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Ok(ask) = serde_json::from_slice::<Ask>(&body) else {
        return bad();
    };
    let return_to = match bounded(&ask.return_to) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let cookie = session_cookie(&headers);
    if !csrf_ok(&headers, cookie.as_deref(), return_to) {
        return refused(
            StatusCode::FORBIDDEN,
            "csrf-mismatch",
            "The page is out of date",
        );
    }
    match s
        .decline_approval(&realm, cookie.as_deref(), return_to)
        .await
    {
        Ok(Ok(to)) => json_reply(StatusCode::OK, &json!({ "redirect_to": to })),
        Ok(Err(n)) => not_approved(n),
        Err(_) => unavailable(),
    }
}
