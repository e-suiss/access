//! The login surface on axum: realm selection by `Host`, cookies, JSON bodies and replies.

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use access_identity_oauth::ports::{Directory, Keys, RealmEntry};
use access_identity_ui::app::{
    Body, Browser, FLOW_COOKIE, LOGIN_COOKIE, MARKER_COOKIE, Reply, SESSION_COOKIE,
};
use access_identity_ui::domain::submission::Submission;
use access_identity_ui::ports::{Clock, Kits, Messages};
use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::{Peer, Shared, assets};
use crate::Problem;

type St<D, K, KI, C, M> = State<Arc<Shared<D, K, KI, C, M>>>;
type Params = Path<HashMap<String, String>>;

const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Longest request id carried into the audit trail.
const MAX_REQUEST_ID: usize = 64;

/// Longest short text in an account request (a label, a name).
const MAX_TEXT: usize = 64;

/// The cookies of a request, by name; the first of a repeated name wins.
pub(crate) fn cookies(headers: &HeaderMap) -> impl Iterator<Item = (&str, &str)> {
    headers
        .get_all(header::COOKIE)
        .into_iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| {
            let (n, v) = pair.trim().split_once('=')?;
            Some((n.trim(), v.trim()))
        })
}

pub(crate) struct Jar {
    flow: Option<String>,
    session: Option<String>,
    marker: Option<String>,
    login: Option<String>,
    ip: IpAddr,
    correlation: String,
}

impl Jar {
    pub(crate) fn of(headers: &HeaderMap, peer: Option<Extension<Peer>>) -> Self {
        let mut jar = Self {
            flow: None,
            session: None,
            marker: None,
            login: None,
            ip: peer.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |Extension(Peer(ip))| ip),
            correlation: headers
                .get(&REQUEST_ID)
                .and_then(|v| v.to_str().ok())
                .filter(|v| v.len() <= MAX_REQUEST_ID)
                .unwrap_or("-")
                .to_owned(),
        };
        let mut bound: Option<String> = None;
        for (name, value) in cookies(headers) {
            let slot = match name {
                FLOW_COOKIE => &mut jar.flow,
                SESSION_COOKIE => &mut jar.session,
                MARKER_COOKIE => &mut jar.marker,
                LOGIN_COOKIE => &mut jar.login,
                access_identity_session::domain::dbsc::BOUND_COOKIE => &mut bound,
                _ => continue,
            };
            if slot.is_none() {
                *slot = Some(value.to_owned());
            }
        }
        // TN-33
        if let (Some(s), Some(b)) = (&jar.session, bound)
            && !s.contains('.')
            && !b.contains('.')
        {
            jar.session = Some(format!("{s}.{b}"));
        }
        jar
    }

    pub(crate) fn browser(&self) -> Browser<'_> {
        Browser {
            flow: self.flow.as_deref(),
            session: self.session.as_deref(),
            marker: self.marker.as_deref(),
            login: self.login.as_deref(),
            ip: self.ip,
            correlation: &self.correlation,
        }
    }
}

fn status(code: u16) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

fn api_headers(h: &mut HeaderMap) {
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

/// A hosted page or script, with the hosted login's security headers (OP-146 m.12 (f)).
fn hosted(
    code: StatusCode,
    body: &'static str,
    content_type: &'static str,
    cache: &'static str,
) -> Response {
    let mut r = (code, body).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    assets::secure(h);
    r
}

fn json_response(code: StatusCode, body: Vec<u8>) -> Response {
    let mut r = (code, body).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

/// The reply on the wire, after its adaptive delay (TN-82).
pub(crate) async fn send(reply: Reply, headers: &HeaderMap) -> Response {
    if reply.pad_ms > 0 {
        tokio::time::sleep(Duration::from_millis(reply.pad_ms)).await;
    }
    let code = status(reply.status);
    let mut response = match reply.body {
        Body::Ui(ui) => json_response(code, serde_json::to_vec(&ui).unwrap_or_default()),
        Body::Json(v) => json_response(code, serde_json::to_vec(&v).unwrap_or_default()),
        Body::Problem(p) => Problem::new(code, p.code, p.title)
            .with_reason(reply.reason)
            .into_response(),
        Body::Html(page) => hosted(code, page, "text/html; charset=utf-8", "no-store"),
        Body::Script(source) => hosted(code, source, "text/javascript; charset=utf-8", "no-cache"),
        Body::Empty => code.into_response(),
        // OP-153 m.3 (l)
        Body::Redirect(to) => {
            let mut r = code.into_response();
            if let Ok(v) = HeaderValue::from_str(&to) {
                r.headers_mut().insert(header::LOCATION, v);
            }
            r
        }
    };
    let h = response.headers_mut();
    api_headers(h);
    for c in reply.cookies {
        if let Ok(v) = HeaderValue::from_str(&c) {
            h.append(header::SET_COOKIE, v);
        }
    }
    if let Some(s) = reply.retry_after_s {
        h.insert(header::RETRY_AFTER, HeaderValue::from(s));
    }
    for (name, value) in reply.headers {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            // OP-156 m.3 (g)
            if n.as_str() == "permissions-policy" {
                h.insert(n, v);
            } else {
                h.append(n, v);
            }
        }
    }
    if let Some(id) = headers.get(&REQUEST_ID) {
        h.insert(REQUEST_ID, id.clone());
    }
    response
}

pub(super) fn problem(code: StatusCode, name: &'static str, title: &'static str) -> Response {
    let mut r = Problem::new(code, name, title).into_response();
    api_headers(r.headers_mut());
    r
}

fn not_found() -> Response {
    problem(StatusCode::NOT_FOUND, "not-found", "Not Found")
}

pub(crate) fn authority<'a>(uri: &'a Uri, headers: &'a HeaderMap) -> &'a str {
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str))
        .unwrap_or_default()
}

/// The realm the request reached; the plain 404 names none (§17.9.6).
pub(super) async fn realm<D: Directory, K: Keys, KI, C, M>(
    s: &Shared<D, K, KI, C, M>,
    params: &HashMap<String, String>,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<RealmEntry, Response> {
    let slug = params.get("slug").map(String::as_str);
    // OP-156 m.3 (i)
    match s
        .discovery
        .resolve_hosted(authority(uri, headers), slug)
        .await
    {
        Ok(Some(entry)) => Ok(entry),
        Ok(None) => Err(not_found()),
        Err(_) => Err(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Service Unavailable",
        )),
    }
}

/// The Frontend API is same-origin only (OP-150 m.3 (r), §14.5, CSRF): a state-changing request
/// that names an `Origin` must name the realm host over `https`, and one that names a
/// `Sec-Fetch-Site` must be `same-origin` or `none` (a direct navigation or a product's own
/// client). No CORS is ever granted, so a browser on another origin never gets past its
/// preflight; this check refuses what a browser sends without one. Cookies are `__Host-`,
/// `Secure`, `HttpOnly`, `SameSite=Lax` (`domain::session::set_cookie`).
pub(super) fn same_origin(headers: &HeaderMap) -> Result<(), Response> {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let cross = || {
        problem(
            StatusCode::FORBIDDEN,
            "cross-site",
            "The request did not come from this site",
        )
    };
    if let Some(origin) = headers.get(header::ORIGIN) {
        let ok = origin
            .to_str()
            .ok()
            .and_then(|o| o.strip_prefix("https://"))
            .is_some_and(|o| !o.is_empty() && o.eq_ignore_ascii_case(host));
        if !ok {
            return Err(cross());
        }
    }
    if let Some(site) = headers.get("sec-fetch-site") {
        let ok = site
            .to_str()
            .is_ok_and(|s| s == "same-origin" || s == "none");
        if !ok {
            return Err(cross());
        }
    }
    Ok(())
}

/// A state-changing request carries JSON, so a cross-site form cannot send it without a
/// preflight this surface never answers.
pub(super) fn json_only(headers: &HeaderMap) -> Result<(), Response> {
    let ok = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
        });
    if ok {
        Ok(())
    } else {
        Err(problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "json-required",
            "Unsupported Media Type",
        ))
    }
}

fn body<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Response> {
    serde_json::from_slice(bytes)
        .map_err(|_| problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request"))
}

fn bounded(text: &str, max: usize) -> Result<&str, Response> {
    if text.chars().count() > max || text.chars().any(char::is_control) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "invalid-request",
            "Bad Request",
        ));
    }
    Ok(text)
}

macro_rules! handler {
    (
        $(#[$doc:meta])*
        $name:ident($s:ident, $entry:ident, $b:ident, $p:ident, $bytes:ident, $headers:ident) $write:literal $body:block
    ) => {
        $(#[$doc])*
        pub(super) async fn $name<D, K, KI, C, M>(
            State($s): St<D, K, KI, C, M>,
            Path($p): Params,
            peer: Option<Extension<Peer>>,
            method: axum::http::Method,
            uri: Uri,
            $headers: HeaderMap,
            $bytes: Bytes,
        ) -> Response
        where
            D: Directory,
            K: Keys,
            KI: Kits,
            C: Clock + Sync,
            M: Messages,
        {
            let $entry = match realm(&$s, &$p, &uri, &$headers).await {
                Ok(e) => e,
                Err(r) => return r,
            };
            let bodiless_delete = method == axum::http::Method::DELETE && $bytes.is_empty();
            if $write
                && let Err(r) = same_origin(&$headers)
                    .and_then(|()| if bodiless_delete { Ok(()) } else { json_only(&$headers) })
            {
                return r;
            }
            let jar = Jar::of(&$headers, peer);
            let $b = jar.browser();
            let reply: Result<Reply, Response> = async { $body }.await;
            match reply {
                Ok(r) => send(r, &$headers).await,
                Err(r) => r,
            }
        }
    };
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkBody {
    token: String,
    #[serde(default)]
    other_device: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StepUpBody {
    #[serde(default)]
    max_age: Option<u64>,
    #[serde(default)]
    acr: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TotpBody {
    #[serde(default)]
    label: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeBody {
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyBody {
    name: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialBody {
    credential: serde_json::Value,
}

fn param<'a>(p: &'a HashMap<String, String>, name: &str) -> &'a str {
    p.get(name).map_or("", String::as_str)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailBody {
    email: String,
}

handler! {
    /// `POST /v1/login/flows`: a login flow, or a sign-up flow when the body names
    /// `kind: registration` (OP-153 m.3 (g)).
    create(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let kind = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("kind").cloned())
            .map_or(Ok(access_identity_ui::domain::flow::FlowKind::Login), serde_json::from_value)
            .map_err(|_| problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request"))?;
        Ok(match kind {
            access_identity_ui::domain::flow::FlowKind::Login => s.hosted.create(&entry, &b).await,
            access_identity_ui::domain::flow::FlowKind::Registration => {
                s.hosted.create_signup(&entry, &b).await
            }
            _ => return Err(problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request")),
        })
    }
}

handler! {
    /// `POST /v1/account/email` (OP-153 m.3 (i)).
    start_email_change(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let req: EmailBody = body(&bytes)?;
        let email = bounded(&req.email, 320)?;
        Ok(s.hosted.start_email_change(&entry, &b, email).await)
    }
}

handler! {
    /// `POST /v1/account/email/{change}` (OP-153 m.3 (i)).
    confirm_email_change(s, entry, b, p, bytes, headers) true {
        let req: CodeBody = body(&bytes)?;
        let code = bounded(&req.code, 16)?;
        let change = bounded(param(&p, "change"), 64)?;
        Ok(s.hosted.confirm_email_change(&entry, &b, change, code).await)
    }
}

handler! {
    /// `POST /v1/login/step-up` (TN-44, RFC 9470): `max_age` seconds, `0` when absent.
    step_up(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let req: StepUpBody = if bytes.is_empty() {
            StepUpBody { max_age: None, acr: None }
        } else {
            body(&bytes)?
        };
        let acr = req.acr.as_deref().map(|a| bounded(a, MAX_TEXT)).transpose()?;
        Ok(s.hosted.step_up(&entry, &b, req.max_age.unwrap_or(0), acr).await)
    }
}

handler! {
    /// `GET /v1/login/flows/{flow}`.
    get_flow(s, entry, b, p, bytes, headers) false {
        let _ = &bytes;
        let flow = param(&p, "flow");
        // OP-153 m.3 (g)
        if access_identity_ui::app::signup::is_signup(flow) {
            return Ok(s.hosted.get_signup(&entry, &b, flow).await);
        }
        Ok(s.hosted.get(&entry, &b, flow).await)
    }
}

handler! {
    /// `POST /v1/login/flows/{flow}`.
    submit(s, entry, b, p, bytes, headers) true {
        let submission: Submission = serde_json::from_slice(&bytes).map_err(|_| {
            problem(
                StatusCode::BAD_REQUEST,
                "invalid-submission",
                "The submission does not match the sign-in step",
            )
        })?;
        let flow = param(&p, "flow");
        // OP-153 m.3 (g)
        if access_identity_ui::app::signup::is_signup(flow) {
            return Ok(s.hosted.submit_signup(&entry, &b, flow, submission).await);
        }
        Ok(s.hosted.submit(&entry, &b, flow, submission).await)
    }
}

handler! {
    /// `POST /v1/login/link/preview`.
    preview_link(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let link: LinkBody = body(&bytes)?;
        Ok(s.hosted.preview_link(&entry, &b, bounded(&link.token, 128)?).await)
    }
}

handler! {
    /// `POST /v1/login/link/confirm`.
    confirm_link(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let link: LinkBody = body(&bytes)?;
        Ok(s.hosted
            .confirm_link(&entry, &b, bounded(&link.token, 128)?, link.other_device)
            .await)
    }
}

handler! {
    /// `GET /v1/sessions/current`.
    current_session(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        Ok(s.hosted.current_session(&entry, &b).await)
    }
}

handler! {
    /// `GET /v1/sessions`.
    sessions(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        Ok(s.hosted.sessions(&entry, &b).await)
    }
}

handler! {
    /// `POST /v1/sessions/current/sign-out`.
    sign_out(s, entry, b, p, bytes, headers) true {
        let _ = (&p, &bytes);
        Ok(s.hosted.sign_out(&entry, &b).await)
    }
}

handler! {
    /// `POST /v1/sessions/sign-out-everywhere`.
    sign_out_everywhere(s, entry, b, p, bytes, headers) true {
        let _ = (&p, &bytes);
        Ok(s.hosted.sign_out_everywhere(&entry, &b).await)
    }
}

handler! {
    /// `POST /v1/account/totp`.
    begin_totp(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let req: TotpBody = if bytes.is_empty() { TotpBody { label: None } } else { body(&bytes)? };
        let label = bounded(req.label.as_deref().unwrap_or("account"), MAX_TEXT)?;
        Ok(s.hosted.begin_totp(&entry, &b, label).await)
    }
}

handler! {
    /// `POST /v1/account/totp/{enrollment}`.
    confirm_totp(s, entry, b, p, bytes, headers) true {
        let req: CodeBody = body(&bytes)?;
        let code = bounded(&req.code, 16)?;
        Ok(s.hosted.confirm_totp(&entry, &b, param(&p, "enrollment"), code).await)
    }
}

handler! {
    /// `POST /v1/account/recovery-codes`.
    recovery_codes(s, entry, b, p, bytes, headers) true {
        let _ = (&p, &bytes);
        Ok(s.hosted.recovery_codes(&entry, &b).await)
    }
}

handler! {
    /// `POST /v1/account/recovery-codes/acknowledgement`.
    acknowledge_recovery_codes(s, entry, b, p, bytes, headers) true {
        let _ = (&p, &bytes);
        Ok(s.hosted.acknowledge_recovery_codes(&entry, &b).await)
    }
}

handler! {
    /// `POST /v1/account/credential-export`.
    export_credentials(s, entry, b, p, bytes, headers) true {
        let _ = (&p, &bytes);
        Ok(s.hosted.export_credentials(&entry, &b).await)
    }
}

handler! {
    /// `POST /v1/account/passkeys`.
    begin_passkey(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let req: PasskeyBody = body(&bytes)?;
        let name = bounded(&req.name, MAX_TEXT)?;
        let display = bounded(req.display_name.as_deref().unwrap_or(name), MAX_TEXT)?;
        Ok(s.hosted.begin_passkey(&entry, &b, name, display).await)
    }
}

handler! {
    /// `POST /v1/account/passkeys/{registration}`.
    finish_passkey(s, entry, b, p, bytes, headers) true {
        let req: CredentialBody = body(&bytes)?;
        let text = match req.credential {
            serde_json::Value::String(t) => t,
            other => other.to_string(),
        };
        Ok(s.hosted
            .finish_passkey(&entry, &b, param(&p, "registration"), &text)
            .await)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordBody {
    new_password: String,
}

handler! {
    /// `POST /v1/sessions/{session}/end` (X36, OP-153 m.3 (y)).
    end_sign_in(s, entry, b, p, bytes, headers) true {
        let _ = &bytes;
        let session = bounded(param(&p, "session"), MAX_TEXT)?;
        Ok(s.hosted.end_sign_in(&entry, &b, session).await)
    }
}

handler! {
    /// `GET /v1/account/methods` (S11, TN-99).
    sign_in_methods(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        Ok(s.hosted.sign_in_methods(&entry, &b).await)
    }
}

handler! {
    /// `DELETE /v1/account/methods/{credential}` (TN-68).
    remove_sign_in_method(s, entry, b, p, bytes, headers) true {
        let _ = &bytes;
        let credential = bounded(param(&p, "credential"), MAX_TEXT)?;
        Ok(s.hosted.remove_sign_in_method(&entry, &b, credential).await)
    }
}

handler! {
    /// `PUT /v1/account/password` (§10.2.1, TN-50).
    set_password(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let req: PasswordBody = body(&bytes)?;
        if req.new_password.chars().count() > 128 {
            return Err(problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request"));
        }
        Ok(s.hosted.set_password(&entry, &b, &req.new_password).await)
    }
}

handler! {
    /// `GET /v1/login/branding` (TN-106).
    branding(s, entry, b, p, bytes, headers) false {
        let _ = (&b, &p, &bytes);
        Ok(s.hosted.branding(&entry).await)
    }
}

handler! {
    /// `GET /v1/login/messages` (X35, OP-153 m.22 (k)).
    message_overrides(s, entry, b, p, bytes, headers) false {
        let _ = (&b, &p, &bytes);
        Ok(s.hosted.message_overrides(&entry).await)
    }
}

/// The DBSC proof of a request, when it carries exactly one.
fn dbsc_proof(headers: &HeaderMap) -> Option<&str> {
    let mut all = headers
        .get_all(access_identity_session::domain::dbsc::RESPONSE_HEADER)
        .iter();
    let first = all.next()?.to_str().ok()?;
    if all.next().is_some() {
        return None;
    }
    Some(first.trim().trim_matches('"'))
}

handler! {
    /// `POST /v1/dbsc/register` (TN-33): the browser posts its proof in a header, no body.
    dbsc_register(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        same_origin(&headers)?;
        Ok(s.hosted.dbsc_register(&entry, &b, dbsc_proof(&headers)).await)
    }
}

handler! {
    /// `POST /v1/dbsc/refresh` (TN-33).
    dbsc_refresh(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        same_origin(&headers)?;
        Ok(s.hosted.dbsc_refresh(&entry, &b, dbsc_proof(&headers)).await)
    }
}

/// Largest CSP report body read.
const MAX_CSP_REPORT: usize = 64 * 1024;

handler! {
    /// `POST /csp-reports` (OP-153 m.3 (t)): `application/csp-report` or
    /// `application/reports+json`.
    csp_report(s, entry, b, p, bytes, headers) false {
        let _ = &p;
        let kind = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::trim)
            .unwrap_or_default();
        if !matches!(kind, "application/csp-report" | "application/reports+json" | "application/json") {
            return Err(problem(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json-required", "Unsupported Media Type"));
        }
        if bytes.len() > MAX_CSP_REPORT {
            return Err(problem(StatusCode::PAYLOAD_TOO_LARGE, "too-large", "Payload Too Large"));
        }
        Ok(s.hosted.csp_report(&entry, &b, &bytes).await)
    }
}

/// `GET /login/theme.css`: the realm's colours as CSS custom properties (TN-106).
pub(super) async fn theme_css<D, K, KI, C, M>(
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
    match s.hosted.theme(&entry).await {
        Ok(theme) => {
            let mut r = (StatusCode::OK, theme.css()).into_response();
            let h = r.headers_mut();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/css; charset=utf-8"),
            );
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            assets::secure(h);
            r
        }
        Err(r) => send(r, &headers).await,
    }
}

/// `GET /.well-known/webauthn`: the realm's Related Origins document (TN-18).
pub(super) async fn related_origins<D, K, KI, C, M>(
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
    match s.hosted.related_origins(&entry).await {
        Ok(doc) => json_response(StatusCode::OK, doc.into_bytes()),
        Err(r) => send(r, &headers).await,
    }
}

/// A declared Frontend API route whose lane does not serve it yet: an unknown host is the
/// router's plain 404 as for every hosted route (§17.9.6), a known one `501 not-yet-served`
/// (OP-153 m.4).
pub(super) async fn not_yet_served<D, K, KI, C, M>(
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
    if let Err(r) = realm(&s, &p, &uri, &headers).await {
        return r;
    }
    crate::problem::codes::NOT_YET_SERVED
        .problem()
        .into_response()
}

/// Whether the page at `uri` has the person's device Instance sign with the Kernel (Wasm): the
/// consent screen of a client the realm did not register (EI-18, OP-154 m.3 (k)) and the CIBA
/// approval page (OP-155 m.3 (l)).
fn signs(uri: &Uri) -> bool {
    uri.query()
        .and_then(|q| access_identity_oauth::domain::request::Params::parse(q).ok())
        .is_some_and(|p| matches!(p.get("reason"), Some("approve" | "ciba")))
}

/// `policy` with WebAssembly compilation allowed to this origin's scripts, and nothing else.
fn with_wasm(policy: &str) -> String {
    policy.replacen(
        "script-src 'self';",
        "script-src 'self' 'wasm-unsafe-eval';",
        1,
    )
}

/// The login app's page.
pub(super) async fn page<D, K, KI, C, M>(
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
    if s.assets.is_none() {
        return not_found();
    }
    // TN-106, IDP-36, OP-153 m.3 (t)
    let (Ok(theme), Ok(base)) = (
        s.hosted.theme(&entry).await,
        s.hosted.base_path(&entry).await,
    ) else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Service Unavailable",
        );
    };
    let Some(mut page) = s.assets.as_ref().and_then(|a| a.page_at(&base)) else {
        return not_found();
    };
    let (mut enforced, mut report_only) = theme.csp(&base);
    // EI-18, OP-154 m.3 (k)
    if signs(&uri) {
        enforced = with_wasm(&enforced);
        report_only = report_only.map(|r| with_wasm(&r));
    }
    let h = page.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&enforced) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    if let Some(v) = report_only.and_then(|r| HeaderValue::from_str(&r).ok()) {
        h.insert(header::CONTENT_SECURITY_POLICY_REPORT_ONLY, v);
    }
    if let Ok(v) = HeaderValue::from_str(
        &access_identity_ui::domain::branding::reporting_endpoints(&base),
    ) {
        h.insert(HeaderName::from_static("reporting-endpoints"), v);
    }
    page
}

/// A built asset of the login app.
pub(super) async fn asset<D, K, KI, C, M>(
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
    if let Err(r) = realm(&s, &p, &uri, &headers).await {
        return r;
    }
    s.assets
        .as_ref()
        .and_then(|a| a.asset(param(&p, "path")))
        .unwrap_or_else(not_found)
}

handler! {
    /// `GET /v1/account/preferences` (IDP-37).
    preferences(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        Ok(s.hosted.preferences(&entry, &b).await)
    }
}

handler! {
    /// `PUT /v1/account/preferences` (IDP-37, OP-153 m.3 (ee)).
    set_preferences(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let req: access_identity_ui::app::privacy::PreferencesBody = body(&bytes)?;
        Ok(s.hosted.set_preferences(&entry, &b, &req).await)
    }
}

handler! {
    /// `GET /v1/account/documents` (E60).
    documents(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        Ok(s.hosted.documents(&entry, &b).await)
    }
}

handler! {
    /// `POST /v1/account/documents` (IDP-37, TN-132).
    accept_document(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let req: access_identity_ui::app::privacy::DocumentBody = body(&bytes)?;
        Ok(s.hosted.accept_document(&entry, &b, &req).await)
    }
}

handler! {
    /// `GET /v1/account/security-history` (OP-43).
    security_history(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        Ok(s.hosted.security_history(&entry, &b).await)
    }
}

handler! {
    /// `GET /v1/account/deletion` (OP-153 m.3 (bb), X38).
    deletion(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        Ok(s.hosted.deletion(&entry, &b).await)
    }
}

handler! {
    /// `DELETE /v1/account/deletion`: cancels inside the window (OP-153 m.3 (bb)).
    cancel_deletion(s, entry, b, p, bytes, headers) true {
        let _ = (&p, &bytes);
        Ok(s.hosted.cancel_deletion(&entry, &b).await)
    }
}

handler! {
    /// `GET /v1/account/data-requests` (TN-78).
    data_requests(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        Ok(s.hosted.data_requests(&entry, &b).await)
    }
}

handler! {
    /// `POST /v1/invitations/{code}` (TN-89, OP-153 m.3 (o)).
    accept_invitation(s, entry, b, p, bytes, headers) true {
        let req: access_identity_ui::app::orgs::AcceptBody = if bytes.is_empty() {
            access_identity_ui::app::orgs::AcceptBody::default()
        } else {
            body(&bytes)?
        };
        Ok(s.hosted.accept_invitation(&entry, &b, param(&p, "code"), &req).await)
    }
}

handler! {
    /// `GET /v1/account/organizations` (OP-153 m.3 (o)).
    organizations(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        Ok(s.hosted.organizations(&entry, &b).await)
    }
}

handler! {
    /// `POST /v1/organizations/{organization}/access-requests` (TN-90).
    request_access(s, entry, b, p, bytes, headers) true {
        let _ = &bytes;
        Ok(s.hosted.request_access(&entry, &b, param(&p, "organization")).await)
    }
}

/// `GET /v1/invitations/{code}` (TN-89 (8), (9)): no session needed; a scanner's fetch is
/// counted and consumes nothing; the answer is never sent on as a referrer.
pub(super) async fn invitation<D, K, KI, C, M>(
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
    let reply = s.hosted.invitation(&entry, param(&p, "code")).await;
    let mut r = send(reply, &headers).await;
    r.headers_mut().insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    r
}

handler! {
    /// `GET /v1/organizations/{organization}/sign-in` (TN-3, TN-98).
    organization_sign_in(s, entry, b, p, bytes, headers) false {
        let _ = (&b, &bytes);
        Ok(s.hosted.organization_sign_in(&entry, param(&p, "organization")).await)
    }
}

handler! {
    /// `GET /v1/account/handovers` (TN-91).
    handovers(s, entry, b, p, bytes, headers) false {
        let _ = (&p, &bytes);
        Ok(s.hosted.handovers(&entry, &b).await)
    }
}

handler! {
    /// `POST /v1/organizations/{organization}/handovers/{handover}/contribution` (TN-91).
    contribute_handover(s, entry, b, p, bytes, headers) true {
        let req: access_identity_ui::app::household::HandoverAcceptance = body(&bytes)?;
        Ok(s.hosted
            .contribute_handover(
                &entry,
                &b,
                (param(&p, "organization"), param(&p, "handover")),
                &req,
            )
            .await)
    }
}

handler! {
    /// `DELETE /v1/organizations/{organization}/handovers/{handover}` (TN-91).
    cancel_handover(s, entry, b, p, bytes, headers) true {
        let _ = &bytes;
        Ok(s.hosted
            .cancel_handover(&entry, &b, param(&p, "organization"), param(&p, "handover"))
            .await)
    }
}

handler! {
    /// `POST /v1/account/guardian-consents` (E53, E47).
    ask_consent(s, entry, b, p, bytes, headers) true {
        let _ = &p;
        let req: access_identity_ui::app::household::ConsentAsk = body(&bytes)?;
        Ok(s.hosted.ask_consent(&entry, &b, &req).await)
    }
}

handler! {
    /// `GET /v1/account/guardian-consents/{consent}` (E47).
    consent(s, entry, b, p, bytes, headers) false {
        let _ = &bytes;
        Ok(s.hosted.consent(&entry, &b, param(&p, "consent")).await)
    }
}

handler! {
    /// `POST /v1/account/guardian-consents/{consent}` (E53, E47).
    decide_consent(s, entry, b, p, bytes, headers) true {
        let req: access_identity_ui::app::household::ConsentDecision = body(&bytes)?;
        Ok(s.hosted.decide_consent(&entry, &b, param(&p, "consent"), &req).await)
    }
}
