//! The account BFF on axum (OP-153 m.3 (w)): the built app at `/account`, its API under
//! `/account/api/`, the device registration and the ADP proxy. The hosted login session is
//! checked on every API call; state-changing calls pass the origin and CSRF checks; the proxy
//! passes on only what the session's device Instance signed.

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use access_identity_oauth::ports::{Directory, RealmEntry};
use access_identity_ui::app::shell::Shell;
use access_identity_ui::app::{Browser, Devices, Hosted, Reply, SESSION_COOKIE};
use access_identity_ui::domain::frontend::{InstanceRegistration, rfc3339};
use access_identity_ui::ports::{
    ApprovalClaims, Approvals, ArtifactSigner, Clock, DeviceInstances, Kits, Messages,
};
use access_kernel::json::{b64url_decode, b64url_encode};
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Extension, Router};
use serde_json::json;
use suiss_crypto::secret::Secret;
use tower::ServiceExt as _;

use super::domain::{
    ACCOUNT_PEP, CSRF_COOKIE, CSRF_HEADER, Forwarded, api_base, carries_ais, csrf_cookie, csrf_ok,
    csrf_token, forwarded, read_intent, secure,
};
use crate::adp::adapters::{Pep, Requester};
use crate::console::domain::{
    Gate, ProofError, RETURNED, ReadRefusal, adp_read_scope, gate, pick, unsafe_method,
    verify_commit, verify_read_proof,
};
use crate::login::web::{Jar, authority, cookies, send};
use crate::login::{Assets, Peer};
use crate::problem::codes;
use crate::{Limits, Problem};

/// Largest ADP answer passed back.
const MAX_ANSWER: usize = 4 * 1024 * 1024;

type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The hosted login behind the account pages: its session, its device registration and its
/// trusted clock.
trait Hosting: Send + Sync {
    fn shell<'a>(
        &'a self,
        entry: &'a RealmEntry,
        b: Browser<'a>,
    ) -> Boxed<'a, Result<Shell, Reply>>;
    fn challenge<'a>(
        &'a self,
        entry: &'a RealmEntry,
        b: Browser<'a>,
        key: &'a str,
    ) -> Boxed<'a, Reply>;
    fn register<'a>(
        &'a self,
        entry: &'a RealmEntry,
        b: Browser<'a>,
        body: &'a InstanceRegistration,
    ) -> Boxed<'a, Reply>;
    fn now_ms(&self) -> u64;
    fn realm<'a>(
        &'a self,
        authority: &'a str,
        slug: Option<&'a str>,
    ) -> Boxed<'a, Result<Option<RealmEntry>, ()>>;
}

struct Hosted9<D, KI, C, M, A, I, P, Q> {
    directory: D,
    hosted: Arc<Hosted<KI, C, M>>,
    devices: Devices<A, I, P, Q>,
}

impl<D, KI, C, M, A, I, P, Q> Hosting for Hosted9<D, KI, C, M, A, I, P, Q>
where
    D: Directory,
    KI: Kits,
    C: Clock + Sync + Send,
    M: Messages,
    A: ArtifactSigner,
    I: DeviceInstances,
    P: Approvals,
    Q: ApprovalClaims,
{
    fn shell<'a>(
        &'a self,
        entry: &'a RealmEntry,
        b: Browser<'a>,
    ) -> Boxed<'a, Result<Shell, Reply>> {
        Box::pin(async move { self.hosted.shell(entry, &b).await })
    }

    fn challenge<'a>(
        &'a self,
        entry: &'a RealmEntry,
        b: Browser<'a>,
        key: &'a str,
    ) -> Boxed<'a, Reply> {
        Box::pin(async move {
            self.hosted
                .shell_challenge(&self.devices, entry, &b, key)
                .await
        })
    }

    fn register<'a>(
        &'a self,
        entry: &'a RealmEntry,
        b: Browser<'a>,
        body: &'a InstanceRegistration,
    ) -> Boxed<'a, Reply> {
        Box::pin(async move {
            self.hosted
                .register_instance(&self.devices, entry, &b, body)
                .await
        })
    }

    fn now_ms(&self) -> u64 {
        self.hosted.clock.now_ms()
    }

    fn realm<'a>(
        &'a self,
        authority: &'a str,
        slug: Option<&'a str>,
    ) -> Boxed<'a, Result<Option<RealmEntry>, ()>> {
        Box::pin(async move {
            access_identity_oauth::app::resolve(&self.directory, authority, slug)
                .await
                .map_err(|_| ())
        })
    }
}

struct Account {
    hosting: Box<dyn Hosting>,
    adp: Router,
    assets: Option<Assets>,
    limits: Limits,
}

type St = State<Arc<Account>>;
type Params = Path<HashMap<String, String>>;

/// The account's problems.
mod problems {
    use super::{Problem, StatusCode};

    pub(super) fn csrf() -> Problem {
        Problem::new(StatusCode::FORBIDDEN, "csrf-token-invalid", "Forbidden")
    }

    pub(super) fn origin() -> Problem {
        Problem::new(StatusCode::FORBIDDEN, "origin-not-allowed", "Forbidden")
    }

    pub(super) fn instance_required() -> Problem {
        Problem::new(
            StatusCode::FORBIDDEN,
            "account-instance-required",
            "Forbidden",
        )
    }

    pub(super) fn proof_rejected() -> Problem {
        Problem::new(StatusCode::FORBIDDEN, "read-proof-rejected", "Forbidden")
    }

    pub(super) fn commit_rejected() -> Problem {
        Problem::new(StatusCode::FORBIDDEN, "commit-ais-rejected", "Forbidden")
    }

    pub(super) fn read_not_own() -> Problem {
        Problem::new(StatusCode::FORBIDDEN, "read-not-own", "Forbidden")
    }

    pub(super) fn step_up() -> Problem {
        Problem::new(StatusCode::FORBIDDEN, "step-up-required", "Forbidden")
    }

    pub(super) fn instance_exists() -> Problem {
        Problem::new(StatusCode::CONFLICT, "instance-exists", "Conflict")
    }

    pub(super) fn draft(e: crate::console::drafts::DraftError) -> Problem {
        Problem::new(StatusCode::BAD_REQUEST, e.code(), "Bad Request")
    }
}

fn unavailable() -> Response {
    codes::UNAVAILABLE.problem().into_response()
}

fn not_found() -> Response {
    codes::NOT_FOUND.problem().into_response()
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn json_reply(status: StatusCode, value: &serde_json::Value) -> Response {
    no_store((status, axum::Json(value)).into_response())
}

/// The realm's origin from its stored issuer (TN-131: the `Host` header only selects it).
fn origin_of(entry: &RealmEntry) -> &str {
    let issuer = entry.issuer.as_str();
    issuer
        .get(..issuer.len().saturating_sub(entry.issuer.path().len()))
        .unwrap_or(issuer)
}

/// A request's realm, its cookies and its live session.
struct Live {
    entry: RealmEntry,
    jar: Jar,
    cookie: Secret<[u8; 32]>,
    shell: Shell,
}

fn session_value(headers: &HeaderMap) -> Option<Secret<[u8; 32]>> {
    let mut found: Option<&str> = None;
    for (n, v) in cookies(headers) {
        if n == SESSION_COOKIE {
            match found {
                Some(prior) if prior != v => return None,
                _ => found = Some(v),
            }
        }
    }
    let bytes = b64url_decode(found?).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok().map(Secret::new)
}

async fn entry(
    s: &Account,
    p: &HashMap<String, String>,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<RealmEntry, Response> {
    match s
        .hosting
        .realm(authority(uri, headers), p.get("slug").map(String::as_str))
        .await
    {
        Ok(Some(e)) => Ok(e),
        Ok(None) => Err(not_found()),
        Err(()) => Err(unavailable()),
    }
}

/// TN-131: a browser's cross-site request is refused; a state-changing one names the realm's
/// origin and carries the session's CSRF token.
fn guard(
    origin: &str,
    method: &Method,
    headers: &HeaderMap,
    cookie: &Secret<[u8; 32]>,
) -> Result<(), Response> {
    match gate(headers, method, origin) {
        Gate::Pass => {}
        Gate::Origin | Gate::CrossSite => return Err(problems::origin().into_response()),
    }
    if !unsafe_method(method) {
        return Ok(());
    }
    let presented = headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let double = cookies(headers)
        .find(|(n, _)| *n == CSRF_COOKIE)
        .map(|(_, v)| v)
        .unwrap_or_default();
    if csrf_ok(cookie, presented, double) {
        Ok(())
    } else {
        Err(problems::csrf().into_response())
    }
}

/// Every API call: the realm, the gates and the live session (G57).
async fn live(
    s: &Account,
    p: &HashMap<String, String>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    peer: Option<Extension<Peer>>,
) -> Result<Live, Response> {
    let entry = entry(s, p, uri, headers).await?;
    if gate(headers, method, origin_of(&entry)) == Gate::CrossSite {
        return Err(problems::origin().into_response());
    }
    let Some(cookie) = session_value(headers) else {
        return Err(send(
            Reply::problem(access_identity_ui::app::SESSION_REQUIRED),
            headers,
        )
        .await);
    };
    guard(origin_of(&entry), method, headers, &cookie)?;
    let jar = Jar::of(headers, peer);
    let shell = match s.hosting.shell(&entry, jar.browser()).await {
        Ok(sh) => sh,
        Err(r) => return Err(send(r, headers).await),
    };
    Ok(Live {
        entry,
        jar,
        cookie,
        shell,
    })
}

async fn page(State(s): St, Path(p): Params, uri: Uri, headers: HeaderMap) -> Response {
    if let Err(r) = entry(&s, &p, &uri, &headers).await {
        return r;
    }
    s.assets
        .as_ref()
        .and_then(Assets::page)
        .unwrap_or_else(not_found)
}

async fn asset(State(s): St, Path(p): Params) -> Response {
    let path = p.get("path").map_or("", String::as_str);
    s.assets
        .as_ref()
        .and_then(|a| a.asset(path))
        .unwrap_or_else(not_found)
}

/// `GET …/account/api/session`: who is signed in, the session's device Instance and Party, and
/// the PEP the browser's statements name; sets the CSRF cookie.
async fn session(
    State(s): St,
    Path(p): Params,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
) -> Response {
    let l = match live(&s, &p, &method, &uri, &headers, peer).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let sh = &l.shell;
    let slug = p.get("slug").map(String::as_str);
    let token = csrf_token(&l.cookie);
    let mut r = json_reply(
        StatusCode::OK,
        &json!({
            "realm": sh.slug,
            "domain": b64url_encode(&sh.domain.0),
            "account": sh.account,
            "expires_at": rfc3339(sh.expires_ms),
            "party": sh.party.map(|p| b64url_encode(&p)),
            "instance": sh.instance.as_ref().map(|i| b64url_encode(&i.kid)),
            "instance_id": sh.instance.as_ref().map(|i| b64url_encode(&i.instance)),
            "step_up_needed": !sh.fresh,
            "pep": ACCOUNT_PEP,
            "api": api_base(slug),
            "frontend": slug.map_or_else(String::new, |s| format!("/realms/{s}")),
        }),
    );
    if let Ok(v) = HeaderValue::from_str(&csrf_cookie(&token)) {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
    r
}

/// `POST …/account/api/instances/challenge` (OP-149 m.6): the challenge for the browser's key,
/// with the intent envelopes its Kernel shows before it signs (X11).
async fn challenge(
    State(s): St,
    Path(p): Params,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
    body: Bytes,
) -> Response {
    let l = match live(&s, &p, &method, &uri, &headers, peer).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    if l.shell.instance.is_some() {
        return problems::instance_exists().into_response();
    }
    // OP-149 m.6
    if !l.shell.fresh {
        return problems::step_up().into_response();
    }
    let Some(key) = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("key").and_then(|k| k.as_str()).map(String::from))
    else {
        return codes::INVALID_REQUEST.problem().into_response();
    };
    let reply = s.hosting.challenge(&l.entry, l.jar.browser(), &key).await;
    send(reply, &headers).await
}

/// `POST …/account/api/instances` (OP-149 m.6, OP-151 m.3 (e)): registers the browser's key as
/// the session's device Instance through its own `instance_create` Exercise.
async fn register(
    State(s): St,
    Path(p): Params,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
    body: Bytes,
) -> Response {
    let l = match live(&s, &p, &method, &uri, &headers, peer).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    if l.shell.instance.is_some() {
        return problems::instance_exists().into_response();
    }
    let Ok(req) = serde_json::from_slice::<InstanceRegistration>(&body) else {
        return codes::INVALID_REQUEST.problem().into_response();
    };
    let reply = s.hosting.register(&l.entry, l.jar.browser(), &req).await;
    send(reply, &headers).await
}

fn statement(headers: &HeaderMap) -> Result<Vec<u8>, Response> {
    let values: Vec<&str> = headers
        .get_all(crate::console::domain::AIS_HEADER)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    crate::api::domain::caller::ais_bytes(&values, b"")
        .map_err(|_| codes::AIS_REQUIRED.problem().into_response())
}

/// `POST …/account/api/intents` (PI-7): drafts the intent a hub screen asks for, for a read
/// proof by the session's device Instance over this very request.
async fn intents(
    State(s): St,
    Path(p): Params,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
    body: Bytes,
) -> Response {
    let l = match live(&s, &p, &method, &uri, &headers, peer).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let ais = match statement(&headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let now = s.hosting.now_ms();
    let instance = l.shell.instance.as_ref().map(|i| (&i.kid, &i.key));
    match verify_read_proof(
        &ais,
        instance,
        &l.shell.domain,
        &read_intent(&Method::POST, uri.path()),
        now,
    ) {
        Ok(_) => {}
        Err(ProofError::NoInstance) => return problems::instance_required().into_response(),
        Err(ProofError::Rejected) => return problems::proof_rejected().into_response(),
    }
    match crate::console::drafts::draft(&body, &l.shell.slug, now) {
        Ok(d) => json_reply(StatusCode::OK, &d.answer(&l.shell.domain)),
        Err(e) => problems::draft(e).into_response(),
    }
}

fn returned(status: u16, headers: &HeaderMap, body: Bytes) -> Response {
    let mut r = (
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
        body,
    )
        .into_response();
    r.headers_mut().remove(header::CONTENT_TYPE);
    for (name, value) in pick(headers, &RETURNED) {
        r.headers_mut().append(name, value);
    }
    no_store(r)
}

/// `POST …/account/api/proxy/adp/{rest}` → `/access/v1/{rest}` (TN-110, TN-128, OP-153 m.8):
/// a hub read goes on only with the session's device Instance's AIS, for the session's own
/// domain; `evaluation` only as a `commit` that Instance signed. The BFF adds no credential and
/// never signs; ADP sees the account pages as their own PEP.
async fn proxy(
    State(s): St,
    Path(p): Params,
    peer: Option<Extension<Peer>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let (method, headers, uri) = (&parts.method, &parts.headers, &parts.uri);
    let sess = match live(&s, &p, method, uri, headers, peer).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let rest = p.get("rest").map_or("", String::as_str);
    let Some(kind) = forwarded(rest).filter(|_| uri.query().is_none()) else {
        return not_found();
    };
    let Some(instance) = sess.shell.instance.as_ref() else {
        return problems::instance_required().into_response();
    };
    let Ok(body) = to_bytes(body, s.limits.max_body_bytes).await else {
        return codes::BODY_TOO_LARGE.problem().into_response();
    };
    match kind {
        Forwarded::Commit => {
            let now = s.hosting.now_ms();
            match verify_commit(
                &body,
                Some((&instance.kid, &instance.key)),
                &sess.shell.domain,
                now,
            ) {
                Ok(_) => {}
                Err(ProofError::NoInstance) => {
                    return problems::instance_required().into_response();
                }
                Err(ProofError::Rejected) => return problems::commit_rejected().into_response(),
            }
        }
        Forwarded::Read => {
            if !carries_ais(&body) {
                return problems::read_not_own().into_response();
            }
            match adp_read_scope(
                rest,
                &body,
                s.limits.max_body_bytes,
                &sess.shell.domain,
                sess.shell.party,
                Some(&instance.kid),
            ) {
                Ok(()) => {}
                Err(ReadRefusal::Malformed(error, at)) => {
                    return crate::adp::adapters::respond(crate::adp::app::bad(error, at), headers);
                }
                Err(ReadRefusal::Foreign) => {
                    tracing::info!(
                        event = "account.adp.refused",
                        outcome = "refused",
                        "forwarded read is not the session's own"
                    );
                    return problems::read_not_own().into_response();
                }
            }
        }
    }
    let Ok(mut forward) = axum::http::Request::builder()
        .method(Method::POST)
        .uri(format!("/access/v1/{rest}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .body(Body::from(body))
    else {
        return unavailable();
    };
    forward
        .extensions_mut()
        .insert(Pep(String::from(ACCOUNT_PEP)));
    // OP-141 m.23 (a)
    forward
        .extensions_mut()
        .insert(Requester(b64url_encode(&sess.shell.session)));
    let Ok(answer) = s.adp.clone().oneshot(forward).await;
    let (parts, body) = answer.into_parts();
    let Ok(body) = to_bytes(body, MAX_ANSWER).await else {
        return unavailable();
    };
    returned(parts.status.as_u16(), &parts.headers, body)
}

async fn api_not_found() -> Response {
    not_found()
}

async fn headers_layer(request: Request, next: Next) -> Response {
    let mut r = next.run(request).await;
    secure(r.headers_mut());
    r
}

/// The account routes: the pages, their assets and `…/account/api/*`, at the realm's host and
/// under `/realms/{slug}`, every answer with the account's security headers. `adp` is ADP's
/// router in this process; `assets` the built `web/account`.
pub fn router<D, KI, C, M, A, I, P, Q>(
    directory: D,
    hosted: Arc<Hosted<KI, C, M>>,
    devices: Devices<A, I, P, Q>,
    adp: Router,
    assets: Option<Assets>,
    limits: Limits,
) -> Router
where
    D: Directory + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
    A: ArtifactSigner + 'static,
    I: DeviceInstances + 'static,
    P: Approvals + 'static,
    Q: ApprovalClaims + 'static,
{
    let account = Arc::new(Account {
        hosting: Box::new(Hosted9 {
            directory,
            hosted,
            devices,
        }),
        adp,
        assets,
        limits,
    });
    let mut routes = Router::new().route("/account/assets/{*path}", get(asset));
    for prefix in ["", "/realms/{slug}"] {
        routes = routes
            .route(&format!("{prefix}/account"), get(page))
            .route(&format!("{prefix}/account/api/session"), get(session))
            .route(
                &format!("{prefix}/account/api/instances/challenge"),
                post(challenge),
            )
            .route(&format!("{prefix}/account/api/instances"), post(register))
            .route(&format!("{prefix}/account/api/intents"), post(intents))
            .route(
                &format!("{prefix}/account/api/proxy/adp/{{*rest}}"),
                post(proxy),
            )
            .route(
                &format!("{prefix}/account/api/{{*rest}}"),
                any(api_not_found),
            )
            .route(&format!("{prefix}/account/{{*rest}}"), get(page));
    }
    crate::harden(routes.with_state(account), limits)
        .layer(axum::middleware::from_fn(headers_layer))
}
