//! The console BFF on axum (TN-128–TN-131, OP-151 m.3 (b), (e), (f)): the built console at
//! `/console`, its API under `/console/api/`, and the two proxies. The cookie is checked on
//! every API call against the console session policy; state-changing calls pass the origin and
//! CSRF checks; the proxies pass on only what the browser signed.

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use access_identity_oauth::domain::issuer::check_slug;
use access_identity_session::domain::console::{
    self as policy, Binding, CONSOLE_COOKIE, CSRF_COOKIE, CSRF_HEADER, ConsoleCheck,
};
use access_identity_session::domain::session::cookie_digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Extension, Router};
use serde_json::json;
use suiss_crypto::digest::sha256;
use suiss_crypto::secret::Secret;

use super::domain::{
    ADMIN_FORWARDED, ADP_FORWARDED, AIS_HEADER, Gate, ProofError, RETURNED, ReadRefusal,
    admin_path, adp_commit, adp_read, adp_read_scope, gate, pick, read_intent, secure,
    unsafe_method, verify_commit, verify_read_proof,
};
use super::ports::{
    ConsoleEnv, ConsoleSession, ConsoleSessions, DeviceAnswer, Devices, DpopKeys, Forward,
    Forwarded, Network, NewConsoleSession, Profiles, ReadGrants, SessionInstance, SignIn,
    Unavailable, Upstream,
};
use crate::login::{Assets, Peer};
use crate::problem::codes;
use crate::product::domain::rfc3339;
use crate::{Limits, Problem};

/// The sign-in hand-off cookie: the realm and the state a sign-in started with. `Lax`, since
/// the hosted login sends the browser back with a top-level navigation from another site.
pub const SIGN_IN_COOKIE: &str = "__Host-access-console-signin";

/// How long a sign-in may take, seconds.
pub const SIGN_IN_TTL_S: u64 = 600;

/// The console's page (TN-113: a path has one spelling, and a trailing slash is an empty
/// segment, so the console is `/console`, its screens `/console/<screen>`).
pub const HOME_PATH: &str = "/console";

/// Where the browser returns from the hosted login.
pub const CALLBACK_PATH: &str = "/console/api/sign-in/callback";

/// A read token the BFF holds for a session, until shortly before it ends.
struct Held {
    token: Secret<Vec<u8>>,
    expires_ms: u64,
}

/// Renew a held token this long before its end.
const RENEW_MS: u64 = 60_000;

/// The console BFF over its ports.
pub struct Console<E> {
    env: E,
    limits: Limits,
    assets: Option<Assets>,
    held: Mutex<HashMap<[u8; 16], Held>>,
}

impl<E: ConsoleEnv> Console<E> {
    /// The BFF over `env`, serving the built console `assets` when given.
    #[must_use]
    pub fn new(env: E, limits: Limits, assets: Option<Assets>) -> Arc<Self> {
        Arc::new(Self {
            env,
            limits,
            assets,
            held: Mutex::new(HashMap::new()),
        })
    }

    /// The ports.
    pub const fn env(&self) -> &E {
        &self.env
    }

    fn forget(&self, session: [u8; 16]) {
        if let Ok(mut held) = self.held.lock() {
            held.remove(&session);
        }
        self.env.dpop().forget(session);
    }
}

type St<E> = State<Arc<Console<E>>>;

/// The console's problems; the shared catalogue's where one fits.
pub mod problems {
    use super::{Problem, StatusCode};

    /// No live console session.
    #[must_use]
    pub fn session_required(reason: Option<&'static str>) -> Problem {
        Problem::new(
            StatusCode::UNAUTHORIZED,
            "console-session-required",
            "Unauthorized",
        )
        .with_reason(reason)
    }

    /// The CSRF token is missing or not the session's (TN-131).
    #[must_use]
    pub fn csrf() -> Problem {
        Problem::new(StatusCode::FORBIDDEN, "csrf-token-invalid", "Forbidden")
    }

    /// `Origin` is not the management origin, or the browser marked the request cross-site.
    #[must_use]
    pub fn origin() -> Problem {
        Problem::new(StatusCode::FORBIDDEN, "origin-not-allowed", "Forbidden")
    }

    /// The session has no device Instance yet (OP-151 m.3 (e)).
    #[must_use]
    pub fn instance_required() -> Problem {
        Problem::new(
            StatusCode::FORBIDDEN,
            "console-instance-required",
            "Forbidden",
        )
    }

    /// The AIS is not by the session's device Instance, or not a read proof for this request.
    #[must_use]
    pub fn proof_rejected() -> Problem {
        Problem::new(StatusCode::FORBIDDEN, "read-proof-rejected", "Forbidden")
    }

    /// A forwarded commit is not one the session's device Instance signed (TN-110, MD-14).
    #[must_use]
    pub fn commit_rejected() -> Problem {
        Problem::new(StatusCode::FORBIDDEN, "commit-ais-rejected", "Forbidden")
    }

    /// A forwarded ADP read names another domain, Party or key than the session's (TN-128).
    #[must_use]
    pub fn read_not_own() -> Problem {
        Problem::new(StatusCode::FORBIDDEN, "read-not-own", "Forbidden")
    }

    /// No read token may be issued to the session.
    #[must_use]
    pub fn read_not_granted() -> Problem {
        Problem::new(StatusCode::FORBIDDEN, "read-not-granted", "Forbidden")
    }

    /// The sign-in did not complete.
    #[must_use]
    pub fn sign_in_failed() -> Problem {
        Problem::new(StatusCode::BAD_REQUEST, "sign-in-failed", "Bad Request")
    }

    /// The draft asked for is not one the console may have (OP-151 m.19 (a)).
    #[must_use]
    pub fn draft(e: crate::console::drafts::DraftError) -> Problem {
        Problem::new(StatusCode::BAD_REQUEST, e.code(), "Bad Request")
    }

    /// DBSC is not available yet (TN-33).
    #[must_use]
    pub fn dbsc() -> Problem {
        Problem::new(
            StatusCode::NOT_IMPLEMENTED,
            "dbsc-not-available",
            "Not Implemented",
        )
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

fn set_cookies<const N: usize>(mut r: Response, cookies: [String; N]) -> Response {
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(&c) {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut found: Option<&str> = None;
    let pairs = headers
        .get_all(header::COOKIE)
        .into_iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| {
            let (n, v) = pair.trim().split_once('=')?;
            Some((n.trim(), v.trim()))
        });
    for (n, v) in pairs {
        if n == name {
            match found {
                Some(prior) if prior != v => return Err(()),
                _ => found = Some(v),
            }
        }
    }
    Ok(found)
}

fn cookie_value(text: &str) -> Option<Secret<[u8; 32]>> {
    let bytes = b64url_decode(text).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok().map(Secret::new)
}

fn random32<E: ConsoleEnv>(env: &E) -> Result<Secret<[u8; 32]>, Unavailable> {
    let mut out = [0u8; 32];
    env.entropy().fill(&mut out)?;
    Ok(Secret::new(out))
}

/// A request's live console session and its cookie value.
struct Live {
    session: ConsoleSession,
    cookie: Secret<[u8; 32]>,
}

fn peer_ip(peer: Option<&Extension<Peer>>) -> Option<IpAddr> {
    peer.map(|Extension(Peer(ip))| *ip)
}

/// TN-129: the cookie's session, checked against the console policy from this client.
async fn live<E: ConsoleEnv>(
    c: &Console<E>,
    headers: &HeaderMap,
    ip: Option<IpAddr>,
) -> Result<Live, Response> {
    let refused = |reason| problems::session_required(reason).into_response();
    let text = match cookie(headers, CONSOLE_COOKIE) {
        Ok(Some(t)) => t,
        Ok(None) => return Err(refused(None)),
        Err(()) => return Err(refused(Some("cookie-ambiguous"))),
    };
    let Some(value) = cookie_value(text) else {
        return Err(refused(None));
    };
    let Some(ip) = ip else {
        return Err(unavailable());
    };
    let env = &c.env;
    let Ok(now) = env.clock().now_ms() else {
        return Err(unavailable());
    };
    let session = match env.sessions().find(cookie_digest(value.expose())).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(refused(None)),
        Err(Unavailable) => return Err(unavailable()),
    };
    let Ok(binding) = env.network().policy(&session.who.realm).await else {
        return Err(unavailable());
    };
    let found = policy::check(&session.facts, ip, env.network().asn(ip), binding, now);
    if found != ConsoleCheck::Valid {
        if !matches!(found, ConsoleCheck::Ended) {
            if env.sessions().end(session.id, now).await.is_err() {
                return Err(unavailable());
            }
            c.forget(session.id);
        }
        // TN-129
        tracing::info!(
            event = "console.session.refused",
            outcome = "refused",
            reason = found.code(),
            "console session not live"
        );
        let r = problems::session_required(Some(found.code())).into_response();
        return Err(set_cookies(r, policy::clear_cookies()));
    }
    if env.sessions().touch(session.id, now).await.is_err() {
        return Err(unavailable());
    }
    Ok(Live {
        session,
        cookie: value,
    })
}

/// TN-131: origin gate, and the CSRF token on every state-changing call.
fn guard_write(
    origin: &str,
    method: &Method,
    headers: &HeaderMap,
    live: &Live,
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
    let Ok(Some(double)) = cookie(headers, CSRF_COOKIE) else {
        return Err(problems::csrf().into_response());
    };
    if policy::csrf_ok(&live.cookie, presented, double) {
        Ok(())
    } else {
        Err(problems::csrf().into_response())
    }
}

/// Every API call: the live session and the gates.
async fn authed<E: ConsoleEnv>(
    c: &Console<E>,
    method: &Method,
    headers: &HeaderMap,
    peer: Option<&Extension<Peer>>,
) -> Result<Live, Response> {
    if gate(headers, method, c.env.origin()) == Gate::CrossSite {
        return Err(problems::origin().into_response());
    }
    let live = live(c, headers, peer_ip(peer)).await?;
    guard_write(c.env.origin(), method, headers, &live)?;
    Ok(live)
}

async fn page<E: ConsoleEnv>(State(c): St<E>) -> Response {
    c.assets
        .as_ref()
        .and_then(Assets::page)
        .unwrap_or_else(not_found)
}

async fn asset<E: ConsoleEnv>(State(c): St<E>, Path(path): Path<String>) -> Response {
    c.assets
        .as_ref()
        .and_then(|a| a.asset(&path))
        .unwrap_or_else(not_found)
}

/// `GET /console/api/session`: who is signed in (TN-128: the identity plane's own data).
async fn session_info<E: ConsoleEnv>(
    State(c): St<E>,
    method: Method,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
) -> Response {
    let live = match authed(&c, &method, &headers, peer.as_ref()).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let s = &live.session;
    let absolute = s.facts.created_ms.saturating_add(policy::ABSOLUTE_MS);
    json_reply(
        StatusCode::OK,
        &json!({
            "account": s.who.account,
            "display_name": s.who.display_name,
            "realm": s.who.realm,
            "domain": b64url_encode(&s.who.domain.0),
            "expires_at": rfc3339(absolute),
            "idle_timeout_s": (policy::IDLE_MS / 1000).to_string(),
            "instance": s.instance.as_ref().map(|i| b64url_encode(&i.kid)),
        }),
    )
}

/// `GET /console/api/about`: the server's version, for the About screen.
async fn about<E: ConsoleEnv>(
    State(c): St<E>,
    method: Method,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
) -> Response {
    if let Err(r) = authed(&c, &method, &headers, peer.as_ref()).await {
        return r;
    }
    json_reply(
        StatusCode::OK,
        &json!({ "server_version": env!("CARGO_PKG_VERSION") }),
    )
}

/// `GET /console/api/csrf`: the session's CSRF token, also set as the double-submit cookie.
async fn csrf<E: ConsoleEnv>(
    State(c): St<E>,
    method: Method,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
) -> Response {
    let live = match authed(&c, &method, &headers, peer.as_ref()).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let token = policy::csrf_token(&live.cookie);
    let r = json_reply(StatusCode::OK, &json!({ "token": token }));
    set_cookies(r, [policy::csrf_cookie(&token)])
}

/// `GET /console/api/sessions`: the account's own sessions (Ek B 3089, cookie only).
async fn sessions<E: ConsoleEnv>(
    State(c): St<E>,
    method: Method,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
) -> Response {
    let live = match authed(&c, &method, &headers, peer.as_ref()).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let Ok(list) = c.env.sessions().list(&live.session).await else {
        return unavailable();
    };
    let items: Vec<_> = list
        .iter()
        .map(|s| {
            json!({
                "id": b64url_encode(&s.id),
                "kind": s.kind,
                "created_at": rfc3339(s.created_ms),
                "last_seen_at": rfc3339(s.last_seen_ms),
                "current": s.id == live.session.id,
            })
        })
        .collect();
    json_reply(StatusCode::OK, &json!({ "sessions": items }))
}

/// `POST /console/api/sessions/{id}/revoke`: ends one of the account's own sessions; a
/// self-action of the identity plane, so the cookie and the CSRF token suffice (TN-128).
async fn revoke<E: ConsoleEnv>(
    State(c): St<E>,
    method: Method,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
    Path(id): Path<String>,
) -> Response {
    let live = match authed(&c, &method, &headers, peer.as_ref()).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let Some(target) = b64url_decode(&id)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
    else {
        return not_found();
    };
    let Ok(now) = c.env.clock().now_ms() else {
        return unavailable();
    };
    match c.env.sessions().revoke(&live.session, target, now).await {
        Ok(true) => {}
        Ok(false) => return not_found(),
        Err(Unavailable) => return unavailable(),
    }
    tracing::info!(
        event = "console.session.revoked",
        outcome = "ok",
        "own session revoked"
    );
    let r = no_store(StatusCode::NO_CONTENT.into_response());
    if target == live.session.id {
        c.forget(target);
        return set_cookies(r, policy::clear_cookies());
    }
    r
}

/// `GET /console/api/profile`: the account's own profile, read only.
async fn profile<E: ConsoleEnv>(
    State(c): St<E>,
    method: Method,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
) -> Response {
    let live = match authed(&c, &method, &headers, peer.as_ref()).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    match c.env.profiles().profile(&live.session).await {
        Ok(Some(p)) => json_reply(StatusCode::OK, &p),
        Ok(None) => not_found(),
        Err(Unavailable) => unavailable(),
    }
}

fn query_value<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    query?
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find_map(|(k, v)| (k == name).then_some(v))
}

/// `GET /console/api/sign-in?realm=<slug>`: to the realm's hosted login, which returns to
/// [`CALLBACK_PATH`].
async fn sign_in<E: ConsoleEnv>(State(c): St<E>, uri: Uri) -> Response {
    let Some(realm) = query_value(uri.query(), "realm").filter(|r| check_slug(r).is_ok()) else {
        return problems::sign_in_failed().into_response();
    };
    let Ok(state) = random32(&c.env) else {
        return unavailable();
    };
    let state = b64url_encode(state.expose());
    let callback = format!("{}{CALLBACK_PATH}", c.env.origin());
    let url = match c.env.sign_in().start(realm, &state, &callback).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found(),
        Err(Unavailable) => return unavailable(),
    };
    let Ok(location) = HeaderValue::from_str(&url) else {
        return unavailable();
    };
    let mut r = no_store(StatusCode::SEE_OTHER.into_response());
    r.headers_mut().insert(header::LOCATION, location);
    set_cookies(
        r,
        [format!(
            "{SIGN_IN_COOKIE}={realm}.{state}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={SIGN_IN_TTL_S}"
        )],
    )
}

fn clear_sign_in() -> String {
    format!("{SIGN_IN_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// `GET /console/api/sign-in/callback`: opens the console session under the console policy
/// (TN-129) and returns to the console.
async fn callback<E: ConsoleEnv>(
    State(c): St<E>,
    uri: Uri,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
) -> Response {
    let failed = || {
        set_cookies(
            problems::sign_in_failed().into_response(),
            [clear_sign_in()],
        )
    };
    let Ok(Some(started)) = cookie(&headers, SIGN_IN_COOKIE) else {
        return failed();
    };
    let Some((realm, state)) = started.split_once('.') else {
        return failed();
    };
    let Some(ip) = peer_ip(peer.as_ref()) else {
        return unavailable();
    };
    let env = &c.env;
    let who = match env
        .sign_in()
        .finish(realm, state, uri.query().unwrap_or_default())
        .await
    {
        Ok(Some(w)) if w.realm == realm => w,
        Ok(_) => return failed(),
        Err(Unavailable) => return unavailable(),
    };
    let (Ok(now), Ok(binding), Ok(value)) = (
        env.clock().now_ms(),
        env.network().policy(realm).await,
        random32(env),
    ) else {
        return unavailable();
    };
    let new = NewConsoleSession {
        cookie_digest: cookie_digest(value.expose()),
        who,
        binding: Binding::of(ip, env.network().asn(ip), binding),
        now_ms: now,
    };
    if env.sessions().open(new).await.is_err() {
        return unavailable();
    }
    tracing::info!(
        event = "console.session.opened",
        outcome = "ok",
        "console session opened"
    );
    let text = b64url_encode(value.expose());
    let token = policy::csrf_token(&value);
    let mut r = no_store(StatusCode::SEE_OTHER.into_response());
    r.headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(HOME_PATH));
    set_cookies(
        r,
        [
            policy::session_cookie(&text),
            policy::csrf_cookie(&token),
            clear_sign_in(),
        ],
    )
}

/// `POST /console/api/sign-out`.
async fn sign_out<E: ConsoleEnv>(
    State(c): St<E>,
    method: Method,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
) -> Response {
    let live = match authed(&c, &method, &headers, peer.as_ref()).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let Ok(now) = c.env.clock().now_ms() else {
        return unavailable();
    };
    if c.env.sessions().end(live.session.id, now).await.is_err() {
        return unavailable();
    }
    c.forget(live.session.id);
    set_cookies(
        no_store(StatusCode::NO_CONTENT.into_response()),
        policy::clear_cookies(),
    )
}

fn device_reply(a: &DeviceAnswer) -> Response {
    json_reply(
        StatusCode::from_u16(a.status).unwrap_or(StatusCode::BAD_GATEWAY),
        &a.body,
    )
}

/// `POST /console/api/instances/challenge` (OP-149 m.6): a challenge for the browser's key.
async fn challenge<E: ConsoleEnv>(
    State(c): St<E>,
    method: Method,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
    body: Bytes,
) -> Response {
    let live = match authed(&c, &method, &headers, peer.as_ref()).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    if live.session.instance.is_some() {
        return Problem::new(StatusCode::CONFLICT, "instance-exists", "Conflict").into_response();
    }
    match c.env.devices().challenge(&live.session, body).await {
        Ok(a) => device_reply(&a),
        Err(Unavailable) => unavailable(),
    }
}

/// `POST /console/api/instances` (OP-149 m.6, OP-151 m.3 (e)): registers the browser's key as
/// the session's device Instance through its own `instance_create` Exercise.
async fn register<E: ConsoleEnv>(
    State(c): St<E>,
    method: Method,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
    body: Bytes,
) -> Response {
    let live = match authed(&c, &method, &headers, peer.as_ref()).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    if live.session.instance.is_some() {
        return Problem::new(StatusCode::CONFLICT, "instance-exists", "Conflict").into_response();
    }
    let answer = match c.env.devices().register(&live.session, body).await {
        Ok(a) => a,
        Err(Unavailable) => return unavailable(),
    };
    if let Some(instance) = answer.instance.clone()
        && c.env
            .sessions()
            .attach(live.session.id, instance)
            .await
            .is_err()
    {
        return unavailable();
    }
    device_reply(&answer)
}

fn forwarded(f: Forwarded) -> Response {
    let mut r = (
        StatusCode::from_u16(f.status).unwrap_or(StatusCode::BAD_GATEWAY),
        f.body,
    )
        .into_response();
    r.headers_mut().remove(header::CONTENT_TYPE);
    for (name, value) in pick(&f.headers, &RETURNED) {
        r.headers_mut().append(name, value);
    }
    no_store(r)
}

fn single_ais(headers: &HeaderMap) -> Result<Vec<u8>, Response> {
    let values: Vec<&str> = headers
        .get_all(AIS_HEADER)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    crate::api::domain::caller::ais_bytes(&values, b"")
        .map_err(|_| codes::AIS_REQUIRED.problem().into_response())
}

fn path_and_query(path: &str, uri: &Uri) -> String {
    match uri.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_owned(),
    }
}

/// The session's read token, held or newly issued to its device Instance and bound to the
/// BFF's DPoP key of the session (TN-130, OP-151 m.3 (c)).
async fn read_token<E: ConsoleEnv>(
    c: &Console<E>,
    session: &ConsoleSession,
    instance: &SessionInstance,
    now: u64,
) -> Result<Option<Secret<Vec<u8>>>, Unavailable> {
    if let Ok(held) = c.held.lock()
        && let Some(h) = held.get(&session.id)
        && h.expires_ms > now.saturating_add(RENEW_MS)
    {
        return Ok(Some(h.token.clone()));
    }
    let jkt = c.env.dpop().jkt(session.id)?;
    let Some(issued) = c.env.grants().issue(session, instance, jkt).await? else {
        return Ok(None);
    };
    let token = issued.token.clone();
    let mut held = c.held.lock().map_err(|_| Unavailable)?;
    held.insert(
        session.id,
        Held {
            token: issued.token,
            expires_ms: issued.expires_ms,
        },
    );
    Ok(Some(token))
}

/// `/console/api/proxy/admin/{rest}` → `/admin/v1/{rest}` (TN-128, OP-151 m.3 (c), (e)). Only
/// with the browser's AIS: a write passes it on for the management API to verify and compile
/// into an Exercise, and never carries a token; a read, and the `POST …/intents` draft that is
/// one (OP-151 m.11 (a)), is a read proof by the session's device Instance, and only then does
/// the BFF present the session's read token.
async fn admin_proxy<E: ConsoleEnv>(
    State(c): St<E>,
    peer: Option<Extension<Peer>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let (method, headers, uri) = (&parts.method, &parts.headers, &parts.uri);
    let live = match authed(&c, method, headers, peer.as_ref()).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let Some(rest) = uri.path().strip_prefix("/console/api/proxy/admin/") else {
        return not_found();
    };
    if !admin_path(rest) {
        return not_found();
    }
    let ais = match single_ais(headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Some(instance) = live.session.instance.clone() else {
        return problems::instance_required().into_response();
    };
    let Ok(body) = axum::body::to_bytes(body, c.limits.max_body_bytes).await else {
        return codes::BODY_TOO_LARGE.problem().into_response();
    };
    let path = format!("/admin/v1/{rest}");
    let target = path_and_query(&path, uri);
    let Ok(now) = c.env.clock().now_ms() else {
        return unavailable();
    };
    let mut forward = Forward {
        method: method.clone(),
        path_and_query: target.clone(),
        headers: pick(headers, &ADMIN_FORWARDED),
        body,
    };
    // OP-151 m.11 (a)
    let drafting = *method == Method::POST && rest.ends_with("/intents");
    if unsafe_method(method) && !drafting {
        // MD-14
        match crate::api::domain::caller::ais_kid(&ais) {
            Ok(kid) if kid == instance.kid => {}
            _ => return problems::proof_rejected().into_response(),
        }
    } else {
        let intent = read_intent(method, &target);
        match verify_read_proof(
            &ais,
            Some((&instance.kid, &instance.key)),
            &live.session.who.domain,
            &intent,
            now,
        ) {
            Ok(_) => {}
            Err(ProofError::NoInstance) => return problems::instance_required().into_response(),
            Err(ProofError::Rejected) => return problems::proof_rejected().into_response(),
        }
        let token = match read_token(&c, &live.session, &instance, now).await {
            Ok(Some(t)) => t,
            Ok(None) => return problems::read_not_granted().into_response(),
            Err(Unavailable) => return unavailable(),
        };
        let htu = format!("{}{path}", c.env.origin());
        let ath = sha256(token.expose());
        let Ok(proof) = c
            .env
            .dpop()
            .proof(live.session.id, method.as_str(), &htu, &ath, now)
        else {
            return unavailable();
        };
        let (Ok(text), Ok(proof)) = (
            String::from_utf8(token.expose().clone()),
            HeaderValue::from_str(&proof),
        ) else {
            return unavailable();
        };
        let Ok(authorization) = HeaderValue::from_str(&format!("DPoP {text}")) else {
            return unavailable();
        };
        forward.headers.retain(|(n, _)| *n != AIS_HEADER);
        forward.headers.push((header::AUTHORIZATION, authorization));
        forward
            .headers
            .push((axum::http::HeaderName::from_static("dpop"), proof));
    }
    match c.env.upstream().admin(forward).await {
        Ok(f) => forwarded(f),
        Err(Unavailable) => unavailable(),
    }
}

/// TN-128, OP-151 m.12 (e): a forwarded read names the session's own domain, an eligibility
/// check the session's own Party, an AIS the session's own device Instance.
async fn own_read<E: ConsoleEnv>(
    c: &Console<E>,
    session: &ConsoleSession,
    rest: &str,
    body: &[u8],
    headers: &HeaderMap,
) -> Result<(), Response> {
    let party = if rest == "eligibility:check" {
        match c.env.devices().party(session).await {
            Ok(p) => p,
            Err(Unavailable) => return Err(unavailable()),
        }
    } else {
        None
    };
    let instance = session.instance.as_ref().map(|i| &i.kid);
    match adp_read_scope(
        rest,
        body,
        c.limits.max_body_bytes,
        &session.who.domain,
        party,
        instance,
    ) {
        Ok(()) => Ok(()),
        Err(ReadRefusal::Malformed(e, kind)) => Err(crate::adp::adapters::respond(
            crate::adp::app::bad(e, kind),
            headers,
        )),
        Err(ReadRefusal::Foreign) => {
            tracing::info!(
                event = "console.adp.refused",
                outcome = "refused",
                "forwarded read is not the session's own"
            );
            Err(problems::read_not_own().into_response())
        }
    }
}

/// `POST /console/api/proxy/adp/{rest}` → `/access/v1/{rest}` (TN-128): explain, search and
/// the eligibility check go on as the browser wrote them, with the AIS they carry or none; the
/// BFF adds no credential of its own, so a request without the browser's AIS is the anonymous
/// reader's and sees Public only. `evaluation` and `audit/export` go on only as a `commit` whose
/// AIS the session's device Instance signed (TN-110, OP-151 m.19): the single write path is ADP
/// `commit` with the browser's statement, and the BFF never signs.
async fn adp_proxy<E: ConsoleEnv>(
    State(c): St<E>,
    peer: Option<Extension<Peer>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let (method, headers, uri) = (&parts.method, &parts.headers, &parts.uri);
    let live = match authed(&c, method, headers, peer.as_ref()).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let Some(rest) = uri.path().strip_prefix("/console/api/proxy/adp/") else {
        return not_found();
    };
    let commit = adp_commit(rest);
    if !(adp_read(rest) || commit) || uri.query().is_some() {
        return not_found();
    }
    let Ok(body) = axum::body::to_bytes(body, c.limits.max_body_bytes).await else {
        return codes::BODY_TOO_LARGE.problem().into_response();
    };
    if commit {
        let Ok(now) = c.env.clock().now_ms() else {
            return unavailable();
        };
        let instance = live.session.instance.as_ref().map(|i| (&i.kid, &i.key));
        match verify_commit(&body, instance, &live.session.who.domain, now) {
            Ok(_) => {}
            Err(ProofError::NoInstance) => return problems::instance_required().into_response(),
            Err(ProofError::Rejected) => return problems::commit_rejected().into_response(),
        }
    } else if let Err(r) = own_read(&c, &live.session, rest, &body, headers).await {
        return r;
    }
    let forward = Forward {
        method: Method::POST,
        path_and_query: format!("/access/v1/{rest}"),
        headers: pick(headers, &ADP_FORWARDED),
        body,
    };
    // OP-141 m.23 (a)
    let requester = b64url_encode(&live.session.id);
    match c.env.upstream().adp(forward, requester).await {
        Ok(f) => forwarded(f),
        Err(Unavailable) => unavailable(),
    }
}

/// The path of the intent draft route.
pub const INTENTS_PATH: &str = "/console/api/intents";

/// `POST /console/api/intents` (OP-151 m.19 (a), PI-7): drafts the intent a screen asks for,
/// `{action, resources, params?, mode}` → `{intent, envelope}`, for the session's realm. A read
/// that changes nothing, so it is gated like one: the live session, the CSRF token and a read
/// proof by the session's device Instance over this very request (OP-151 m.12 (c)).
async fn intents<E: ConsoleEnv>(
    State(c): St<E>,
    method: Method,
    headers: HeaderMap,
    peer: Option<Extension<Peer>>,
    body: Bytes,
) -> Response {
    let live = match authed(&c, &method, &headers, peer.as_ref()).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let ais = match single_ais(&headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Ok(now) = c.env.clock().now_ms() else {
        return unavailable();
    };
    let instance = live.session.instance.as_ref().map(|i| (&i.kid, &i.key));
    match verify_read_proof(
        &ais,
        instance,
        &live.session.who.domain,
        &read_intent(&Method::POST, INTENTS_PATH),
        now,
    ) {
        Ok(_) => {}
        Err(ProofError::NoInstance) => return problems::instance_required().into_response(),
        Err(ProofError::Rejected) => return problems::proof_rejected().into_response(),
    }
    // OP-151 m.20 (a)
    let tenant = match super::drafts::asked_action(&body) {
        Some((namespace, name, major)) => match c
            .env
            .accepted()
            .action(live.session.who.domain, &namespace, &name, major)
            .await
        {
            Ok(t) => t,
            Err(Unavailable) => return unavailable(),
        },
        None => None,
    };
    match super::drafts::draft_with(&body, &live.session.who.realm, now, tenant.as_ref()) {
        Ok(d) => json_reply(StatusCode::OK, &d.answer(&live.session.who.domain)),
        Err(e) => problems::draft(e).into_response(),
    }
}

/// `/console/api/dbsc/*` (TN-33): the session row keeps a slot for a device-bound key, and the
/// `Sec-Session-*` registration and refresh answer `501` until DBSC is implemented.
async fn dbsc() -> Response {
    problems::dbsc().into_response()
}

async fn api_not_found() -> Response {
    not_found()
}

async fn headers_layer(request: Request, next: Next) -> Response {
    let mut r = next.run(request).await;
    secure(r.headers_mut());
    r
}

/// The console routes: `/console`, its screens and assets, `/console/api/*` and the proxies, every
/// answer with the console's security headers (TN-131).
pub fn router<E: ConsoleEnv>(console: &Arc<Console<E>>) -> Router {
    let routes = Router::new()
        .route(HOME_PATH, get(page::<E>))
        .route("/console/assets/{*path}", get(asset::<E>))
        .route("/console/api/session", get(session_info::<E>))
        .route("/console/api/csrf", get(csrf::<E>))
        .route("/console/api/about", get(about::<E>))
        .route("/console/api/sessions", get(sessions::<E>))
        .route("/console/api/sessions/{id}/revoke", post(revoke::<E>))
        .route("/console/api/profile", get(profile::<E>))
        .route("/console/api/sign-in", get(sign_in::<E>))
        .route(CALLBACK_PATH, get(callback::<E>))
        .route("/console/api/sign-out", post(sign_out::<E>))
        .route("/console/api/instances/challenge", post(challenge::<E>))
        .route("/console/api/instances", post(register::<E>))
        .route(INTENTS_PATH, post(intents::<E>))
        .route("/console/api/proxy/admin/{*rest}", any(admin_proxy::<E>))
        .route("/console/api/proxy/adp/{*rest}", post(adp_proxy::<E>))
        .route("/console/api/dbsc/{*rest}", any(dbsc))
        .route("/console/api/{*rest}", any(api_not_found))
        .route("/console/{*rest}", get(page::<E>))
        .with_state(console.clone());
    crate::harden(routes, console.limits).layer(axum::middleware::from_fn(headers_layer))
}
