//! The console BFF over fake ports (TN-128–TN-131, OP-151 m.3 (e), (f), (s), Ek B 2969, 2973,
//! 3017, 3087, 3088, 3089, 3266, 3339).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::unused_async_trait_impl,
    clippy::panic,
    clippy::map_unwrap_or,
    clippy::indexing_slicing,
    reason = "test"
)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use access_http::Limits;
use access_http::console::domain::read_intent;
use access_http::console::ports::{
    Clock, ConsoleEnv, ConsoleSession, ConsoleSessions, DeviceAnswer, Devices, DpopKeys, Entropy,
    Forward, Forwarded, IssuedRead, Network, NewConsoleSession, Profiles, ReadGrants,
    SessionInstance, SessionSummary, SignIn, SignedIn, Unavailable, Upstream,
};
use access_http::console::{Console, router};
use access_http::login::{Assets, Peer};
use access_identity_session::domain::console::{
    BindingPolicy, CONSOLE_COOKIE, CSRF_COOKIE, ConsoleFacts, IDLE_MS, csrf_token,
};
use access_identity_session::domain::session::cookie_digest;
use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Id;
use access_kernel::verify::key_scope::thumbprint;
use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};
use tower::ServiceExt;

const ORIGIN: &str = "https://access-server:9443";
const T0: u64 = 1_800_000_000_000;
const DOMAIN: Digest = Digest([3; 32]);
const CLIENT: &str = "198.51.100.7";
const PARTY: [u8; 16] = [9; 16];

struct FakeClock(AtomicU64);

impl Clock for FakeClock {
    fn now_ms(&self) -> Result<u64, Unavailable> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct Counter(AtomicU64);

impl Entropy for Counter {
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        let n = self.0.fetch_add(1, Ordering::SeqCst).to_be_bytes();
        out.fill(0xA5);
        for (d, s) in out.iter_mut().zip(n) {
            *d = s;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Sessions {
    rows: Mutex<HashMap<[u8; 32], ConsoleSession>>,
    down: AtomicBool,
    next: AtomicU64,
}

impl Sessions {
    fn up(&self) -> Result<(), Unavailable> {
        if self.down.load(Ordering::SeqCst) {
            Err(Unavailable)
        } else {
            Ok(())
        }
    }

    fn with<T>(&self, id: [u8; 16], f: impl FnOnce(&mut ConsoleSession) -> T) -> Option<T> {
        let mut rows = self.rows.lock().unwrap();
        rows.values_mut().find(|s| s.id == id).map(f)
    }
}

impl ConsoleSessions for Sessions {
    async fn open(&self, new: NewConsoleSession) -> Result<[u8; 16], Unavailable> {
        self.up()?;
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&self.next.fetch_add(1, Ordering::SeqCst).to_be_bytes());
        self.rows.lock().unwrap().insert(
            new.cookie_digest,
            ConsoleSession {
                id,
                who: new.who,
                facts: ConsoleFacts {
                    created_ms: new.now_ms,
                    last_seen_ms: new.now_ms,
                    revoked: false,
                    ended: false,
                    binding: new.binding,
                },
                instance: None,
                dbsc: None,
            },
        );
        Ok(id)
    }

    async fn find(&self, digest: [u8; 32]) -> Result<Option<ConsoleSession>, Unavailable> {
        self.up()?;
        Ok(self.rows.lock().unwrap().get(&digest).cloned())
    }

    async fn touch(&self, id: [u8; 16], now_ms: u64) -> Result<(), Unavailable> {
        self.up()?;
        self.with(id, |s| s.facts.last_seen_ms = now_ms);
        Ok(())
    }

    async fn end(&self, id: [u8; 16], _: u64) -> Result<(), Unavailable> {
        self.up()?;
        self.with(id, |s| s.facts.ended = true);
        Ok(())
    }

    async fn attach(&self, id: [u8; 16], instance: SessionInstance) -> Result<(), Unavailable> {
        self.up()?;
        self.with(id, |s| s.instance = Some(instance));
        Ok(())
    }

    async fn list(&self, session: &ConsoleSession) -> Result<Vec<SessionSummary>, Unavailable> {
        self.up()?;
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .values()
            .filter(|s| s.who.account == session.who.account && !s.facts.ended)
            .map(|s| SessionSummary {
                id: s.id,
                kind: "console",
                created_ms: s.facts.created_ms,
                last_seen_ms: s.facts.last_seen_ms,
            })
            .collect())
    }

    async fn revoke(
        &self,
        session: &ConsoleSession,
        target: [u8; 16],
        _: u64,
    ) -> Result<bool, Unavailable> {
        self.up()?;
        let mut rows = self.rows.lock().unwrap();
        let Some(s) = rows
            .values_mut()
            .find(|s| s.id == target && s.who.account == session.who.account)
        else {
            return Ok(false);
        };
        s.facts.ended = true;
        Ok(true)
    }
}

struct Hosted;

fn who(account: &str) -> SignedIn {
    SignedIn {
        realm: "acme".to_owned(),
        domain: DOMAIN,
        account: account.to_owned(),
        display_name: "<b>Ada</b>".to_owned(),
        subject: [1; 16],
        login_session: [2; 16],
        auth_time_ms: 1,
    }
}

impl SignIn for Hosted {
    async fn start(
        &self,
        realm: &str,
        state: &str,
        callback: &str,
    ) -> Result<Option<String>, Unavailable> {
        Ok((realm == "acme")
            .then(|| format!("https://acme.example/login?state={state}&cb={callback}")))
    }

    async fn finish(
        &self,
        _: &str,
        state: &str,
        query: &str,
    ) -> Result<Option<SignedIn>, Unavailable> {
        Ok((query == format!("state={state}&code=good")).then(|| who("acc_ada")))
    }
}

#[derive(Default)]
struct Net {
    full_ip: AtomicBool,
}

impl Network for Net {
    fn asn(&self, _: IpAddr) -> Option<u32> {
        None
    }

    async fn policy(&self, _: &str) -> Result<BindingPolicy, Unavailable> {
        Ok(BindingPolicy {
            full_ip: self.full_ip.load(Ordering::SeqCst),
        })
    }
}

struct Profile;

impl Profiles for Profile {
    async fn profile(&self, s: &ConsoleSession) -> Result<Option<serde_json::Value>, Unavailable> {
        Ok(Some(serde_json::json!({ "account": s.who.account })))
    }
}

struct Device(SessionInstance);

impl Devices for Device {
    async fn challenge(&self, _: &ConsoleSession, _: Bytes) -> Result<DeviceAnswer, Unavailable> {
        Ok(DeviceAnswer {
            status: 201,
            body: serde_json::json!({ "challenge": "c" }),
            instance: None,
        })
    }

    async fn register(&self, _: &ConsoleSession, body: Bytes) -> Result<DeviceAnswer, Unavailable> {
        let ok = body.as_ref() == b"{\"ok\":true}";
        Ok(DeviceAnswer {
            status: if ok { 201 } else { 400 },
            body: serde_json::json!({}),
            instance: ok.then(|| self.0.clone()),
        })
    }

    async fn party(&self, _: &ConsoleSession) -> Result<Option<[u8; 16]>, Unavailable> {
        Ok(Some(PARTY))
    }
}

#[derive(Default)]
struct Grants {
    issued: AtomicU64,
    refuse: AtomicBool,
}

impl ReadGrants for Grants {
    async fn issue(
        &self,
        _: &ConsoleSession,
        _: &SessionInstance,
        jkt: [u8; 32],
    ) -> Result<Option<IssuedRead>, Unavailable> {
        if self.refuse.load(Ordering::SeqCst) {
            return Ok(None);
        }
        self.issued.fetch_add(1, Ordering::SeqCst);
        Ok(Some(IssuedRead {
            token: Secret::new(format!("tok-{}", b64url_encode(&jkt)).into_bytes()),
            expires_ms: T0 + 3_600_000,
        }))
    }
}

struct Dpop;

impl DpopKeys for Dpop {
    fn jkt(&self, session: [u8; 16]) -> Result<[u8; 32], Unavailable> {
        let mut out = [7u8; 32];
        out[..16].copy_from_slice(&session);
        Ok(out)
    }

    fn proof(
        &self,
        _: [u8; 16],
        method: &str,
        htu: &str,
        _: &[u8; 32],
        _: u64,
    ) -> Result<String, Unavailable> {
        Ok(format!("proof {method} {htu}"))
    }

    fn forget(&self, _: [u8; 16]) {}
}

#[derive(Default)]
struct Up {
    seen: Mutex<Vec<(&'static str, Forward)>>,
    requesters: Mutex<Vec<String>>,
}

impl Up {
    fn take(&self) -> Vec<(&'static str, Forward)> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }

    fn answer() -> Forwarded {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("set-cookie", "upstream=1".parse().unwrap());
        headers.insert("request-id", "rid".parse().unwrap());
        Forwarded {
            status: 200,
            headers,
            body: Bytes::from_static(b"{}"),
        }
    }
}

impl Upstream for Up {
    async fn admin(&self, request: Forward) -> Result<Forwarded, Unavailable> {
        self.seen.lock().unwrap().push(("admin", request));
        Ok(Self::answer())
    }

    async fn adp(&self, request: Forward, requester: String) -> Result<Forwarded, Unavailable> {
        self.requesters.lock().unwrap().push(requester);
        self.seen.lock().unwrap().push(("adp", request));
        Ok(Self::answer())
    }
}

struct Env {
    clock: FakeClock,
    entropy: Counter,
    sessions: Sessions,
    net: Net,
    device: Device,
    grants: Grants,
    up: Up,
}

impl ConsoleEnv for Env {
    type Sessions = Sessions;
    type SignIn = Hosted;
    type Network = Net;
    type Profiles = Profile;
    type Devices = Device;
    type Grants = Grants;
    type Dpop = Dpop;
    type Upstream = Up;

    fn clock(&self) -> &dyn Clock {
        &self.clock
    }
    fn entropy(&self) -> &dyn Entropy {
        &self.entropy
    }
    fn sessions(&self) -> &Sessions {
        &self.sessions
    }
    fn sign_in(&self) -> &Hosted {
        &Hosted
    }
    fn network(&self) -> &Net {
        &self.net
    }
    fn profiles(&self) -> &Profile {
        &Profile
    }
    fn devices(&self) -> &Device {
        &self.device
    }
    fn grants(&self) -> &Grants {
        &self.grants
    }
    fn dpop(&self) -> &Dpop {
        &Dpop
    }
    fn upstream(&self) -> &Up {
        &self.up
    }
    fn origin(&self) -> &str {
        ORIGIN
    }
}

struct Harness {
    console: Arc<Console<Env>>,
    router: Router,
    key: SoftSigner,
}

impl Harness {
    fn new() -> Self {
        Self::serving(None)
    }

    fn serving(assets: Option<Assets>) -> Self {
        let (key, _) = SoftSigner::generate_p256().unwrap();
        let instance = SessionInstance {
            kid: thumbprint(&key.public_key()),
            key: key.public_key(),
        };
        let env = Env {
            clock: FakeClock(AtomicU64::new(T0)),
            entropy: Counter(AtomicU64::new(1)),
            sessions: Sessions::default(),
            net: Net::default(),
            device: Device(instance),
            grants: Grants::default(),
            up: Up::default(),
        };
        let console = Console::new(env, Limits::default(), assets);
        let router = router(&console);
        Self {
            console,
            router,
            key,
        }
    }

    fn env(&self) -> &Env {
        self.console.env()
    }

    fn advance(&self, ms: u64) {
        self.env().clock.0.fetch_add(ms, Ordering::SeqCst);
    }

    fn now(&self) -> u64 {
        self.env().clock.0.load(Ordering::SeqCst)
    }

    async fn send(&self, mut request: Request<Body>, ip: &str) -> (Response<Body>, Vec<u8>) {
        request.extensions_mut().insert(Peer(ip.parse().unwrap()));
        let response = self.router.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, 1 << 20).await.unwrap().to_vec();
        (Response::from_parts(parts, Body::empty()), bytes)
    }

    /// Signs in through the hosted login hand-off and returns the cookie header.
    async fn sign_in(&self) -> Session {
        let (r, _) = self
            .send(get("/console/api/sign-in?realm=acme", None), CLIENT)
            .await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        let started = set_cookie(&r, "__Host-access-console-signin");
        let state = started.split_once('.').unwrap().1.to_owned();
        let callback = Request::get(format!(
            "/console/api/sign-in/callback?state={state}&code=good"
        ))
        .header("cookie", format!("__Host-access-console-signin={started}"))
        .body(Body::empty())
        .unwrap();
        let (r, _) = self.send(callback, CLIENT).await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(r.headers()["location"], "/console");
        let value = set_cookie(&r, CONSOLE_COOKIE);
        let csrf = set_cookie(&r, CSRF_COOKIE);
        Session { value, csrf }
    }

    async fn with_instance(&self) -> Session {
        let s = self.sign_in().await;
        let (r, _) = self
            .send(s.post("/console/api/instances", "{\"ok\":true}"), CLIENT)
            .await;
        assert_eq!(r.status(), StatusCode::CREATED);
        s
    }

    fn ais(&self, mode: Mode, intent: Digest, iat: u64) -> String {
        ais_by(&self.key, mode, intent, iat)
    }
}

fn ais_by(key: &SoftSigner, mode: Mode, intent: Digest, iat: u64) -> String {
    let statement = Statement {
        domain: DOMAIN,
        nonce: vec![1; 16],
        intent,
        mode,
        pep: "access-console".to_owned(),
        capacity: Capacity::Own,
        basis: ExerciseBasis::Public(Id([1; 16])),
        iat,
        exercise: None,
    };
    let sign1 = sign_sign1(
        key as &dyn Signer,
        thumbprint(&key.public_key()),
        CONTENT_TYPE,
        &statement.to_bytes().unwrap(),
    )
    .unwrap();
    b64url_encode(&sign1)
}

struct Session {
    value: String,
    csrf: String,
}

impl Session {
    fn cookie(&self) -> String {
        format!(
            "{CONSOLE_COOKIE}={}; {CSRF_COOKIE}={}",
            self.value, self.csrf
        )
    }

    fn get(&self, path: &str) -> Request<Body> {
        get(path, Some(&self.cookie()))
    }

    fn post(&self, path: &str, body: &'static str) -> Request<Body> {
        Request::post(path)
            .header("cookie", self.cookie())
            .header("origin", ORIGIN)
            .header("x-csrf-token", &self.csrf)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }
}

fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::get(path);
    if let Some(c) = cookie {
        b = b.header("cookie", c);
    }
    b.body(Body::empty()).unwrap()
}

fn set_cookie(r: &Response<Body>, name: &str) -> String {
    r.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .find_map(|c| c.strip_prefix(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap().to_owned())
        .unwrap_or_else(|| panic!("no {name} cookie"))
}

fn set_cookie_line(r: &Response<Body>, name: &str) -> String {
    r.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .find(|c| c.starts_with(&format!("{name}=")))
        .unwrap()
}

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap()
}

// TN-128, TN-129, TN-33: the hand-off opens a console session with a strict host-only cookie
#[tokio::test]
async fn sign_in_opens_a_strict_console_session() {
    let h = Harness::new();
    let (r, _) = h
        .send(get("/console/api/sign-in?realm=acme", None), CLIENT)
        .await;
    let line = set_cookie_line(&r, "__Host-access-console-signin");
    assert!(
        line.contains("SameSite=Lax") && line.contains("HttpOnly") && line.contains("Max-Age=600")
    );
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("cb=https://access-server:9443/console/api/sign-in/callback")
    );
    let s = h.sign_in().await;
    let (r, body) = h.send(s.get("/console/api/session"), CLIENT).await;
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(&body);
    assert_eq!(v["account"], "acc_ada");
    assert_eq!(v["realm"], "acme");
    assert_eq!(v["domain"], b64url_encode(&DOMAIN.0));
    assert_eq!(v["display_name"], "<b>Ada</b>");
    assert_eq!(v["idle_timeout_s"], "900");
    assert!(v["instance"].is_null());
    assert_eq!(r.headers()["cache-control"], "no-store");
    for bad in ["/console/api/sign-in", "/console/api/sign-in?realm=A!"] {
        let (r, _) = h.send(get(bad, None), CLIENT).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }
}

// TN-131: a callback without the state this browser started with opens nothing
#[tokio::test]
async fn a_forged_callback_opens_nothing() {
    let h = Harness::new();
    let (r, _) = h
        .send(
            get("/console/api/sign-in/callback?state=x&code=good", None),
            CLIENT,
        )
        .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let forged = Request::get("/console/api/sign-in/callback?state=x&code=good")
        .header("cookie", "__Host-access-console-signin=acme.y")
        .body(Body::empty())
        .unwrap();
    let (r, _) = h.send(forged, CLIENT).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(h.env().sessions.rows.lock().unwrap().is_empty());
}

// TN-129, OP-151 m.3 (f): 15 minutes idle ends the session
#[tokio::test]
async fn idle_sessions_end_after_fifteen_minutes() {
    let h = Harness::new();
    let s = h.sign_in().await;
    h.advance(IDLE_MS - 1);
    let (r, _) = h.send(s.get("/console/api/session"), CLIENT).await;
    assert_eq!(r.status(), StatusCode::OK);
    h.advance(IDLE_MS);
    let (r, body) = h.send(s.get("/console/api/session"), CLIENT).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["reason"], "idle-expired");
    assert!(set_cookie_line(&r, CONSOLE_COOKIE).contains("Max-Age=0"));
    let (r, body) = h.send(s.get("/console/api/session"), CLIENT).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["code"], "console-session-required");
}

// TN-129, OP-151 m.3 (f): 12 hours absolute, however busy
#[tokio::test]
async fn sessions_end_after_twelve_hours() {
    let h = Harness::new();
    let s = h.sign_in().await;
    for _ in 0..48 {
        h.advance(15 * 60_000 - 1);
        h.send(s.get("/console/api/session"), CLIENT).await;
    }
    h.advance(1_000);
    let (r, body) = h.send(s.get("/console/api/session"), CLIENT).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["reason"], "expired");
}

// TN-129, OP-151 m.1 (b): bound to the /24 without a `GeoResolver` source; the realm may bind the address
#[tokio::test]
async fn sessions_are_bound_to_the_network() {
    let h = Harness::new();
    let s = h.sign_in().await;
    let (r, _) = h
        .send(s.get("/console/api/session"), "198.51.100.200")
        .await;
    assert_eq!(r.status(), StatusCode::OK);
    let (r, body) = h.send(s.get("/console/api/session"), "198.51.101.7").await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["reason"], "binding-mismatch");

    let h = Harness::new();
    h.env().net.full_ip.store(true, Ordering::SeqCst);
    let s = h.sign_in().await;
    let (r, _) = h.send(s.get("/console/api/session"), CLIENT).await;
    assert_eq!(r.status(), StatusCode::OK);
    let (r, _) = h.send(s.get("/console/api/session"), "198.51.100.8").await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

// Ek B 2973: a session store failure is a 503; nothing is passed through (fail closed)
#[tokio::test]
async fn a_session_store_failure_fails_closed() {
    let h = Harness::new();
    let s = h.with_instance().await;
    h.env().sessions.down.store(true, Ordering::SeqCst);
    let target = "/admin/v1/realms/acme";
    let mut read = s.get("/console/api/proxy/admin/realms/acme");
    read.headers_mut().insert(
        "x-access-ais",
        h.ais(Mode::Check, read_intent(&Method::GET, target), h.now())
            .parse()
            .unwrap(),
    );
    for request in [
        s.get("/console/api/session"),
        s.get("/console/api/sessions"),
        read,
        s.post("/console/api/proxy/adp/explain", "{}"),
    ] {
        let (r, _) = h.send(request, CLIENT).await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    assert!(h.env().up.take().is_empty());
    let (r, _) = h
        .send(get("/console/api/sign-in?realm=acme", None), CLIENT)
        .await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
}

// TN-131: state-changing calls need the configured Origin and the session's CSRF token; Host
// is never consulted
#[tokio::test]
async fn writes_need_origin_and_the_sessions_csrf_token() {
    let h = Harness::new();
    let s = h.sign_in().await;
    let other = h.sign_in().await;
    let mut no_token = s.post("/console/api/sign-out", "");
    no_token.headers_mut().remove("x-csrf-token");
    let mut wrong_token = s.post("/console/api/sign-out", "");
    wrong_token
        .headers_mut()
        .insert("x-csrf-token", other.csrf.parse().unwrap());
    let mut no_origin = s.post("/console/api/sign-out", "");
    no_origin.headers_mut().remove("origin");
    no_origin
        .headers_mut()
        .insert("host", "access-server:9443".parse().unwrap());
    let mut evil = s.post("/console/api/sign-out", "");
    evil.headers_mut()
        .insert("origin", "https://acme.example".parse().unwrap());
    let mut cross = s.get("/console/api/session");
    cross
        .headers_mut()
        .insert("sec-fetch-site", "cross-site".parse().unwrap());
    for (request, code) in [
        (no_token, "csrf-token-invalid"),
        (wrong_token, "csrf-token-invalid"),
        (no_origin, "origin-not-allowed"),
        (evil, "origin-not-allowed"),
        (cross, "origin-not-allowed"),
    ] {
        let (r, body) = h.send(request, CLIENT).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(json(&body)["code"], code);
    }
    let (r, _) = h.send(s.get("/console/api/csrf"), CLIENT).await;
    let token = set_cookie(&r, CSRF_COOKIE);
    assert_eq!(token, s.csrf);
    let (r, _) = h.send(s.post("/console/api/sign-out", ""), CLIENT).await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let (r, _) = h.send(s.get("/console/api/session"), CLIENT).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

// TN-128, MD-14, OP-151 m.3 (s), TNI-12: the cookie alone neither reads through the admin
// proxy nor writes through it; nothing reaches the management API
#[tokio::test]
async fn the_cookie_alone_cannot_read_or_write() {
    let h = Harness::new();
    let s = h.with_instance().await;
    let (r, body) = h
        .send(s.get("/console/api/proxy/admin/realms/acme"), CLIENT)
        .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["code"], "ais-required");
    let (r, body) = h
        .send(
            s.post("/console/api/proxy/admin/realms/acme/groups", "{}"),
            CLIENT,
        )
        .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["code"], "ais-required");
    assert!(h.env().up.take().is_empty());
    assert_eq!(h.env().grants.issued.load(Ordering::SeqCst), 0);
}

// TN-128, OP-151 m.3 (e): a key other than the session's device Instance proves nothing
#[tokio::test]
async fn another_key_proves_nothing() {
    let h = Harness::new();
    let s = h.with_instance().await;
    let (thief, _) = SoftSigner::generate_p256().unwrap();
    let target = "/admin/v1/realms/acme";
    let mut read = s.get("/console/api/proxy/admin/realms/acme");
    read.headers_mut().insert(
        "x-access-ais",
        ais_by(
            &thief,
            Mode::Check,
            read_intent(&Method::GET, target),
            h.now(),
        )
        .parse()
        .unwrap(),
    );
    let mut write = s.post("/console/api/proxy/admin/realms/acme/groups", "{}");
    write.headers_mut().insert(
        "x-access-ais",
        ais_by(&thief, Mode::Commit, Digest([5; 32]), h.now())
            .parse()
            .unwrap(),
    );
    let mut replayed = s.get("/console/api/proxy/admin/realms/acme/clients");
    replayed.headers_mut().insert(
        "x-access-ais",
        h.ais(Mode::Check, read_intent(&Method::GET, target), h.now())
            .parse()
            .unwrap(),
    );
    for request in [read, write, replayed] {
        let (r, body) = h.send(request, CLIENT).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(json(&body)["code"], "read-proof-rejected");
    }
    assert!(h.env().up.take().is_empty());
}

// TN-128, TN-130, OP-151 m.3 (c), (e): a read proof by the session's Instance gets the
// session's DPoP-bound read token attached; the cookie and the AIS stay at the BFF
#[tokio::test]
async fn a_read_proof_gets_the_holder_bound_read_token() {
    let h = Harness::new();
    let s = h.with_instance().await;
    let target = "/admin/v1/realms/acme/clients?limit=5";
    for _ in 0..2 {
        let mut read = s.get("/console/api/proxy/admin/realms/acme/clients?limit=5");
        read.headers_mut().insert(
            "x-access-ais",
            h.ais(Mode::Check, read_intent(&Method::GET, target), h.now())
                .parse()
                .unwrap(),
        );
        let (r, _) = h.send(read, CLIENT).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r.headers().get("set-cookie").is_none());
        assert_eq!(r.headers()["request-id"], "rid");
    }
    assert_eq!(h.env().grants.issued.load(Ordering::SeqCst), 1);
    let seen = h.env().up.take();
    assert_eq!(seen.len(), 2);
    let (which, f) = &seen[0];
    assert_eq!(*which, "admin");
    assert_eq!(f.path_and_query, target);
    let names: Vec<_> = f.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(!names.contains(&"cookie") && !names.contains(&"x-access-ais"));
    let auth = f
        .headers
        .iter()
        .find(|(n, _)| n == "authorization")
        .unwrap()
        .1
        .to_str()
        .unwrap();
    assert!(auth.starts_with("DPoP tok-"));
    let dpop = f
        .headers
        .iter()
        .find(|(n, _)| n == "dpop")
        .unwrap()
        .1
        .clone();
    assert_eq!(
        dpop,
        "proof GET https://access-server:9443/admin/v1/realms/acme/clients"
    );
}

// OP-151 m.11 (a), TN-130: drafting an intent is a read; it needs a read proof over the POST
// and goes up with the read token, never as a write
#[tokio::test]
async fn drafting_an_intent_is_a_read() {
    let h = Harness::new();
    let s = h.with_instance().await;
    let target = "/admin/v1/realms/acme/intents";
    let body = "{\"operation\":\"createGroup\",\"body\":{\"name\":\"ops\"}}";
    let mut commit = s.post("/console/api/proxy/admin/realms/acme/intents", body);
    commit.headers_mut().insert(
        "x-access-ais",
        h.ais(Mode::Commit, Digest([5; 32]), h.now())
            .parse()
            .unwrap(),
    );
    let (r, refused) = h.send(commit, CLIENT).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(json(&refused)["code"], "read-proof-rejected");
    let mut draft = s.post("/console/api/proxy/admin/realms/acme/intents", body);
    draft.headers_mut().insert(
        "x-access-ais",
        h.ais(Mode::Check, read_intent(&Method::POST, target), h.now())
            .parse()
            .unwrap(),
    );
    let (r, _) = h.send(draft, CLIENT).await;
    assert_eq!(r.status(), StatusCode::OK);
    let seen = h.env().up.take();
    let (_, f) = &seen[0];
    assert_eq!(f.method, Method::POST);
    assert_eq!(f.body.as_ref(), body.as_bytes());
    let names: Vec<_> = f.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"authorization") && names.contains(&"dpop"));
    assert!(!names.contains(&"x-access-ais"));
}

// TN-130: no read token for the session means no read
#[tokio::test]
async fn no_read_token_means_no_read() {
    let h = Harness::new();
    let s = h.with_instance().await;
    h.env().grants.refuse.store(true, Ordering::SeqCst);
    let target = "/admin/v1/realms/acme";
    let mut read = s.get("/console/api/proxy/admin/realms/acme");
    read.headers_mut().insert(
        "x-access-ais",
        h.ais(Mode::Check, read_intent(&Method::GET, target), h.now())
            .parse()
            .unwrap(),
    );
    let (r, body) = h.send(read, CLIENT).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(json(&body)["code"], "read-not-granted");
    assert!(h.env().up.take().is_empty());
}

// TN-110, MD-14: a write passes on the browser's AIS and carries no token
#[tokio::test]
async fn a_write_passes_on_the_browsers_ais_only() {
    let h = Harness::new();
    let s = h.with_instance().await;
    let ais = h.ais(Mode::Commit, Digest([5; 32]), h.now());
    let mut write = s.post(
        "/console/api/proxy/admin/realms/acme/groups",
        "{\"name\":\"ops\"}",
    );
    write
        .headers_mut()
        .insert("x-access-ais", ais.parse().unwrap());
    write
        .headers_mut()
        .insert("idempotency-key", "AQEBAQEBAQEBAQEBAQEBAQ".parse().unwrap());
    let (r, _) = h.send(write, CLIENT).await;
    assert_eq!(r.status(), StatusCode::OK);
    let seen = h.env().up.take();
    let (_, f) = &seen[0];
    assert_eq!(f.method, Method::POST);
    assert_eq!(f.path_and_query, "/admin/v1/realms/acme/groups");
    assert_eq!(f.body.as_ref(), b"{\"name\":\"ops\"}");
    let names: Vec<_> = f.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"x-access-ais") && names.contains(&"idempotency-key"));
    assert!(
        !names.contains(&"authorization") && !names.contains(&"dpop") && !names.contains(&"cookie")
    );
    assert_eq!(h.env().grants.issued.load(Ordering::SeqCst), 0);
}

// TN-128, OP-151 m.3 (e): before the session registered its device Instance nothing goes up
#[tokio::test]
async fn no_instance_no_proxy() {
    let h = Harness::new();
    let s = h.sign_in().await;
    let mut write = s.post("/console/api/proxy/admin/realms/acme/groups", "{}");
    write.headers_mut().insert(
        "x-access-ais",
        h.ais(Mode::Commit, Digest([5; 32]), h.now())
            .parse()
            .unwrap(),
    );
    let (r, body) = h.send(write, CLIENT).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(json(&body)["code"], "console-instance-required");
    assert!(h.env().up.take().is_empty());
}

// TN-128, OP-151 m.3 (s), TNI-12: ADP reads go on as the browser wrote them; the BFF adds no
// credential, so a body without the browser's AIS reads as Anonymous; nothing else is reachable
#[tokio::test]
async fn adp_reads_carry_no_bff_credential() {
    let h = Harness::new();
    let s = h.sign_in().await;
    let body = search_body(&DOMAIN, None);
    let (r, _) = h
        .send(
            with_body(&s, "/console/api/proxy/adp/search/subject", body.clone()),
            CLIENT,
        )
        .await;
    assert_eq!(r.status(), StatusCode::OK);
    let seen = h.env().up.take();
    let (which, f) = &seen[0];
    assert_eq!(*which, "adp");
    assert_eq!(f.path_and_query, "/access/v1/search/subject");
    assert_eq!(f.body.as_ref(), body.as_bytes());
    let names: Vec<_> = f.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["content-type"]);
    for path in [
        "/console/api/proxy/adp/evaluations",
        "/console/api/proxy/adp/explain?x=1",
        "/console/api/proxy/adp/audit/export?x=1",
    ] {
        let (r, _) = h.send(s.post(path, "{}"), CLIENT).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
    }
    // OP-151 m.19: without the browser's Instance there is no commit to forward
    let (r, _) = h
        .send(s.post("/console/api/proxy/adp/evaluation", "{}"), CLIENT)
        .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let (r, _) = h
        .send(s.get("/console/api/proxy/adp/explain"), CLIENT)
        .await;
    assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(h.env().up.take().is_empty());
}

// Ek B 3089, TN-128: own sessions with the cookie; another account's session is not found
#[tokio::test]
async fn own_sessions_list_and_revoke() {
    let h = Harness::new();
    let a = h.sign_in().await;
    let b = h.sign_in().await;
    let (r, body) = h.send(a.get("/console/api/sessions"), CLIENT).await;
    assert_eq!(r.status(), StatusCode::OK);
    let list = json(&body)["sessions"].as_array().unwrap().clone();
    assert_eq!(list.len(), 2);
    let current = list.iter().find(|s| s["current"] == true).unwrap();
    let other = list.iter().find(|s| s["current"] == false).unwrap();
    let id = other["id"].as_str().unwrap();
    let path = format!("/console/api/sessions/{id}/revoke");
    let (r, _) = h.send(a.post(&path, ""), CLIENT).await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let (r, _) = h.send(b.get("/console/api/session"), CLIENT).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    {
        let mut rows = h.env().sessions.rows.lock().unwrap();
        let digest = cookie_digest(
            &<[u8; 32]>::try_from(access_kernel::json::b64url_decode(&a.value).unwrap()).unwrap(),
        );
        let mine = rows.get(&digest).unwrap().clone();
        let mut stranger = mine.clone();
        stranger.id = [9; 16];
        stranger.who.account = "acc_eve".to_owned();
        rows.insert([1; 32], stranger);
    }
    let (r, _) = h
        .send(
            a.post("/console/api/sessions/CQkJCQkJCQkJCQkJCQkJCQ/revoke", ""),
            CLIENT,
        )
        .await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let id = current["id"].as_str().unwrap();
    let path = format!("/console/api/sessions/{id}/revoke");
    let (r, _) = h.send(a.post(&path, ""), CLIENT).await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert!(set_cookie_line(&r, CONSOLE_COOKIE).contains("Max-Age=0"));
    let (r, body) = h.send(a.get("/console/api/profile"), CLIENT).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["code"], "console-session-required");
}

// Ek B 3089: the own profile is a cookie-only read
#[tokio::test]
async fn own_profile_is_a_cookie_read() {
    let h = Harness::new();
    let s = h.sign_in().await;
    let (r, body) = h.send(s.get("/console/api/profile"), CLIENT).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(json(&body)["account"], "acc_ada");
    let (r, body) = h.send(s.get("/console/api/about"), CLIENT).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert!(json(&body)["server_version"].is_string());
    let (r, _) = h.send(get("/console/api/about", None), CLIENT).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

// OP-149 m.6, OP-151 m.3 (e): the registration binds the session to its device Instance once
#[tokio::test]
async fn registration_binds_the_session_instance_once() {
    let h = Harness::new();
    let s = h.sign_in().await;
    let (r, body) = h
        .send(s.post("/console/api/instances/challenge", ""), CLIENT)
        .await;
    assert_eq!(r.status(), StatusCode::CREATED);
    assert_eq!(json(&body)["challenge"], "c");
    let (r, _) = h
        .send(s.post("/console/api/instances", "{\"ok\":false}"), CLIENT)
        .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let (r, _) = h
        .send(s.post("/console/api/instances", "{\"ok\":true}"), CLIENT)
        .await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let (_, body) = h.send(s.get("/console/api/session"), CLIENT).await;
    assert_eq!(
        json(&body)["instance"],
        b64url_encode(&thumbprint(&h.key.public_key()))
    );
    let (r, body) = h
        .send(s.post("/console/api/instances", "{\"ok\":true}"), CLIENT)
        .await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(json(&body)["code"], "instance-exists");
    let (r, _) = h
        .send(s.post("/console/api/instances/challenge", ""), CLIENT)
        .await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
}

// TN-33: the DBSC handshake answers 501 until DBSC lands; nothing is faked
#[tokio::test]
async fn dbsc_is_not_faked() {
    let h = Harness::new();
    for m in [Method::GET, Method::POST] {
        let request = Request::builder()
            .method(m)
            .uri("/console/api/dbsc/registration")
            .body(Body::empty())
            .unwrap();
        let (r, body) = h.send(request, CLIENT).await;
        assert_eq!(r.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(json(&body)["code"], "dbsc-not-available");
    }
}

// TN-131: every console answer carries the strict headers; unknown API paths are 404
#[tokio::test]
async fn every_answer_carries_the_console_headers() {
    let h = Harness::new();
    for path in [
        "/console",
        "/console/api/session",
        "/console/api/nothing",
        "/console/assets/x.js",
    ] {
        let (r, _) = h.send(get(path, None), CLIENT).await;
        let csp = r
            .headers()
            .get("content-security-policy")
            .unwrap_or_else(|| panic!("{path}: {:?}", r.status()))
            .to_str()
            .unwrap();
        assert!(csp.starts_with("default-src 'none'"), "{path}");
        assert_eq!(r.headers()["referrer-policy"], "no-referrer");
        assert_eq!(r.headers()["x-frame-options"], "DENY");
    }
    let (r, _) = h.send(get("/console/api/nothing", None), CLIENT).await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

fn console_dist() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "access-console-dist-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace("::", "-")
    ));
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>Console</title><script type=module src=/console/assets/app.js></script>",
    )
    .unwrap();
    std::fs::write(dir.join("assets/app.js"), "export {};").unwrap();
    dir
}

// TN-113, TN-128 (S-2): the console is served at its one canonical spelling, `/console`, with
// its screens and its assets under the Vite base `/console/`; the sign-in returns there, and
// the trailing-slash spelling is refused, never rewritten
#[tokio::test]
async fn the_console_is_served_at_its_canonical_path() {
    let h = Harness::serving(Some(Assets::load(&console_dist()).unwrap()));
    for path in ["/console", "/console/admin/people", "/console/profile"] {
        let (r, body) = h.send(get(path, None), CLIENT).await;
        assert_eq!(r.status(), StatusCode::OK, "{path}");
        assert!(String::from_utf8_lossy(&body).contains("/console/assets/app.js"));
    }
    let (r, body) = h.send(get("/console/assets/app.js", None), CLIENT).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(body, b"export {};");
    let (r, body) = h.send(get("/console/", None), CLIENT).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["code"], "path-not-canonical");
    h.sign_in().await;
}

// TN-131: an ambiguous cookie is refused rather than guessed
#[tokio::test]
async fn ambiguous_cookies_are_refused() {
    let h = Harness::new();
    let s = h.sign_in().await;
    let request = get(
        "/console/api/session",
        Some(&format!(
            "{CONSOLE_COOKIE}={}; {CONSOLE_COOKIE}=AAAA",
            s.value
        )),
    );
    let (r, body) = h.send(request, CLIENT).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["reason"], "cookie-ambiguous");
    let _ = csrf_token(&Secret::new([0; 32]));
}

fn commit_body(ais: &str, domain: &Digest, mode: &str) -> String {
    serde_json::json!({
        "context": {
            "domain": b64url_encode(&domain.0),
            "mode": mode,
            "nonce": b64url_encode(&[1; 16]),
            "ais": ais,
        },
    })
    .to_string()
}

fn with_body(s: &Session, path: &str, body: String) -> Request<Body> {
    Request::post(path)
        .header("cookie", s.cookie())
        .header("origin", ORIGIN)
        .header("x-csrf-token", &s.csrf)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

// TN-110, TN-128, MD-14, OP-151 m.19: ADP `evaluation` and `audit/export` go on only as a
// `commit` the session's device Instance signed for the session's domain; a check, another
// key, another domain, a stale statement or no statement is refused and nothing goes up
#[tokio::test]
#[allow(
    clippy::many_single_char_names,
    reason = "the harness, session, answer and body"
)]
async fn adp_commits_need_the_browsers_commit_ais() {
    let h = Harness::new();
    let s = h.with_instance().await;
    for rest in ["evaluation", "audit/export"] {
        let path = format!("/console/api/proxy/adp/{rest}");
        let good = h.ais(Mode::Commit, Digest([5; 32]), h.now());
        let (r, _) = h
            .send(
                with_body(&s, &path, commit_body(&good, &DOMAIN, "commit")),
                CLIENT,
            )
            .await;
        assert_eq!(r.status(), StatusCode::OK, "{rest}");
        let types: Vec<_> = r.headers().get_all("content-type").iter().collect();
        assert_eq!(types, ["application/json"], "the upstream type, once");
        let seen = h.env().up.take();
        let (which, f) = &seen[0];
        assert_eq!(*which, "adp");
        assert_eq!(f.path_and_query, format!("/access/v1/{rest}"));
        let names: Vec<_> = f.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["content-type"]);
        let (thief, _) = SoftSigner::generate_p256().unwrap();
        let refused = [
            commit_body(
                &h.ais(Mode::Check, Digest([5; 32]), h.now()),
                &DOMAIN,
                "commit",
            ),
            commit_body(&good, &DOMAIN, "check"),
            commit_body(&good, &Digest([4; 32]), "commit"),
            commit_body(
                &ais_by(&thief, Mode::Commit, Digest([5; 32]), h.now()),
                &DOMAIN,
                "commit",
            ),
            commit_body(
                &h.ais(Mode::Commit, Digest([5; 32]), h.now() - 3_600_000),
                &DOMAIN,
                "commit",
            ),
            "{\"context\":{\"mode\":\"commit\"}}".to_owned(),
            "not json".to_owned(),
        ];
        for body in refused {
            let (r, b) = h.send(with_body(&s, &path, body.clone()), CLIENT).await;
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "{rest} {body}");
            assert_eq!(json(&b)["code"], "commit-ais-rejected");
        }
        assert!(h.env().up.take().is_empty());
    }
}

// OP-151 m.19 (a), m.12 (c), PI-7: the BFF drafts a catalogued intent for the session's realm
// for a read proof over the draft route; without the proof, or for anything else, nothing is
// drafted, and a draft never goes upstream
#[tokio::test]
#[allow(
    clippy::many_single_char_names,
    reason = "the harness, session, answer and body"
)]
async fn intents_are_drafted_for_a_read_proof() {
    use access_http::console::drafts::VALID_FOR_MS;
    let h = Harness::new();
    let s = h.with_instance().await;
    let ask = "{\"action\":{\"namespace\":\"idp.account\",\"name\":\"suspend\",\"major\":1},\"resources\":[{\"namespace\":\"idp\",\"path\":[\"acme\"]}],\"mode\":\"check\"}";
    let (r, b) = h.send(s.post("/console/api/intents", ask), CLIENT).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(&b)["code"], "ais-required");
    let proof = |intent: Digest| h.ais(Mode::Check, intent, h.now());
    let mut wrong = s.post("/console/api/intents", ask);
    wrong.headers_mut().insert(
        "x-access-ais",
        proof(read_intent(&Method::GET, "/console/api/intents"))
            .parse()
            .unwrap(),
    );
    let (r, b) = h.send(wrong, CLIENT).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(json(&b)["code"], "read-proof-rejected");
    let right = || proof(read_intent(&Method::POST, "/console/api/intents"));
    let mut good = s.post("/console/api/intents", ask);
    good.headers_mut()
        .insert("x-access-ais", right().parse().unwrap());
    let (r, b) = h.send(good, CLIENT).await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&b)
    );
    let v = json(&b);
    assert_eq!(v["intent"]["action"]["name"], "suspend");
    assert_eq!(v["intent"]["validity"]["until"], h.now() + VALID_FOR_MS);
    assert!(v["envelope"].is_string());
    let other = "{\"action\":{\"namespace\":\"idp.account\",\"name\":\"suspend\",\"major\":1},\"resources\":[{\"namespace\":\"idp\",\"path\":[\"globex\"]}],\"mode\":\"check\"}";
    let mut elsewhere = s.post("/console/api/intents", other);
    elsewhere
        .headers_mut()
        .insert("x-access-ais", right().parse().unwrap());
    let (r, b) = h.send(elsewhere, CLIENT).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(&b)["code"], "intent-resource-not-allowed");
    let mut no_csrf = s.post("/console/api/intents", ask);
    no_csrf.headers_mut().remove("x-csrf-token");
    no_csrf
        .headers_mut()
        .insert("x-access-ais", right().parse().unwrap());
    let (r, _) = h.send(no_csrf, CLIENT).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(h.env().up.take().is_empty());
}

fn adp_context(domain: &Digest, ais: Option<&str>) -> serde_json::Value {
    let mut ctx = serde_json::json!({
        "domain": b64url_encode(&domain.0),
        "mode": "check",
        "nonce": b64url_encode(&[2; 16]),
        "basis": { "public": b64url_encode(&[3; 16]) },
        "capacity": "own",
        "intent": {
            "action": { "namespace": "access", "name": "read", "major": 1, "schema": b64url_encode(&[5; 32]) },
            "resources": [{ "namespace": "access.search", "path": ["subject"] }],
            "validity": { "from": 0, "until": 100_000 },
        },
    });
    if let Some(a) = ais {
        ctx["ais"] = serde_json::Value::from(a);
    }
    ctx
}

fn search_body(domain: &Digest, ais: Option<&str>) -> String {
    let mut ctx = adp_context(domain, ais);
    ctx["query"] = serde_json::json!({
        "action": { "namespace": "shop", "name": "read", "major": 1, "schema": b64url_encode(&[5; 32]) },
        "resource": { "namespace": "shop", "path": ["item-1"] },
    });
    serde_json::json!({
        "subject": { "type": "access_party" },
        "action": { "name": "read" },
        "context": ctx,
    })
    .to_string()
}

fn explain_body(domain: &Digest, ais: Option<&str>) -> String {
    let mut ctx = adp_context(domain, ais);
    ctx["intent"]["resources"] = serde_json::json!([{ "namespace": "shop", "path": ["item-1"] }]);
    ctx["intent"]["action"]["namespace"] = serde_json::Value::from("shop");
    serde_json::json!({
        "subject": { "type": "user", "id": "alice" },
        "action": { "name": "read" },
        "resource": { "type": "shop", "id": "item-1" },
        "context": ctx,
    })
    .to_string()
}

fn eligibility_body(subject: [u8; 16], domain: &Digest) -> String {
    serde_json::json!({
        "subject": b64url_encode(&subject),
        "set": {
            "domain": b64url_encode(&domain.0),
            "intent": {
                "action": { "namespace": "work", "name": "approve", "major": 1, "schema": b64url_encode(&[4; 32]) },
                "resources": [{ "namespace": "work", "path": ["gate-1"] }],
                "validity": { "from": 0, "until": 2_000_000_000_000_u64 },
            },
            "basis": { "public": b64url_encode(&[3; 16]) },
            "capacity": "own",
        },
    })
    .to_string()
}

// TN-128, OP-151 m.12 (e) (W-5): the ADP proxy is not an oracle over other tenants: a read
// names the session's own domain, an eligibility check the session's own Party, and an AIS the
// session's own device Instance; anything else is refused and nothing goes up
#[tokio::test]
async fn adp_reads_are_the_sessions_own() {
    let h = Harness::new();
    let s = h.with_instance().await;
    let other = Digest([4; 32]);
    let mine = h.ais(Mode::Check, Digest([5; 32]), h.now());
    let (thief, _) = SoftSigner::generate_p256().unwrap();
    let theirs = ais_by(&thief, Mode::Check, Digest([5; 32]), h.now());
    let allowed = [
        ("eligibility:check", eligibility_body(PARTY, &DOMAIN)),
        ("explain", explain_body(&DOMAIN, None)),
        ("explain", explain_body(&DOMAIN, Some(&mine))),
        ("search/subject", search_body(&DOMAIN, None)),
        ("search/subject", search_body(&DOMAIN, Some(&mine))),
    ];
    for (rest, body) in allowed {
        let path = format!("/console/api/proxy/adp/{rest}");
        let (r, b) = h.send(with_body(&s, &path, body), CLIENT).await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "{rest} {}",
            String::from_utf8_lossy(&b)
        );
        assert_eq!(h.env().up.take().len(), 1, "{rest}");
    }
    let refused = [
        ("eligibility:check", eligibility_body([8; 16], &DOMAIN)),
        ("eligibility:check", eligibility_body(PARTY, &other)),
        ("explain", explain_body(&other, None)),
        ("explain", explain_body(&DOMAIN, Some(&theirs))),
        ("search/subject", search_body(&other, None)),
        ("search/subject", search_body(&DOMAIN, Some(&theirs))),
    ];
    for (rest, body) in refused {
        let path = format!("/console/api/proxy/adp/{rest}");
        let (r, b) = h.send(with_body(&s, &path, body), CLIENT).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "{rest}");
        assert_eq!(json(&b)["code"], "read-not-own");
    }
    let (r, b) = h
        .send(
            with_body(&s, "/console/api/proxy/adp/explain", "{\"q\":1}".to_owned()),
            CLIENT,
        )
        .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(&b)["code"], "context");
    assert!(h.env().up.take().is_empty());
}

// OP-141 m.23 (a), OP-151 m.12 (e) (W-5): each console session is its own requester under the
// console's PEP, so one session's reads never spend another's limit
#[tokio::test]
async fn each_session_is_its_own_requester() {
    let h = Harness::new();
    let a = h.sign_in().await;
    let b = h.sign_in().await;
    for s in [&a, &a, &b] {
        let (r, _) = h
            .send(
                with_body(
                    s,
                    "/console/api/proxy/adp/search/subject",
                    search_body(&DOMAIN, None),
                ),
                CLIENT,
            )
            .await;
        assert_eq!(r.status(), StatusCode::OK);
    }
    let seen = std::mem::take(&mut *h.env().up.requesters.lock().unwrap());
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0], seen[1]);
    assert_ne!(seen[0], seen[2]);
    assert!(seen.iter().all(|r| !r.is_empty() && r != "access-console"));
}
