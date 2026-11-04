//! The hosted login surface end to end: an in-process server over a real PostgreSQL, a
//! software WebAuthn authenticator and a recording Relay seam (OP-146 m.4 (g), (h), m.12).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::unused_async_trait_impl,
    clippy::many_single_char_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "../../identity-webauthn/tests/support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_crypto::totp::{TotpAlgorithm, hotp, step_of};
use access_crypto::webauthn::DecoyKey;
use access_http::login::{Assets, Peer, me_router, router};
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::SystemEntropy;
use access_identity_account::app::accounts::{
    PasswordServices, change_status, create, deactivate, set_password,
};
use access_identity_account::app::hasher::{Hasher, HasherConfig};
use access_identity_account::app::local::LocalLimiter;
use access_identity_account::app::login::LoginGate;
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::password::Argon2Params;
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::domain::throttle::ThrottlePolicy;
use access_identity_account::notify::NotifyError;
use access_identity_account::notify::envelope::EventId;
use access_identity_account::notify::message::{Body, Message};
use access_identity_account::notify::ports::Notifier;
use access_identity_account::ports::{BreachRanges, RangeUnavailable};
use access_identity_oauth::app::Discovery;
use access_identity_oauth::domain::issuer::Issuer;
use access_identity_oauth::ports::{Directory, Keys, RealmEntry, Unavailable};
use access_identity_session::domain::requirement::AuthPolicy;
use access_identity_session::domain::session::SessionPolicy;
use access_identity_ui::app::{Devices, Hosted};
use access_identity_ui::ports::{ArtifactSigner, Clock, DeviceInstances, Kits, Messages, RealmKit};
use access_identity_webauthn::adapters::RealmDecoyKeys;
use access_identity_webauthn::domain::ids::RealmId as WaRealm;
use access_identity_webauthn::domain::policy::RealmPolicy;
use access_identity_webauthn::domain::rp::{RelyingParty, RpId};
use access_internal_api::idp::{Unavailable as PlaneUnavailable, Verdict};
use access_internal_api::instances::{Registered, Registration, RegistrationVerdict, Termination};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::Id;
use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use axum::Router;
use axum::body::Body as HttpBody;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};
use support::{Authenticator, Key, ORIGIN, RP_ID};
use tower::ServiceExt;

const HOST: &str = "acme.example";
const PW: &str = "correct horse battery";
const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};

/// A clock the test moves; a live one also follows real time, so measured durations are real
/// (TN-82 pads to the mean of measured successes).
#[derive(Clone)]
struct TestClock {
    at: Arc<AtomicU64>,
    live: Option<std::time::Instant>,
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        let real = self
            .live
            .map_or(0, |s| u64::try_from(s.elapsed().as_millis()).unwrap());
        self.at.load(Ordering::SeqCst) + real
    }
}

struct Corpus;

impl BreachRanges for Corpus {
    fn range(&self, _: &str) -> impl Future<Output = Result<String, RangeUnavailable>> + Send {
        std::future::ready(Ok(String::new()))
    }
}

/// The Relay seam as a recorder: what would be queued, with its secret.
#[derive(Clone, Default)]
struct Outbox(Arc<Mutex<Vec<String>>>);

struct Recording<'a>(&'a Outbox);

impl Notifier for Recording<'_> {
    fn notify(
        &self,
        _: &mut TenantTx,
        m: &Message,
    ) -> impl Future<Output = Result<EventId, NotifyError>> + Send {
        let secret = match &m.body {
            Body::Otp { code, .. } => code.expose().clone(),
            Body::MagicLink { link, .. } => link.expose().clone(),
            _ => String::new(),
        };
        self.0.0.lock().unwrap().push(secret);
        std::future::ready(Ok(EventId([1; 16])))
    }
}

impl Messages for Outbox {
    type For<'a> = Recording<'a>;

    fn notifier<'a>(&'a self, _: &'a Realm<'a>) -> Recording<'a> {
        Recording(self)
    }
}

impl Outbox {
    fn last(&self) -> String {
        self.0.lock().unwrap().last().cloned().unwrap()
    }
}

struct Dir(RealmEntry);

impl Directory for Dir {
    async fn by_host(&self, host: &str) -> Result<Option<RealmEntry>, Unavailable> {
        Ok((host == HOST).then(|| self.0.clone()))
    }

    async fn by_slug(&self, _: &str) -> Result<Option<RealmEntry>, Unavailable> {
        Ok(None)
    }

    async fn all(&self) -> Result<Vec<RealmEntry>, Unavailable> {
        Ok(vec![self.0.clone()])
    }
}

struct NoKeys;

impl Keys for NoKeys {
    async fn ping(&self) -> Result<(), Unavailable> {
        Ok(())
    }

    async fn jwks(&self, _: RealmId) -> Result<String, Unavailable> {
        Err(Unavailable)
    }
}

/// The identity signer: one in-process key.
#[derive(Clone)]
struct ArtifactKey(Arc<SoftSigner>);

impl ArtifactSigner for ArtifactKey {
    async fn sign_cose(
        &self,
        _: RealmId,
        content_type: &str,
        payload: &[u8],
        _: u64,
    ) -> Result<Vec<u8>, Unavailable> {
        let kid = access_kernel::verify::key_scope::thumbprint(&self.0.public_key());
        sign_sign1(&*self.0, kid, content_type, payload).map_err(|_| Unavailable)
    }
}

/// The authority plane: opens every device Instance as `[9; 16]`, ends none.
struct Plane;

impl DeviceInstances for Plane {
    async fn register(&self, r: Registration) -> Result<RegistrationVerdict, PlaneUnavailable> {
        Ok(RegistrationVerdict::Registered(Registered {
            party: Id([8; 16]),
            instance: Id([9; 16]),
            kid: access_kernel::verify::key_scope::thumbprint(&r.key),
            replayed: false,
        }))
    }

    async fn terminate(&self, _: Termination) -> Result<Verdict, PlaneUnavailable> {
        Ok(Verdict::Refused {
            code: String::from("protocol"),
        })
    }
}

struct Kit(Arc<RealmKit>);

impl Kits for Kit {
    async fn kit(&self, entry: &RealmEntry) -> Result<Arc<RealmKit>, Unavailable> {
        if entry.realm == self.0.realm {
            Ok(self.0.clone())
        } else {
            Err(Unavailable)
        }
    }
}

struct Env {
    db: TestDb,
    tenant: TenantId,
    realm: RealmId,
    kit: Arc<RealmKit>,
    clock: TestClock,
    outbox: Outbox,
    app: Router,
    hasher: Arc<Hasher>,
    peers: AtomicU64,
    signer: ArtifactKey,
}

fn kit(tenant: TenantId, realm: RealmId, seed: u8, auth: AuthPolicy) -> RealmKit {
    let wa = WaRealm::from_bytes(*realm.as_bytes());
    RealmKit {
        tenant,
        realm,
        issuer: format!("https://{HOST}"),
        name: "Acme".into(),
        kek: Box::new(SoftKek::new("realm-kek:1", [seed; 32])),
        ids: IdKey::new(Secret::new([seed.wrapping_add(1); 32])),
        decoys: RealmDecoyKeys::default().with(wa, DecoyKey::new(Secret::new([9; 32]))),
        rp: RelyingParty {
            realm: wa,
            rp_id: RpId::parse(RP_ID).unwrap(),
            name: "Acme".into(),
            pinned: true,
            related: Vec::new(),
        },
        webauthn: RealmPolicy::default(),
        auth,
        lifetimes: SessionPolicy::DEFAULT,
    }
}

fn fixture() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "access-login-dist-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace("::", "-")
    ));
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>Sign in</title><script type=module src=/assets/app.js></script>",
    )
    .unwrap();
    std::fs::write(dir.join("assets/app.js"), "export {};").unwrap();
    dir
}

async fn env(seed: u8, slug: &str, auth: AuthPolicy) -> Env {
    env_with(seed, slug, auth, false).await
}

async fn env_with(seed: u8, slug: &str, auth: AuthPolicy, live: bool) -> Env {
    let db = fresh().await.unwrap();
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *tenant.as_bytes(), &g, &[])
        .await
        .unwrap();
    let mut tx = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    let realm = create_realm(&mut tx, &d, slug, "pool-default")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let kit = Arc::new(kit(tenant, realm, seed, auth));
    let clock = TestClock {
        at: Arc::new(AtomicU64::new(1_800_000_000_000)),
        live: live.then(std::time::Instant::now),
    };
    let outbox = Outbox::default();
    let entry = RealmEntry {
        tenant,
        realm,
        slug: slug.to_owned(),
        issuer: Issuer::parse(&format!("https://{HOST}")).unwrap(),
    };
    let config = HasherConfig::sized(Argon2Params::CANONICAL, 4, None);
    let hosted = Arc::new(Hosted {
        kits: Kit(kit.clone()),
        db: db.app.clone(),
        clock: clock.clone(),
        messages: outbox.clone(),
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        hasher: Hasher::new(config),
        redirect_to: "/".into(),
    });
    let assets = Assets::load(&fixture()).unwrap();
    let signer = ArtifactKey(Arc::new(SoftSigner::generate_ed25519().unwrap().0));
    let app = router(
        Discovery::new(Dir(entry.clone()), NoKeys),
        hosted.clone(),
        Some(assets),
    )
    .merge(me_router(
        Discovery::new(Dir(entry), NoKeys),
        hosted,
        Devices {
            signer: signer.clone(),
            instances: Plane,
            pep: String::from("access-identity"),
        },
    ));
    Env {
        db,
        tenant,
        realm,
        kit,
        clock,
        outbox,
        app,
        hasher: Arc::new(Hasher::new(config)),
        peers: AtomicU64::new(0),
        signer,
    }
}

impl Env {
    fn realm(&self) -> Realm<'_> {
        let _ = (self.tenant, self.realm);
        self.kit.realm()
    }

    async fn account(&self, who: &str) -> [u8; 16] {
        let pg = PgAccounts(self.db.app.clone());
        let id = Identifier::new(IdentifierKind::Email, who).unwrap();
        let s = create(&pg, &self.realm(), &[id], &ADMIN).await.unwrap();
        let services = PasswordServices {
            hasher: &self.hasher,
            ranges: &Corpus,
            entropy: &SystemEntropy,
        };
        set_password(&pg, &self.realm(), &services, s, PW, &ADMIN)
            .await
            .unwrap();
        for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
            change_status(&pg, &self.realm(), s, to, &ADMIN)
                .await
                .unwrap();
        }
        s
    }

    fn browser(&self, name: &str) -> Web {
        let ip = self.peers.fetch_add(1, Ordering::SeqCst);
        Web {
            ip: Ipv4Addr::new(
                10,
                u8::try_from(ip / 250 % 250).unwrap(),
                u8::try_from(ip % 250).unwrap() + 1,
                1,
            ),
            app: self.app.clone(),
            jar: BTreeMap::new(),
            name: name.to_owned(),
            n: 0,
            host: HOST.to_owned(),
        }
    }

    fn advance(&self, ms: u64) {
        self.clock.at.fetch_add(ms, Ordering::SeqCst);
    }

    fn totp(&self, seed: &[u8]) -> String {
        hotp(
            seed,
            TotpAlgorithm::Sha1,
            step_of(self.clock.now_ms() / 1000, 30),
            6,
        )
    }
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn step(&self) -> String {
        self.json()["step"].as_str().unwrap_or_default().to_owned()
    }

    fn messages(&self) -> Vec<String> {
        self.json()["messages"]
            .as_array()
            .map(|m| {
                m.iter()
                    .map(|x| x["id"].as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn action(&self) -> String {
        self.json()["action"].as_str().unwrap().to_owned()
    }
}

/// One browser: a cookie jar and fresh `Idempotency-Key`s.
struct Web {
    ip: Ipv4Addr,
    app: Router,
    jar: BTreeMap<String, String>,
    name: String,
    n: u64,
    host: String,
}

impl Web {
    fn key(&mut self) -> String {
        self.n += 1;
        format!("{}-{}", self.name, self.n)
    }

    async fn send(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
        key: Option<&str>,
    ) -> Answer {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, &self.host)
            .header("x-request-id", "req-1");
        if !self.jar.is_empty() {
            let cookies: Vec<String> = self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect();
            req = req.header(header::COOKIE, cookies.join("; "));
        }
        if method == "POST" || body.is_some() {
            req = req.header(header::CONTENT_TYPE, "application/json");
        }
        if let Some(k) = key {
            req = req.header("idempotency-key", k);
        }
        let body = body.map_or_else(HttpBody::empty, |b| HttpBody::from(b.to_string()));
        let mut req = req.body(body).unwrap();
        req.extensions_mut().insert(Peer(IpAddr::V4(self.ip)));
        let response = self.app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        for c in headers.get_all(header::SET_COOKIE) {
            let c = c.to_str().unwrap();
            let (name, value) = c.split(';').next().unwrap().split_once('=').unwrap();
            if c.contains("Max-Age=0") {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        Answer {
            status,
            headers,
            body,
        }
    }

    async fn post(&mut self, path: &str, body: Option<Value>) -> Answer {
        let key = self.key();
        self.send("POST", path, body, Some(&key)).await
    }

    async fn get(&mut self, path: &str) -> Answer {
        self.send("GET", path, None, None).await
    }

    async fn start(&mut self) -> Answer {
        let a = self.post("/v1/login/flows", None).await;
        assert_eq!(
            a.status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&a.body)
        );
        a
    }

    async fn submit(&mut self, at: &Answer, method: &str, fields: Value) -> Answer {
        self.post(
            &at.action(),
            Some(json!({ "method": method, "fields": fields })),
        )
        .await
    }

    async fn identify(&mut self, who: &str) -> Answer {
        let first = self.start().await;
        let a = self
            .submit(&first, "identifier", json!({ "identifier": who }))
            .await;
        assert_eq!(a.status, StatusCode::OK);
        assert_eq!(a.step(), "authenticate");
        a
    }

    async fn sign_in(&mut self, who: &str) -> Answer {
        let at = self.identify(who).await;
        self.submit(&at, "password", json!({ "password": PW }))
            .await
    }
}

fn base32_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0_u32, 0_u32);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("base32"),
        };
        buf = (buf << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).unwrap());
        }
    }
    out
}

fn passkey_node(a: &Answer) -> Value {
    a.json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["type"] == "passkey_get")
        .unwrap()["options"]
        .clone()
}

// TN-96, TN-132, OP-146 m.12 (b): identifier → password → complete; the session cookie is
// `__Host-` and the flow answers 410 once used
#[tokio::test]
async fn identifier_then_password_signs_in_with_a_host_cookie() {
    let e = env(1, "lg-a", AuthPolicy::DEFAULT).await;
    e.account("alice@example.com").await;
    let mut b = e.browser("b");
    let first = b.start().await;
    assert_eq!(first.step(), "identifier");
    assert!(b.jar.contains_key("__Host-access-flow"));
    assert_eq!(first.headers[header::CACHE_CONTROL], "no-store");
    let at = b
        .submit(
            &first,
            "identifier",
            json!({ "identifier": "alice@example.com" }),
        )
        .await;
    assert_eq!(at.step(), "authenticate");
    let echo = &at.json()["nodes"][0];
    assert_eq!(echo["value"], "alice@example.com");
    assert_eq!(echo["read_only"], true);
    let wrong = b
        .submit(&at, "password", json!({ "password": "nope nope nope" }))
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.messages(), ["login.failed"]);
    let early = b
        .submit(&wrong, "password", json!({ "password": PW }))
        .await;
    assert_eq!(early.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(early.messages(), ["login.throttled"]);
    assert!(early.headers.contains_key(header::RETRY_AFTER));
    e.advance(2_000);
    let done = b
        .submit(&wrong, "password", json!({ "password": PW }))
        .await;
    assert_eq!(done.status, StatusCode::OK);
    assert_eq!(done.step(), "complete");
    assert_eq!(done.json()["redirect_to"], "/");
    let set: Vec<&str> = done
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    let session = set
        .iter()
        .find(|c| c.starts_with("__Host-access-session="))
        .unwrap();
    for attr in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
        assert!(session.contains(attr), "{session}");
    }
    assert!(!session.contains("Domain="));
    let me = b.get("/v1/sessions/current").await;
    assert_eq!(me.status, StatusCode::OK);
    assert!(me.json()["subject"].as_str().unwrap().starts_with("usr_"));
    let again = b.submit(&done, "password", json!({ "password": PW })).await;
    assert_eq!(again.status, StatusCode::GONE);
}

// TN-106, X40: a field or method the step did not offer is 400; the flow is unchanged
#[tokio::test]
async fn fabricated_submissions_are_refused() {
    let e = env(2, "lg-b", AuthPolicy::DEFAULT).await;
    let mut b = e.browser("b");
    let first = b.start().await;
    for body in [
        json!({ "method": "password", "fields": { "password": "x" } }),
        json!({ "method": "identifier", "fields": { "identifier": "a", "role": "admin" } }),
        json!({ "method": "eval" }),
        json!({ "method": "identifier", "fields": { "identifier": "a" }, "extra": 1 }),
    ] {
        let a = b.post(&first.action(), Some(body)).await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST);
        assert_eq!(a.headers[header::CONTENT_TYPE], "application/problem+json");
    }
    let still = b.get(&first.action()).await;
    assert_eq!(still.status, StatusCode::OK);
    assert_eq!(still.step(), "identifier");
}

// TN-126, OP-65: Idempotency-Key is required; the same key answers once; another request under
// it is 422; another browser's key never replays this one's answer
#[tokio::test]
async fn idempotency_keys_replay_and_refuse() {
    let e = env(3, "lg-c", AuthPolicy::DEFAULT).await;
    let mut b = e.browser("b");
    let missing = b.send("POST", "/v1/login/flows", None, None).await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&missing.body).contains("idempotency-key-required"));
    let first = b.start().await;
    let saved = b.jar.clone();
    let body = json!({ "method": "identifier", "fields": { "identifier": "ann@example.com" } });
    let one = b
        .send("POST", &first.action(), Some(body.clone()), Some("k1"))
        .await;
    assert_eq!(one.status, StatusCode::OK);
    b.jar.clone_from(&saved);
    let two = b
        .send("POST", &first.action(), Some(body.clone()), Some("k1"))
        .await;
    assert_eq!(two.body, one.body);
    assert_eq!(
        two.headers.get_all(header::SET_COOKIE).iter().count(),
        one.headers.get_all(header::SET_COOKIE).iter().count()
    );
    b.jar.clone_from(&saved);
    let other = b
        .send(
            "POST",
            &first.action(),
            Some(json!({ "method": "restart" })),
            Some("k1"),
        )
        .await;
    assert_eq!(other.status, StatusCode::UNPROCESSABLE_ENTITY);
    let mut c = e.browser("c");
    c.start().await;
    let theirs = c
        .send("POST", &first.action(), Some(body), Some("k1"))
        .await;
    assert_ne!(theirs.body, one.body);
    let fresh = c.send("POST", "/v1/login/flows", None, Some("k9")).await;
    c.jar.clear();
    let again = c.send("POST", "/v1/login/flows", None, Some("k9")).await;
    assert_eq!(again.status, StatusCode::CREATED);
    assert_ne!(again.body, fresh.body);
}

// §17.9.6: an unknown host gets the plain 404; JSON is required on writes
#[tokio::test]
async fn unknown_hosts_and_forms_are_refused() {
    let e = env(4, "lg-d", AuthPolicy::DEFAULT).await;
    let mut b = e.browser("b");
    b.host = "evil.example".into();
    for (m, p) in [
        ("POST", "/v1/login/flows"),
        ("GET", "/login"),
        ("GET", "/.well-known/webauthn"),
        ("GET", "/v1/sessions"),
    ] {
        let a = b.send(m, p, None, Some("k")).await;
        assert_eq!(a.status, StatusCode::NOT_FOUND, "{p}");
        assert!(!String::from_utf8_lossy(&a.body).contains("lg-d"));
    }
    let mut b = e.browser("f");
    let req = Request::post("/v1/login/flows")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("idempotency-key", "k")
        .body(HttpBody::empty())
        .unwrap();
    let a = b.app.clone().oneshot(req).await.unwrap();
    assert_eq!(a.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    b.jar.clear();
}

// OP-146 m.12 (f), TN-18: the login app is served with the security headers of
// web/login/security-headers.ts; the Related Origins document is the builder's
#[tokio::test]
async fn the_login_app_carries_its_security_headers() {
    let e = env(5, "lg-e", AuthPolicy::DEFAULT).await;
    let mut b = e.browser("b");
    let page = b.get("/login").await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(
        page.headers[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    let ts = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../web/login/security-headers.ts"),
    )
    .unwrap();
    let list = ts
        .split_once("contentSecurityPolicy = [")
        .and_then(|(_, rest)| rest.split_once("].join"))
        .unwrap()
        .0;
    let csp: Vec<&str> = list
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"')?.strip_suffix("\","))
        .collect();
    assert_eq!(page.headers["content-security-policy"], csp.join("; "));
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
    ] {
        assert!(ts.contains(&format!("\"{value}\"")), "{name}");
        assert_eq!(page.headers[name], value);
    }
    assert!(ts.contains(page.headers["permissions-policy"].to_str().unwrap()));
    let js = b.get("/assets/app.js").await;
    assert_eq!(js.status, StatusCode::OK);
    assert_eq!(
        js.headers[header::CACHE_CONTROL],
        "public, max-age=31536000, immutable"
    );
    assert!(js.headers.contains_key("content-security-policy"));
    assert_eq!(
        b.get("/assets/../index.html").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        b.get("/assets/missing.js").await.status,
        StatusCode::NOT_FOUND
    );
    let wk = b.get("/.well-known/webauthn").await;
    assert_eq!(wk.status, StatusCode::OK);
    assert_eq!(wk.json(), json!({ "origins": [ORIGIN] }));
}

// §10.2.2, TN-64, TN-59, TN-36, TN-50, S10: TOTP enrolment from a session ends other sessions;
// the next sign-in asks for the second step; a recovery code works once; sign-out and sign-out
// everywhere end sessions
#[tokio::test]
async fn totp_recovery_codes_and_sign_out() {
    let e = env(6, "lg-f", AuthPolicy::DEFAULT).await;
    e.account("alice@example.com").await;
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("alice@example.com").await.step(), "complete");
    let mut other = e.browser("o");
    assert_eq!(other.sign_in("alice@example.com").await.step(), "complete");
    let list = b.get("/v1/sessions").await;
    assert_eq!(list.json()["sessions"].as_array().unwrap().len(), 2);
    let started = b
        .post("/v1/account/totp", Some(json!({ "label": "alice" })))
        .await;
    assert_eq!(started.status, StatusCode::CREATED);
    let s = started.json();
    assert!(
        s["uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/Acme:alice?secret=")
    );
    let seed = base32_decode(s["secret"].as_str().unwrap());
    let path = format!("/v1/account/totp/{}", s["enrollment"].as_str().unwrap());
    let bad = b.post(&path, Some(json!({ "code": "000000" }))).await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    let ok = b.post(&path, Some(json!({ "code": e.totp(&seed) }))).await;
    assert_eq!(
        ok.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&ok.body)
    );
    let codes: Vec<String> = ok.json()["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(codes.len(), 10);
    assert_eq!(b.get("/v1/sessions/current").await.status, StatusCode::OK);
    assert_eq!(
        other.get("/v1/sessions/current").await.status,
        StatusCode::UNAUTHORIZED
    );

    let mut c = e.browser("c");
    let second = c.sign_in("alice@example.com").await;
    assert_eq!(second.step(), "second_factor");
    let wrong = c
        .submit(&second, "totp", json!({ "totp_code": "000000" }))
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.messages(), ["second_factor.failed"]);
    e.advance(30_000);
    let done = c
        .submit(&wrong, "totp", json!({ "totp_code": e.totp(&seed) }))
        .await;
    assert_eq!(done.step(), "complete");

    let mut d = e.browser("d");
    let second = d.sign_in("alice@example.com").await;
    let used = d
        .submit(
            &second,
            "recovery_code",
            json!({ "recovery_code": codes[0] }),
        )
        .await;
    assert_eq!(used.step(), "complete");
    let mut f = e.browser("f");
    let second = f.sign_in("alice@example.com").await;
    let again = f
        .submit(
            &second,
            "recovery_code",
            json!({ "recovery_code": codes[0] }),
        )
        .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);

    let fresh = b.post("/v1/account/recovery-codes", None).await;
    assert_eq!(fresh.json()["recovery_codes"].as_array().unwrap().len(), 10);

    let out = c.post("/v1/sessions/current/sign-out", None).await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    assert!(!c.jar.contains_key("__Host-access-session"));
    assert_eq!(
        c.get("/v1/sessions/current").await.status,
        StatusCode::UNAUTHORIZED
    );
    let all = b.post("/v1/sessions/sign-out-everywhere", None).await;
    assert_eq!(all.status, StatusCode::NO_CONTENT);
    assert_eq!(
        d.get("/v1/sessions/current").await.status,
        StatusCode::UNAUTHORIZED
    );
}

// §10.2.4, TN-96, TN-97, OP-146 m.9, OP-149 m.16 (a): a passkey registered from a session signs
// in from the identifier step's discoverable button; that stepped-up session registers devices
#[tokio::test]
async fn a_passkey_registered_from_a_session_signs_in() {
    let e = env(7, "lg-g", AuthPolicy::DEFAULT).await;
    e.account("bob@example.com").await;
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("bob@example.com").await.step(), "complete");
    let reg = b
        .post(
            "/v1/account/passkeys",
            Some(json!({ "name": "bob@example.com" })),
        )
        .await;
    assert_eq!(reg.status, StatusCode::CREATED);
    let r = reg.json();
    let challenge = b64url_decode(r["options"]["challenge"].as_str().unwrap()).unwrap();
    let user = r["options"]["user"]["id"].as_str().unwrap().to_owned();
    let mut key = Authenticator::new(Key::es256());
    let (cdj, att) = key.register(RP_ID, ORIGIN, &challenge);
    let id = b64url_encode(&key.credential_id);
    let credential = json!({
        "id": id, "rawId": id, "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(&cdj),
            "attestationObject": b64url_encode(&att),
            "transports": ["internal"],
        },
        "clientExtensionResults": {},
    });
    let path = format!(
        "/v1/account/passkeys/{}",
        r["registration"].as_str().unwrap()
    );
    let done = b
        .post(&path, Some(json!({ "credential": credential })))
        .await;
    assert_eq!(
        done.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&done.body)
    );

    let mut c = e.browser("c");
    let first = c.start().await;
    let options = passkey_node(&first);
    assert_eq!(options["allowCredentials"], json!([]));
    let challenge = b64url_decode(options["challenge"].as_str().unwrap()).unwrap();
    let (cdj, ad, sig) = key.assert(RP_ID, ORIGIN, &challenge);
    let assertion = json!({
        "id": id, "rawId": id, "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(&cdj),
            "authenticatorData": b64url_encode(&ad),
            "signature": b64url_encode(&sig),
            "userHandle": user,
        },
        "clientExtensionResults": {},
    });
    let signed = c
        .submit(
            &first,
            "passkey",
            json!({ "passkey_credential": assertion.to_string() }),
        )
        .await;
    assert_eq!(
        signed.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&signed.body)
    );
    assert!(c.jar.contains_key("__Host-access-session"));
    let replayed = c
        .submit(&first, "passkey", json!({ "passkey_credential": "{}" }))
        .await;
    assert_eq!(replayed.status, StatusCode::GONE);
    devices_bind_the_session_party(&mut c).await;
}

/// OP-149 m.16 (a), L0-META-7: a stepped-up session's first device registers a new Party with
/// its own `party_register`; the identity plane binds the session's subject to that Party, names
/// it in later challenges and forwards later registrations for that Party only.
async fn devices_bind_the_session_party(c: &mut Web) {
    let party = b64url_encode(&[8; 16]);
    let mut register = async |party: &str, new: bool| {
        let ch = c.post("/v1/me/instances/challenges", None).await;
        assert_eq!(ch.status, StatusCode::CREATED);
        let mut body = json!({
            "challenge": ch.json()["challenge"],
            "party": party,
            "key": b64url_encode(&access_identity_session::domain::device::cose_key(
                &SoftSigner::generate_ed25519().unwrap().0.public_key(),
            )),
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-01-01T00:05:00Z",
            "ais": b64url_encode(&[0xd2; 40]),
        });
        if new {
            body["register_ais"] = json!(b64url_encode(&[0xd2; 40]));
        }
        (ch.json(), c.post("/v1/me/instances", Some(body)).await)
    };
    let (first, unbound) = register(&party, false).await;
    assert!(first.get("party").is_none());
    assert_eq!(unbound.status, StatusCode::BAD_REQUEST);
    assert_eq!(unbound.json()["code"], "invalid-party");
    let (_, created) = register(&party, true).await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.json()["party"], party.as_str());
    assert_eq!(
        b64url_decode(created.json()["instance"].as_str().unwrap())
            .unwrap()
            .len(),
        16
    );
    let (second, again) = register(&party, true).await;
    assert_eq!(second["party"], party.as_str());
    assert_eq!(again.json()["code"], "invalid-party");
    let (_, other) = register(&b64url_encode(&[6; 16]), false).await;
    assert_eq!(other.json()["code"], "invalid-party");
    let (_, next) = register(&party, false).await;
    assert_eq!(next.status, StatusCode::CREATED);
}

// §10.2.2, TN-102, OP-146 m.14 (h): a magic link is previewed without being consumed and
// confirmed by POST; another browser must confirm explicitly; only the starting browser gets
// the session. An e-mail code signs in once.
#[tokio::test]
async fn email_links_and_codes() {
    let e = env(8, "lg-h", AuthPolicy::DEFAULT).await;
    e.account("carol@example.com").await;
    let mut b = e.browser("b");
    let at = b.identify("carol@example.com").await;
    let methods: Vec<String> = at.json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n["method"].as_str().map(str::to_owned))
        .collect();
    assert!(methods.contains(&"magic_link".to_owned()));
    let waiting = b.submit(&at, "magic_link", json!({})).await;
    assert_eq!(waiting.status, StatusCode::OK);
    assert_eq!(waiting.messages(), ["email.sent"]);
    let link = e.outbox.last();
    let token = link
        .strip_prefix(&format!("https://{HOST}/login/link#"))
        .unwrap();
    for _ in 0..2 {
        let preview = b
            .post("/v1/login/link/preview", Some(json!({ "token": token })))
            .await;
        assert_eq!(
            preview.json(),
            json!({ "state": "confirm", "same_device": true })
        );
    }
    let mut phone = e.browser("p");
    let other = phone
        .post("/v1/login/link/confirm", Some(json!({ "token": token })))
        .await;
    assert_eq!(other.json(), json!({ "state": "needs_confirmation" }));
    let polled = b.get(&waiting.action()).await;
    assert_eq!(polled.messages(), ["email.sent"]);
    let yes = phone
        .post(
            "/v1/login/link/confirm",
            Some(json!({ "token": token, "other_device": true })),
        )
        .await;
    assert_eq!(
        yes.json(),
        json!({ "state": "confirmed", "same_device": false })
    );
    assert!(!phone.jar.contains_key("__Host-access-session"));
    let done = b.get(&waiting.action()).await;
    assert_eq!(done.step(), "complete");
    assert!(b.jar.contains_key("__Host-access-session"));
    let used = phone
        .post(
            "/v1/login/link/confirm",
            Some(json!({ "token": token, "other_device": true })),
        )
        .await;
    assert_eq!(used.status, StatusCode::GONE);

    let mut c = e.browser("c");
    let at = c.identify("carol@example.com").await;
    let code_step = c.submit(&at, "email_code", json!({})).await;
    assert_eq!(code_step.messages(), ["email.sent"]);
    let code = e.outbox.last();
    let wrong = c
        .submit(
            &code_step,
            "email_code",
            json!({ "email_code": "00000000" }),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let ok = c
        .submit(&code_step, "email_code", json!({ "email_code": code }))
        .await;
    assert_eq!(
        ok.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&ok.body)
    );
}

/// The answer with what differs between any two requests masked: the flow handle, the
/// passkey challenge and credential list (TN-97 makes those per identifier), the echoed
/// identifier, cookie values, `Date` and the request id.
fn masked(a: &Answer) -> (u16, Vec<(String, String)>, String) {
    let mut headers: Vec<(String, String)> = a
        .headers
        .iter()
        .filter(|(n, _)| *n != header::DATE && n.as_str() != "x-request-id")
        .map(|(n, v)| {
            let v = v.to_str().unwrap();
            let v = if *n == header::SET_COOKIE {
                let (name, rest) = v.split_once('=').unwrap();
                let attrs = rest.split_once(';').map_or("", |(_, a)| a);
                format!("{name}=*;{attrs}")
            } else if *n == header::CONTENT_LENGTH {
                "*".to_owned()
            } else {
                v.to_owned()
            };
            (n.as_str().to_owned(), v)
        })
        .collect();
    headers.sort();
    let mut body = a.json();
    if let Some(map) = body.as_object_mut() {
        map.insert("flow".into(), "*".into());
        map.insert("action".into(), "*".into());
    }
    if let Some(nodes) = body["nodes"].as_array_mut() {
        for n in nodes {
            if n.get("options").is_some() {
                n["options"]["challenge"] = "*".into();
                n["options"]["allowCredentials"] = "*".into();
            }
            if n["name"] == "identifier" && n.get("value").is_some() {
                n["value"] = "*".into();
            }
        }
    }
    (a.status.as_u16(), headers, body.to_string())
}

// OP-146 m.4 (h), CR-40, X34, TN-82, TN-96, TN-97, OP-146 m.10 (e): an active, an unknown, a
// locked and a deactivated account read the same at every step: status, header set, body
// bytes and no redirect
#[tokio::test]
async fn enumeration_parity_on_login() {
    let e = env(9, "lg-i", AuthPolicy::DEFAULT).await;
    e.account("ann1@example.com").await;
    let locked = e.account("ann3@example.com").await;
    let gone = e.account("ann4@example.com").await;
    let pg = PgAccounts(e.db.app.clone());
    change_status(&pg, &e.realm(), locked, AccountStatus::Locked, &ADMIN)
        .await
        .unwrap();
    deactivate(&pg, &e.realm(), gone, &ADMIN).await.unwrap();
    let who = [
        "ann1@example.com",
        "ann2@example.com",
        "ann3@example.com",
        "ann4@example.com",
    ];
    let mut identified = Vec::new();
    let mut wrong = Vec::new();
    let mut right = Vec::new();
    for (i, w) in who.iter().enumerate() {
        let mut b = e.browser(&format!("e{i}"));
        let at = b.identify(w).await;
        identified.push(masked(&at));
        let bad = b
            .submit(&at, "password", json!({ "password": "not the one" }))
            .await;
        assert!(!bad.headers.contains_key(header::LOCATION));
        wrong.push(masked(&bad));
        if i > 0 {
            e.advance(2_000);
            let good = b.submit(&bad, "password", json!({ "password": PW })).await;
            right.push(masked(&good));
        }
    }
    for set in [&identified, &wrong, &right] {
        for other in &set[1..] {
            assert_eq!(&set[0], other);
        }
    }
    assert_eq!(wrong[0].0, 401);
    assert!(wrong[0].2.contains("login.failed"));
    assert_eq!(right[0], wrong[0]);
}

fn percentile(sorted: &[u128], p: usize) -> u128 {
    sorted[(sorted.len() - 1) * p / 100]
}

// OP-146 m.4 (h), SA-59, TN-82: the timing half of the enumeration measurement, N = 200 per
// class, after successful sign-ins have set the padding mean. Nightly only (`just test-full`
// runs ignored tests); the PR suite asserts no timing.
#[tokio::test]
#[ignore = "nightly: login timing parity (OP-146 m.4 (h))"]
async fn enumeration_timing_parity_nightly() {
    const N: usize = 200;
    const PER_CLASS: usize = 4;
    let e = env_with(10, "lg-t", AuthPolicy::DEFAULT, true).await;
    let pg = PgAccounts(e.db.app.clone());
    let mut classes: Vec<Vec<String>> = vec![Vec::new(); 4];
    for i in 0..PER_CLASS {
        let active = format!("act{i}@example.com");
        e.account(&active).await;
        classes[0].push(active);
        classes[1].push(format!("unk{i}@example.com"));
        let locked = format!("lck{i}@example.com");
        let s = e.account(&locked).await;
        change_status(&pg, &e.realm(), s, AccountStatus::Locked, &ADMIN)
            .await
            .unwrap();
        classes[2].push(locked);
        let gone = format!("off{i}@example.com");
        let s = e.account(&gone).await;
        deactivate(&pg, &e.realm(), s, &ADMIN).await.unwrap();
        classes[3].push(gone);
    }
    let warm = "warm@example.com";
    e.account(warm).await;
    for i in 0..30 {
        e.advance(61_000);
        let mut b = e.browser(&format!("w{i}"));
        assert_eq!(b.sign_in(warm).await.step(), "complete");
    }
    let mut times: Vec<Vec<u128>> = vec![Vec::new(); 4];
    for round in 0..N {
        for (class, names) in classes.iter().enumerate() {
            let mut b = e.browser(&format!("t{round}-{class}"));
            let at = b.identify(&names[round % PER_CLASS]).await;
            e.advance(61_000);
            let started = std::time::Instant::now();
            let a = b
                .submit(&at, "password", json!({ "password": "not the password" }))
                .await;
            times[class].push(started.elapsed().as_micros());
            assert_eq!(a.status, StatusCode::UNAUTHORIZED);
        }
    }
    for t in &mut times {
        t.sort_unstable();
    }
    let (p50, p95) = (percentile(&times[0], 50), percentile(&times[0], 95));
    for t in &times[1..] {
        let (q50, q95) = (percentile(t, 50), percentile(t, 95));
        assert!(
            q50.abs_diff(p50) <= (p50 / 4).max(10_000),
            "p50 {q50} vs {p50}"
        );
        assert!(
            q95.abs_diff(p95) <= (p95 / 2).max(20_000),
            "p95 {q95} vs {p95}"
        );
    }
}

// OP-149 m.6, m.8, m.9, m.16 (a), G57: the product endpoints need a live session; a challenge
// names what the device's own Exercises sign; registering a device needs AAL2 and a fresh
// step-up; auth_context is the session's artifact signed by the realm key; an approval call never
// redirects to an unregistered URI
#[tokio::test]
async fn product_endpoints_follow_the_frontend_contract() {
    use access_identity_session::domain::auth_context::{CONTENT_TYPE, DIGEST_LABEL};
    use suiss_crypto::cose::{Algorithm, KeySet, verify_sign1};
    use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
    use suiss_crypto::digest::context_digest;

    let e = env(41, "lg-me", AuthPolicy::DEFAULT).await;
    e.account("alice@example.com").await;
    let mut anon = e.browser("anon");
    assert_eq!(
        anon.post("/v1/me/instances/challenges", None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        anon.post("/v1/me/auth-context", None).await.status,
        StatusCode::UNAUTHORIZED
    );

    let mut b = e.browser("b");
    b.sign_in("alice@example.com").await;
    let c = b.post("/v1/me/instances/challenges", None).await;
    assert_eq!(c.status, StatusCode::CREATED);
    assert_eq!(
        b64url_decode(c.json()["challenge"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    // OP-149 m.16 (a)
    assert_eq!(
        b64url_decode(c.json()["domain"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        b64url_decode(c.json()["basis"].as_str().unwrap())
            .unwrap()
            .len(),
        16
    );
    assert_eq!(c.json()["pep"], "access-identity");
    assert!(c.json().get("party").is_none());
    let registration = json!({
        "challenge": c.json()["challenge"],
        "party": b64url_encode(&[8; 16]),
        "key": "pQECIAEhWCA",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-01-01T00:05:00Z",
        "ais": "0oRD",
        "register_ais": "0oRD",
    });
    let weak = b.post("/v1/me/instances", Some(registration.clone())).await;
    assert_eq!(weak.status, StatusCode::FORBIDDEN);
    assert_eq!(weak.json()["code"], "step-up-required");
    let mut extra = registration;
    extra["pop"] = json!("b");
    let extra = b.post("/v1/me/instances", Some(extra)).await;
    assert_eq!(extra.status, StatusCode::BAD_REQUEST);
    // OP-149 m.16 (f)
    let termination = json!({
        "nonce": b64url_encode(&[1; 16]),
        "basis": b64url_encode(&[2; 16]),
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-01-01T00:05:00Z",
        "ais": b64url_encode(&[0xd2; 8]),
    });
    let prefixed = b
        .send(
            "DELETE",
            "/v1/me/instances/ins_0123456789abcdefghjkmnpqrs",
            Some(termination.clone()),
            Some("del-1"),
        )
        .await;
    assert_eq!(prefixed.status, StatusCode::BAD_REQUEST);
    let by_id = b
        .send(
            "DELETE",
            &format!("/v1/me/instances/{}", b64url_encode(&[9; 16])),
            Some(termination),
            Some("del-2"),
        )
        .await;
    assert_eq!(by_id.status, StatusCode::FORBIDDEN);
    assert_eq!(by_id.json()["code"], "step-up-required");

    let issued = b.post("/v1/me/auth-context", None).await;
    assert_eq!(issued.status, StatusCode::OK);
    let sign1 = b64url_decode(issued.json()["auth_context"].as_str().unwrap()).unwrap();
    let key = e.signer.0.public_key();
    let mut keys = KeySet::default();
    keys.insert(access_kernel::verify::key_scope::thumbprint(&key), key)
        .unwrap();
    keys.allowed.insert(Algorithm::Ed25519);
    let verified =
        verify_sign1(&suiss_crypto::sig::PureBackend, &sign1, &keys, CONTENT_TYPE).unwrap();
    assert_eq!(
        b64url_decode(issued.json()["digest"].as_str().unwrap()).unwrap(),
        context_digest(DIGEST_LABEL, &verified.payload).0
    );
    let Cbor::Map(fields) = dcbor::decode(&verified.payload, Limits::CEILING).unwrap() else {
        panic!("not a map");
    };
    let aal = fields
        .iter()
        .find(|(k, _)| *k == Cbor::text("aal"))
        .map(|(_, v)| v.clone());
    assert_eq!(aal, Some(Cbor::text("aal1")));
    let bound = b
        .post(
            "/v1/me/auth-context",
            Some(json!({
                "content_type": "application/json; charset=utf-8",
                "content_digest": b64url_encode(&[1; 32]),
            })),
        )
        .await;
    assert_eq!(bound.status, StatusCode::BAD_REQUEST);
    assert_eq!(bound.json()["code"], "invalid-content");

    let digest = b64url_encode(&[3; 32]);
    let unregistered = b
        .get(&format!(
            "/v1/approve?request={digest}&redirect_uri=https%3A%2F%2Fnope.example%2Fcb&state=s1"
        ))
        .await;
    assert_eq!(unregistered.status, StatusCode::BAD_REQUEST);
    assert_eq!(unregistered.json()["code"], "invalid-redirect-uri");
    assert!(unregistered.headers.get(header::LOCATION).is_none());
    let no_state = b
        .get(&format!(
            "/v1/approve?request={digest}&redirect_uri=https%3A%2F%2Fnope.example%2Fcb"
        ))
        .await;
    assert_eq!(no_state.status, StatusCode::BAD_REQUEST);
}
