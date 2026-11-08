//! Social sign-in, linked sign-ins and combined accounts end to end (IDP-31, P-ID-9, TN-65,
//! TN-67, INV-39, OP-153 m.3 (l), (m)): the real routers over a real PostgreSQL, a provider that
//! signs ID tokens in process, and secrets from a directory.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::unused_async_trait_impl,
    clippy::assigning_clones,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_crypto::webauthn::DecoyKey;
use access_http::login::{Peer, router, social_router};
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::SystemEntropy;
use access_identity_account::app::accounts::{
    PasswordServices, change_status, create, set_password,
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
use access_identity_account::notify::message::Message;
use access_identity_account::notify::ports::Notifier;
use access_identity_account::ports::{BreachRanges, RangeUnavailable};
use access_identity_federation::adapters::FileSecrets;
use access_identity_federation::app::DevClient;
use access_identity_federation::domain::preset::Presets;
use access_identity_federation::ports::{Answer as ProviderAnswer, ProviderHttp, Unreachable};
use access_identity_oauth::app::Discovery;
use access_identity_oauth::domain::issuer::Issuer;
use access_identity_oauth::domain::request::Params;
use access_identity_oauth::ports::{Directory, Keys, RealmEntry, Unavailable};
use access_identity_session::domain::realm_policy::RealmSignin;
use access_identity_session::domain::requirement::AuthPolicy;
use access_identity_session::domain::session::SessionPolicy;
use access_identity_ui::app::Hosted;
use access_identity_ui::app::social::Social;
use access_identity_ui::ports::{Clock, Kits, Messages, RealmKit};
use access_identity_webauthn::adapters::RealmDecoyKeys;
use access_identity_webauthn::domain::ids::RealmId as WaRealm;
use access_identity_webauthn::domain::policy::RealmPolicy;
use access_identity_webauthn::domain::rp::{RelyingParty, RpId};
use access_kernel::json::b64url_encode;
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::federation::SocialRow;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{Decision, bind};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use axum::Router;
use axum::body::Body as HttpBody;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "social.example";
const PW: &str = "correct horse battery";
const T0: u64 = 1_800_000_000_000;
const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};
const ISS: &str = "https://accounts.google.com";

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct Corpus;

impl BreachRanges for Corpus {
    fn range(&self, _: &str) -> impl Future<Output = Result<String, RangeUnavailable>> + Send {
        std::future::ready(Ok(String::new()))
    }
}

#[derive(Clone, Default)]
struct Outbox;

struct Recording;

impl Notifier for Recording {
    fn notify(
        &self,
        _: &mut TenantTx,
        m: &Message,
    ) -> impl Future<Output = Result<EventId, NotifyError>> + Send {
        let checked = m.validate().map_err(NotifyError::from);
        std::future::ready(checked.map(|()| EventId([1; 16])))
    }
}

impl Messages for Outbox {
    type For<'a> = Recording;

    fn notifier<'a>(&'a self, _: &'a Realm<'a>) -> Recording {
        Recording
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

/// What the in-process provider says next.
#[derive(Default)]
struct Says {
    nonce: String,
    sub: String,
    email: Option<(String, bool)>,
    aud: Option<String>,
    forms: Vec<String>,
}

/// An OpenID provider that signs with one ES256 key; its token endpoint answers the code
/// exchange with an ID token for whatever [`Says`] holds.
#[derive(Clone)]
struct Provider {
    key: Arc<EcdsaKeyPair>,
    says: Arc<Mutex<Says>>,
}

impl Provider {
    fn new() -> Self {
        Self {
            key: Arc::new(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap()),
            says: Arc::default(),
        }
    }

    fn jwks(&self) -> Vec<u8> {
        let pk = self.key.public_key().as_ref();
        json!({ "keys": [{ "kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig",
                           "x": b64url_encode(&pk[1..33]), "y": b64url_encode(&pk[33..65]) }] })
        .to_string()
        .into_bytes()
    }

    fn id_token(&self, client_id: &str) -> String {
        let s = self.says.lock().unwrap();
        let mut claims = json!({
            "iss": ISS,
            "aud": s.aud.clone().unwrap_or_else(|| client_id.to_owned()),
            "sub": s.sub,
            "exp": T0 / 1000 + 600,
            "iat": T0 / 1000,
            "nonce": s.nonce,
            "name": "Ada",
        });
        if let Some((e, v)) = &s.email {
            claims["email"] = json!(e);
            claims["email_verified"] = json!(v);
        }
        let input = format!(
            "{}.{}",
            b64url_encode(br#"{"alg":"ES256","kid":"k1"}"#),
            b64url_encode(claims.to_string().as_bytes())
        );
        let sig = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap();
        format!("{input}.{}", b64url_encode(sig.as_ref()))
    }
}

impl ProviderHttp for Provider {
    async fn get_json(&self, url: &str, _: Option<&str>) -> Result<ProviderAnswer, Unreachable> {
        if url == "https://idp.test/jwks" {
            Ok((200, self.jwks()))
        } else {
            Ok((404, Vec::new()))
        }
    }

    async fn post_form(&self, url: &str, form: &str) -> Result<ProviderAnswer, Unreachable> {
        if url != "https://idp.test/token" {
            return Ok((404, Vec::new()));
        }
        self.says.lock().unwrap().forms.push(form.to_owned());
        let p = Params::parse(form).unwrap();
        let client = p.get("client_id").unwrap().to_owned();
        let token = self.id_token(&client);
        Ok((
            200,
            json!({ "access_token": "at", "token_type": "Bearer", "id_token": token })
                .to_string()
                .into_bytes(),
        ))
    }
}

/// The shipped Google preset at the in-process provider's endpoints, signing with ES256.
fn presets() -> Presets {
    let google = r#"
id = "google"
display_name = "Google"
protocol = "oidc"
issuer = "https://accounts.google.com"
authorization_endpoint = "https://idp.test/authorize"
token_endpoint = "https://idp.test/token"
jwks_uri = "https://idp.test/jwks"
scopes = ["openid", "email", "profile"]
logo = "google"
subject = ["sub"]
algorithms = ["ES256"]

[email]
kind = "authoritative_domains"
domains = ["gmail.com", "googlemail.com"]
hosted_domain_claim = "hd"
"#;
    Presets::from_files([("google", google)]).unwrap()
}

struct Env {
    db: TestDb,
    tenant: TenantId,
    realm: RealmId,
    domain: DomainId,
    kit: Arc<RealmKit>,
    app: Router,
    provider: Provider,
    hasher: Hasher,
    pos: AtomicU64,
}

fn secrets_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "access-social-secrets-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace("::", "-")
    ));
    std::fs::create_dir_all(dir.join("social")).unwrap();
    std::fs::write(dir.join("social/google"), "s3cret\n").unwrap();
    dir
}

async fn env(seed: u8, slug: &str) -> Env {
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
    let wa = WaRealm::from_bytes(*realm.as_bytes());
    let kit = Arc::new(RealmKit {
        tenant,
        realm,
        issuer: format!("https://{HOST}"),
        name: "Acme".into(),
        kek: Arc::new(SoftKek::new("realm-kek:1", [seed; 32])),
        index: Arc::new(access_crypto::realm_index::RealmIndexKey::new(Secret::new(
            [seed; 32],
        ))),
        ids: IdKey::new(Secret::new([seed.wrapping_add(1); 32])),
        decoys: RealmDecoyKeys::default().with(wa, DecoyKey::new(Secret::new([9; 32]))),
        rp: RelyingParty {
            realm: wa,
            rp_id: RpId::parse(HOST).unwrap(),
            name: "Acme".into(),
            pinned: true,
            related: Vec::new(),
        },
        webauthn: RealmPolicy::default(),
        auth: AuthPolicy::DEFAULT,
        lifetimes: SessionPolicy::DEFAULT,
        signin: RealmSignin::default(),
    });
    let clock = TestClock(Arc::new(AtomicU64::new(T0)));
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
        products: db.reader.clone(),
        clock,
        messages: Outbox,
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        hasher: Hasher::new(config),
        redirect_to: "/".into(),
        hooks: Arc::new(access_identity_hooks::ports::NoHooks),
        risk: access_identity_session::app::RiskServices::without_sources(),
        signup: access_identity_ui::app::signup::Signup::without_providers().unwrap(),
    });
    let provider = Provider::new();
    let social = Social {
        http: provider.clone(),
        secrets: FileSecrets(Some(secrets_dir())),
        dev: BTreeMap::from([(
            String::from("google"),
            DevClient {
                client_id: String::from("shared-dev"),
                secret_ref: String::from("secret://social/google"),
            },
        )]),
        presets: presets(),
    };
    let app = router(
        Discovery::new(Dir(entry.clone()), NoKeys),
        hosted.clone(),
        None,
    )
    .merge(social_router(
        Discovery::new(Dir(entry), NoKeys),
        hosted,
        social,
    ));
    Env {
        db,
        tenant,
        realm,
        domain: d,
        kit,
        app,
        provider,
        hasher: Hasher::new(config),
        pos: AtomicU64::new(1),
    }
}

impl Env {
    async fn account(&self, who: &str) -> [u8; 16] {
        let pg = PgAccounts::sealed(self.db.app.clone(), self.kit.vault());
        let id = Identifier::new(IdentifierKind::Email, who).unwrap();
        let realm = self.kit.realm();
        let s = create(&pg, &realm, &[id], &ADMIN).await.unwrap();
        let services = PasswordServices {
            hasher: &self.hasher,
            ranges: &Corpus,
            entropy: &SystemEntropy,
        };
        set_password(&pg, &realm, &services, s, PW, &ADMIN)
            .await
            .unwrap();
        for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
            change_status(&pg, &realm, s, to, &ADMIN).await.unwrap();
        }
        s
    }

    /// Writes the realm's Google preset under a committed `idp.social.enable` ALLOW (EI-25);
    /// `client` `None` names the shared development client.
    async fn enable(&self, client: Option<&str>) {
        let (lease, head) = acquire_lease(
            &self.db.sequencer,
            &self.domain,
            "t",
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();
        let n = self.pos.fetch_add(1, Ordering::SeqCst);
        let pos = head.pos + 1;
        let leaf = [u8::try_from(n).unwrap(); 32];
        let nonce = vec![u8::try_from(n).unwrap(); 16];
        commit_batch(
            &self.db.sequencer,
            &self.domain,
            *self.tenant.as_bytes(),
            &CommitBatch {
                epoch: lease.epoch,
                after: head.pos,
                records: vec![LogRecord {
                    pos,
                    kind: "decision",
                    recorded_at: 2,
                    leaf_hash: leaf,
                    envelope: vec![0xa1, 1],
                }],
                head: HeadRow {
                    pos,
                    epoch: lease.epoch,
                    leaf_hash: leaf,
                    recorded_at: 2,
                    frontier: vec![leaf],
                },
                nonces: vec![NonceRow {
                    nonce: nonce.clone(),
                    actor: vec![1],
                    intent_digest: [9; 32],
                    decision_pos: pos,
                    outcome: String::from("allow"),
                    render_digest: None,
                    tier: None,
                }],
                outbox: vec![],
                proofs: vec![],
                reads: vec![],
                writes: vec![],
                draws: vec![],
                single_use: vec![],
                effects: vec![],
            },
        )
        .await
        .unwrap();
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let bound = bind(
            &mut tx,
            &Decision {
                domain: &self.domain,
                position: pos,
                nonce: &nonce,
                intent: [9; 32],
                change: [5; 32],
                action: "idp.social.enable",
            },
        )
        .await
        .unwrap()
        .unwrap();
        tx.put_social_provider(
            &bound,
            &SocialRow {
                preset: String::from("google"),
                client_id: client.map(String::from),
                client_secret_ref: client.map(|_| String::from("secret://social/google")),
                active: true,
                previous_client_id: None,
                client_changed_ms: None,
                position: 0,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    async fn sandbox(&self) {
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        access_store::sandbox::mark(
            &mut t,
            &self.domain,
            access_store::sandbox::Budget {
                exercises_per_day: 10,
                projections_per_day: 10,
            },
        )
        .await
        .unwrap();
        t.commit().await.unwrap();
    }

    fn says(&self, sub: &str, email: Option<(&str, bool)>) {
        let mut s = self.provider.says.lock().unwrap();
        s.sub = sub.to_owned();
        s.email = email.map(|(e, v)| (e.to_owned(), v));
        s.aud = None;
    }

    fn browser(&self, n: u8) -> Web {
        Web {
            ip: Ipv4Addr::new(10, 0, 0, n),
            app: self.app.clone(),
            jar: BTreeMap::new(),
            n: 0,
        }
    }

    /// The account the provider's subject `sub` is linked to.
    async fn link_of(&self, sub: &str) -> Option<[u8; 16]> {
        let key = access_identity_federation::domain::key::identity_key(ISS, sub);
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let row = t.federated_by_key(&key).await.unwrap();
        t.commit().await.unwrap();
        row.map(|r| r.subject)
    }

    async fn links_of(&self, subject: [u8; 16]) -> Vec<access_store::federation::FederatedRow> {
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let rows = t.federated_of(subject).await.unwrap();
        t.commit().await.unwrap();
        rows
    }

    async fn live_identifiers(&self, subject: [u8; 16]) -> usize {
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let n = t
            .identifiers(subject)
            .await
            .unwrap()
            .iter()
            .filter(|i| i.live)
            .count();
        t.commit().await.unwrap();
        n
    }

    async fn head(&self) -> u64 {
        access_store::authority::read_head(&self.db.sequencer, &self.domain)
            .await
            .unwrap()
            .pos
    }

    async fn status(&self, subject: [u8; 16]) -> String {
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let s = t.subject(subject, false).await.unwrap().unwrap().status;
        t.commit().await.unwrap();
        s
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

    fn location(&self) -> String {
        self.headers
            .get(header::LOCATION)
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default()
    }

    fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_owned()
    }
}

struct Web {
    ip: Ipv4Addr,
    app: Router,
    jar: BTreeMap<String, String>,
    n: u64,
}

impl Web {
    async fn send(&mut self, method: &str, path: &str, body: Option<Value>) -> Answer {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, HOST)
            .header("x-request-id", "req-1");
        if !self.jar.is_empty() {
            let cookies: Vec<String> = self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect();
            req = req.header(header::COOKIE, cookies.join("; "));
        }
        if method != "GET" {
            self.n += 1;
            req = req
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", format!("k-{}-{}", self.ip, self.n));
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

    async fn sign_in(&mut self, who: &str) {
        let a = self.send("POST", "/v1/login/flows", None).await;
        assert_eq!(a.status, StatusCode::CREATED);
        let action = a.json()["action"].as_str().unwrap().to_owned();
        let b = self
            .send(
                "POST",
                &action,
                Some(json!({ "method": "identifier", "fields": { "identifier": who } })),
            )
            .await;
        let action = b.json()["action"].as_str().unwrap().to_owned();
        let c = self
            .send(
                "POST",
                &action,
                Some(json!({ "method": "password", "fields": { "password": PW } })),
            )
            .await;
        assert_eq!(
            c.json()["step"],
            "complete",
            "{}",
            String::from_utf8_lossy(&c.body)
        );
    }

    /// Follows the provider round trip of `start` (a `303` to the provider) back to the callback.
    async fn round_trip(&mut self, e: &Env, start: &Answer) -> Answer {
        let to = if start.status == StatusCode::SEE_OTHER {
            start.location()
        } else {
            start.json()["redirect_to"].as_str().unwrap().to_owned()
        };
        assert!(to.starts_with("https://idp.test/authorize?"), "{to}");
        let p = Params::parse(to.split_once('?').unwrap().1).unwrap();
        e.provider.says.lock().unwrap().nonce = p.get("nonce").unwrap().to_owned();
        let state = p.get("state").unwrap().to_owned();
        assert_eq!(
            p.get("redirect_uri").unwrap(),
            format!("https://{HOST}/v1/login/social/google/callback")
        );
        self.send(
            "GET",
            &format!("/v1/login/social/google/callback?code=c-1&state={state}"),
            None,
        )
        .await
    }

    async fn social(&mut self, e: &Env) -> Answer {
        let start = self.send("GET", "/v1/login/social/google", None).await;
        assert_eq!(start.status, StatusCode::SEE_OTHER, "{}", start.code());
        self.round_trip(e, &start).await
    }
}

// IDP-31, §10.2.6, P-ID-9, CR-40, OP-153 m.3 (l)
#[tokio::test]
async fn a_social_sign_in_creates_the_account_once_and_then_finds_it_by_its_key() {
    let e = env(0x41, "soc-a").await;
    e.enable(Some("own-client")).await;
    e.says("g-1", Some(("ada@gmail.com", true)));
    let mut w = e.browser(1);
    let first = w.social(&e).await;
    assert_eq!(first.status, StatusCode::SEE_OTHER, "{}", first.code());
    assert_eq!(first.location(), "/");
    assert!(w.jar.contains_key("__Host-access-session"));
    let form = e.provider.says.lock().unwrap().forms[0].clone();
    assert!(form.contains("client_id=own-client") && form.contains("client_secret=s3cret"));
    assert!(form.contains("code_verifier="));
    let subject = e.link_of("g-1").await.unwrap();
    assert_eq!(e.status(subject).await, "active");
    assert_eq!(
        e.live_identifiers(subject).await,
        1,
        "a vouched, free address signs in"
    );

    let mut again = e.browser(2);
    let second = again.social(&e).await;
    assert_eq!(
        (second.status, second.location()),
        (first.status, first.location()),
        "the same answer for a known identity"
    );
    assert_eq!(
        e.link_of("g-1").await,
        Some(subject),
        "found by (provider, subject)"
    );
    assert_eq!(e.links_of(subject).await.len(), 1, "not created again");

    // §10.2.6
    let replay = w
        .send(
            "GET",
            "/v1/login/social/google/callback?code=c&state=x",
            None,
        )
        .await;
    assert_eq!(replay.status, StatusCode::GONE);
}

// IDP-31 (3), §7.1, MD-5, TN-3, TN-65 (7), CR-40
#[tokio::test]
async fn a_matching_verified_address_never_links_and_the_answer_does_not_tell() {
    let e = env(0x42, "soc-b").await;
    e.enable(Some("own-client")).await;
    let ada = e.account("ada@gmail.com").await;
    e.says("g-2", Some(("ada@gmail.com", true)));
    let mut w = e.browser(1);
    let a = w.social(&e).await;
    assert_eq!(
        (a.status, a.location()),
        (StatusCode::SEE_OTHER, String::from("/"))
    );
    let new = e.link_of("g-2").await.unwrap();
    assert_ne!(new, ada, "an address is never a key");
    assert_eq!(e.links_of(ada).await.len(), 0);
    assert_eq!(e.live_identifiers(ada).await, 1);
    assert_eq!(
        e.live_identifiers(new).await,
        0,
        "the address stays only with its owner"
    );
}

// §10.2.6, MD-8
#[tokio::test]
async fn a_wrong_audience_or_nonce_is_refused_and_nothing_is_created() {
    let e = env(0x43, "soc-c").await;
    e.enable(Some("own-client")).await;
    e.says("g-3", None);
    e.provider.says.lock().unwrap().aud = Some(String::from("another-client"));
    let mut w = e.browser(1);
    let a = w.social(&e).await;
    assert_eq!(
        (a.status, a.code().as_str()),
        (StatusCode::UNAUTHORIZED, "social-sign-in-failed")
    );

    e.provider.says.lock().unwrap().aud = None;
    let mut w = e.browser(2);
    let start = w.send("GET", "/v1/login/social/google", None).await;
    let to = start.location();
    let p = Params::parse(to.split_once('?').unwrap().1).unwrap();
    e.provider.says.lock().unwrap().nonce = String::from("not-the-flows-nonce");
    let state = p.get("state").unwrap().to_owned();
    let b = w
        .send(
            "GET",
            &format!("/v1/login/social/google/callback?code=c&state={state}"),
            None,
        )
        .await;
    assert_eq!(
        (b.status, b.code().as_str()),
        (StatusCode::UNAUTHORIZED, "social-sign-in-failed")
    );
    assert_eq!(e.link_of("g-3").await, None);

    // §10.2.6
    let mut w = e.browser(3);
    let start = w.send("GET", "/v1/login/social/google", None).await;
    let to = start.location();
    let p = Params::parse(to.split_once('?').unwrap().1).unwrap();
    let state = p.get("state").unwrap().to_owned();
    let mut other = e.browser(4);
    let c = other
        .send(
            "GET",
            &format!("/v1/login/social/google/callback?code=c&state={state}"),
            None,
        )
        .await;
    assert_eq!(c.status, StatusCode::GONE);
}

// IDP-31 (4), OP-153 m.3 (l)
#[tokio::test]
async fn the_shared_development_client_works_only_in_a_sandbox_realm() {
    let e = env(0x44, "soc-d").await;
    e.enable(None).await;
    let mut w = e.browser(1);
    let a = w.send("GET", "/v1/login/social/google", None).await;
    assert_eq!(
        (a.status, a.code().as_str()),
        (StatusCode::CONFLICT, "shared-social-key-in-production")
    );
    e.sandbox().await;
    e.says("g-4", None);
    let b = w.social(&e).await;
    assert_eq!(b.status, StatusCode::SEE_OTHER, "{}", b.code());
    let form = e.provider.says.lock().unwrap().forms[0].clone();
    assert!(form.contains("client_id=shared-dev"));
    let none = w.send("GET", "/v1/login/social/github", None).await;
    assert_eq!(none.status, StatusCode::NOT_FOUND);
}

// TN-65, P-ID-9, TN-68, §8.5 S11
#[tokio::test]
async fn linking_needs_a_fresh_session_and_the_providers_proof_and_ends_every_session() {
    let e = env(0x45, "soc-e").await;
    e.enable(Some("own-client")).await;
    let ada = e.account("ada@example.com").await;
    let mut w = e.browser(1);
    w.sign_in("ada@example.com").await;
    let start = w
        .send(
            "POST",
            "/v1/account/linked",
            Some(json!({ "provider": "google" })),
        )
        .await;
    assert_eq!(start.status, StatusCode::OK, "{}", start.code());
    e.says("g-5", Some(("ada@example.com", false)));
    let done = w.round_trip(&e, &start).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.code());
    assert_eq!(done.json()["signed_out"], true);
    assert!(!w.jar.contains_key("__Host-access-session"));
    assert_eq!(e.link_of("g-5").await, Some(ada));

    let mut w = e.browser(2);
    w.sign_in("ada@example.com").await;
    let list = w.send("GET", "/v1/account/linked", None).await;
    let linked = list.json()["linked"].as_array().unwrap().clone();
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0]["provider"], "google");
    assert!(!list.body.windows(6).any(|x| x == b"merged"));
    let link = linked[0]["link"].as_str().unwrap().to_owned();
    let gone = w
        .send("DELETE", &format!("/v1/account/linked/{link}"), None)
        .await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT);
    assert_eq!(e.link_of("g-5").await, None);

    // TN-68
    e.says("g-6", None);
    let mut s = e.browser(3);
    s.social(&e).await;
    let list = s.send("GET", "/v1/account/linked", None).await;
    let link = list.json()["linked"][0]["link"]
        .as_str()
        .unwrap()
        .to_owned();
    let kept = s
        .send("DELETE", &format!("/v1/account/linked/{link}"), None)
        .await;
    assert_eq!(
        (kept.status, kept.code().as_str()),
        (StatusCode::CONFLICT, "last-sign-in-method")
    );
}

// INV-39, TNI-11, TN-67, OP-153 m.3 (m)
#[tokio::test]
async fn combining_moves_identities_only_after_a_snapshot_and_nothing_of_the_authority_plane() {
    let e = env(0x46, "soc-f").await;
    e.enable(Some("own-client")).await;
    let ada = e.account("ada@example.com").await;
    e.says("g-7", None);
    let mut social = e.browser(1);
    social.social(&e).await;
    let absorbed = e.link_of("g-7").await.unwrap();
    let head_before = e.head().await;

    let offer = social
        .send("POST", "/v1/account/combine", Some(json!({})))
        .await;
    assert_eq!(offer.status, StatusCode::CREATED, "{}", offer.code());
    let ticket = offer.json()["ticket"].as_str().unwrap().to_owned();
    let mut survivor = e.browser(2);
    survivor.sign_in("ada@example.com").await;
    let same = social
        .send(
            "POST",
            "/v1/account/combine",
            Some(json!({ "ticket": ticket })),
        )
        .await;
    assert_eq!(
        same.status,
        StatusCode::CONFLICT,
        "an account does not absorb itself"
    );

    let offer = social
        .send("POST", "/v1/account/combine", Some(json!({})))
        .await;
    let ticket = offer.json()["ticket"].as_str().unwrap().to_owned();
    let done = survivor
        .send(
            "POST",
            "/v1/account/combine",
            Some(json!({ "ticket": ticket })),
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.code());
    assert!(
        done.json()["notice"]
            .as_str()
            .unwrap()
            .contains("must be given again")
    );
    assert_eq!(e.status(absorbed).await, "tombstone");
    assert_eq!(e.link_of("g-7").await, Some(ada));
    assert_eq!(e.links_of(absorbed).await.len(), 0);
    assert_eq!(
        e.head().await,
        head_before,
        "no Grant, lineage or holding moves"
    );
    let reused = survivor
        .send(
            "POST",
            "/v1/account/combine",
            Some(json!({ "ticket": ticket })),
        )
        .await;
    assert_eq!(reused.status, StatusCode::CONFLICT);
}
