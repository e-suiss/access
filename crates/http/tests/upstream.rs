//! Enterprise upstream sign-in end to end (OP-155 m.3 (h); IDP-27, IDP-34, TN-66, TN-95, TN-98,
//! TN-108, INV-17, SEC9, GHSA-x8cg-3c8h-gw55): the real routers over a real PostgreSQL, an
//! OpenID provider that signs ID tokens in process, an Acceptance switch and a recording client
//! assertion signer.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::unused_async_trait_impl,
    clippy::many_single_char_names,
    clippy::assigning_clones,
    clippy::assert_is_empty,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_crypto::webauthn::DecoyKey;
use access_http::login::{Peer, router, social_router, upstream_router};
use access_identity_account::app::Realm;
use access_identity_account::app::hasher::{Hasher, HasherConfig};
use access_identity_account::app::local::LocalLimiter;
use access_identity_account::app::login::LoginGate;
use access_identity_account::domain::claims::ClaimOrder;
use access_identity_account::domain::password::Argon2Params;
use access_identity_account::domain::throttle::ThrottlePolicy;
use access_identity_account::notify::NotifyError;
use access_identity_account::notify::envelope::EventId;
use access_identity_account::notify::message::{Body as MessageBody, Message};
use access_identity_account::notify::ports::Notifier;
use access_identity_federation::adapters::FileSecrets;
use access_identity_federation::domain::connection::{
    AssuranceMap, MapEntry, MatchOn, Profile, issuer_id,
};
use access_identity_federation::domain::key::identity_key;
use access_identity_federation::domain::preset::Presets;
use access_identity_federation::ports::{
    Answer as ProviderAnswer, ClientAssertion, ProviderHttp, Signed, Trusted, Unreachable,
    UpstreamTrust,
};
use access_identity_oauth::app::Discovery;
use access_identity_oauth::domain::issuer::Issuer;
use access_identity_oauth::domain::request::Params;
use access_identity_oauth::ports::{Directory, Keys, RealmEntry, Unavailable};
use access_identity_session::domain::realm_policy::RealmSignin;
use access_identity_session::domain::requirement::AuthPolicy;
use access_identity_session::domain::session::SessionPolicy;
use access_identity_ui::app::Hosted;
use access_identity_ui::app::social::Social;
use access_identity_ui::app::upstream::Upstreams;
use access_identity_ui::ports::{Clock, Kits, Messages, RealmKit};
use access_identity_webauthn::adapters::RealmDecoyKeys;
use access_identity_webauthn::domain::ids::RealmId as WaRealm;
use access_identity_webauthn::domain::policy::RealmPolicy;
use access_identity_webauthn::domain::rp::{RelyingParty, RpId};
use access_kernel::claim::body::Body as ClaimBody;
use access_kernel::json::b64url_encode;
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
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

const HOST: &str = "upstream.example";
const T0: u64 = 1_800_000_000_000;
const CORP: &str = "https://idp.test/corp";
const OTHER: &str = "https://idp.test/other";

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Counts the Relay messages queued, by kind.
#[derive(Clone, Default)]
struct Outbox(Arc<Mutex<Vec<String>>>);

struct Recording(Arc<Mutex<Vec<String>>>);

impl Notifier for Recording {
    fn notify(
        &self,
        _: &mut TenantTx,
        m: &Message,
    ) -> impl Future<Output = Result<EventId, NotifyError>> + Send {
        let checked = m.validate().map_err(NotifyError::from);
        if let MessageBody::UpstreamSubjectConflict { upstream, .. } = &m.body {
            self.0.lock().unwrap().push(upstream.clone());
        }
        std::future::ready(checked.map(|()| EventId([1; 16])))
    }
}

impl Messages for Outbox {
    type For<'a> = Recording;

    fn notifier<'a>(&'a self, _: &'a Realm<'a>) -> Recording {
        Recording(self.0.clone())
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
    email: Option<String>,
    iss: Option<String>,
    acr: Option<String>,
    tckn: Option<String>,
    down: bool,
    forms: Vec<String>,
    tokens: Vec<String>,
}

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
            "iss": s.iss.clone().unwrap_or_else(|| CORP.to_owned()),
            "aud": client_id,
            "sub": s.sub,
            "exp": T0 / 1000 + 600,
            "iat": T0 / 1000,
            "auth_time": T0 / 1000,
            "nonce": s.nonce,
            "amr": ["pwd"],
            "name": "Ada",
        });
        if let Some(e) = &s.email {
            claims["email"] = json!(e);
            claims["email_verified"] = json!(true);
        }
        if let Some(a) = &s.acr {
            claims["acr"] = json!(a);
        }
        if let Some(t) = &s.tckn {
            claims["tckn"] = json!(t);
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

fn discovery(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": "https://idp.test/authorize",
        "token_endpoint": "https://idp.test/token",
        "jwks_uri": "https://idp.test/jwks",
        "id_token_signing_alg_values_supported": ["none", "HS256", "ES256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_post"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "authorization_response_iss_parameter_supported": true,
        "ui_locales_supported": ["en", "tr"],
    })
}

impl ProviderHttp for Provider {
    async fn get_json(&self, url: &str, _: Option<&str>) -> Result<ProviderAnswer, Unreachable> {
        if self.says.lock().unwrap().down {
            return Err(Unreachable);
        }
        let body = match url {
            "https://idp.test/jwks" => return Ok((200, self.jwks())),
            "https://idp.test/corp/.well-known/openid-configuration" => discovery(CORP),
            "https://idp.test/other/.well-known/openid-configuration" => discovery(OTHER),
            _ => return Ok((404, Vec::new())),
        };
        Ok((200, body.to_string().into_bytes()))
    }

    async fn post_form(&self, url: &str, form: &str) -> Result<ProviderAnswer, Unreachable> {
        if url != "https://idp.test/token" || self.says.lock().unwrap().down {
            return Err(Unreachable);
        }
        self.says.lock().unwrap().forms.push(form.to_owned());
        let p = Params::parse(form).unwrap();
        let client = p.get("client_id").unwrap().to_owned();
        let token = self.id_token(&client);
        self.says.lock().unwrap().tokens.push(token.clone());
        Ok((
            200,
            json!({ "access_token": "at", "token_type": "Bearer", "id_token": token })
                .to_string()
                .into_bytes(),
        ))
    }
}

/// The governing domain's Acceptance of upstream issuers: on for every issuer in the set.
#[derive(Clone, Default)]
struct Trust(Arc<Mutex<Vec<[u8; 16]>>>);

impl UpstreamTrust for Trust {
    fn accepted(&self, _: [u8; 32], issuer: [u8; 16]) -> Trusted<'_> {
        let ok = self.0.lock().unwrap().contains(&issuer);
        Box::pin(async move { Ok(ok) })
    }
}

/// Records the client assertions it signs.
#[derive(Clone, Default)]
struct Assertions(Arc<AtomicUsize>);

impl ClientAssertion for Assertions {
    fn sign(&self, _: [u8; 16], alg: &'static str, claims: Vec<u8>, _: u64) -> Signed<'_> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let v: Value = serde_json::from_slice(&claims).unwrap();
        assert_eq!(alg, "ES256");
        assert_eq!(v["iss"], v["sub"]);
        assert!(v["aud"] == CORP || v["aud"] == OTHER);
        Box::pin(async { Ok(String::from("eyJhbGciOiJFUzI1NiJ9.e30.sig")) })
    }
}

/// The parser worker's answer as the test encodes it: the message is the facts' CBOR, read only
/// with the identity provider's pinned certificate (the real worker's signature checks are its own tests).
struct FakeReader;

const IDP_CERT: &[u8] = b"pinned-idp-cert";

impl access_identity_federation::ports::AssertionReader for FakeReader {
    fn read(
        &self,
        certs: Vec<Vec<u8>>,
        message: Vec<u8>,
    ) -> access_identity_federation::ports::Read<'_> {
        Box::pin(async move {
            if certs != [IDP_CERT.to_vec()] {
                return Err(access_identity_federation::ports::AssertionError::Refused(
                    String::from("signature-invalid"),
                ));
            }
            access_internal_api::saml::AssertionFacts::decode(&message).map_err(|_| {
                access_identity_federation::ports::AssertionError::Refused(String::from(
                    "saml-field",
                ))
            })
        })
    }
}

/// Hands the `AuthnRequest` and `RelayState` back in the URL, unsigned.
struct FakeSamlSigner;

impl access_identity_federation::ports::SamlRequestSigner for FakeSamlSigner {
    fn redirect<'a>(
        &'a self,
        _: [u8; 16],
        location: &'a str,
        request: &'a str,
        relay_state: &'a str,
    ) -> Signed<'a> {
        let mut url = format!("{location}?SAMLRequest=");
        access_identity_oauth::domain::issuer::form_encode(request, &mut url);
        url.push_str("&RelayState=");
        url.push_str(relay_state);
        Box::pin(async move { Ok(url) })
    }
}

struct Env {
    db: TestDb,
    tenant: TenantId,
    realm: RealmId,
    domain: DomainId,
    kit: Arc<RealmKit>,
    app: Router,
    provider: Provider,
    trust: Trust,
    assertions: Assertions,
    notices: Arc<Mutex<Vec<String>>>,
    pos: AtomicU64,
}

fn secrets_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "access-upstream-secrets-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace("::", "-")
    ));
    std::fs::create_dir_all(dir.join("upstream")).unwrap();
    std::fs::write(dir.join("upstream/corp"), "s3cret\n").unwrap();
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
    let notices = Arc::new(Mutex::new(Vec::new()));
    let config = HasherConfig::sized(Argon2Params::CANONICAL, 4, None);
    let hosted = Arc::new(Hosted {
        kits: Kit(kit.clone()),
        db: db.app.clone(),
        products: db.reader.clone(),
        clock,
        messages: Outbox(notices.clone()),
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        hasher: Hasher::new(config),
        redirect_to: "/".into(),
        hooks: Arc::new(access_identity_hooks::ports::NoHooks),
        risk: access_identity_session::app::RiskServices::without_sources(),
        signup: access_identity_ui::app::signup::Signup::without_providers().unwrap(),
    });
    let provider = Provider::new();
    let social = Arc::new(Social {
        http: provider.clone(),
        secrets: FileSecrets(Some(secrets_dir())),
        dev: BTreeMap::new(),
        presets: Presets::from_files(Vec::<(&str, &str)>::new()).unwrap(),
    });
    let trust = Trust::default();
    let assertions = Assertions::default();
    let app = router(
        Discovery::new(Dir(entry.clone()), NoKeys),
        hosted.clone(),
        None,
    )
    .merge(social_router(
        Discovery::new(Dir(entry.clone()), NoKeys),
        hosted.clone(),
        social.clone(),
    ))
    .merge(upstream_router(
        Discovery::new(Dir(entry), NoKeys),
        hosted,
        social,
        Upstreams {
            trust: Arc::new(trust.clone()),
            assertions: Arc::new(assertions.clone()),
            reader: Arc::new(FakeReader),
            saml_signer: Arc::new(FakeSamlSigner),
        },
    ));
    Env {
        db,
        tenant,
        realm,
        domain: d,
        kit,
        app,
        provider,
        trust,
        assertions,
        notices,
        pos: AtomicU64::new(1),
    }
}

impl Env {
    /// A committed ALLOW of `action` bound to the realm (EI-25).
    async fn decision(&self, action: &str) -> (TenantTx, access_store::idp::Bound) {
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
                action,
            },
        )
        .await
        .unwrap()
        .unwrap();
        (tx, bound)
    }

    /// Registers connection `name` at `issuer` under a committed `idp.upstream.register` ALLOW
    /// (TN-95); `accept` also gives its issuer the governing domain's Acceptance.
    async fn connection(&self, name: &str, issuer: &str, profile: &Profile, accept: bool) {
        let (mut tx, bound) = self.decision("idp.upstream.register").await;
        let secret = profile
            .client_auth
            .secret()
            .then(|| String::from("secret://upstream/corp"));
        let row = access_store::idp::realm::UpstreamRow {
            name: name.to_owned(),
            issuer: issuer.to_owned(),
            client_id: format!("{name}-client"),
            client_secret_ref: secret,
            jwks_uri: String::from("https://idp.test/jwks"),
            ssf: None,
            profile: Some(profile.to_json()),
            active: true,
            position: 0,
        };
        assert!(
            access_store::idp::realm::put_upstream(&mut tx, &bound, &row, true)
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();
        if accept {
            self.trust.0.lock().unwrap().push(issuer_id(issuer));
        }
    }

    async fn assurance_map(&self, name: &str, map: &AssuranceMap) {
        let (mut tx, bound) = self.decision("idp.upstream.assurance_map").await;
        tx.put_upstream_assurance_map(&bound, name, &map.to_json())
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    fn says(&self, sub: &str, email: Option<&str>) {
        let mut s = self.provider.says.lock().unwrap();
        s.sub = sub.to_owned();
        s.email = email.map(String::from);
        s.iss = None;
        s.acr = None;
        s.tckn = None;
    }

    fn browser(&self, n: u8) -> Web {
        Web {
            ip: Ipv4Addr::new(10, 0, 0, n),
            app: self.app.clone(),
            jar: BTreeMap::new(),
            n: 0,
        }
    }

    async fn tx(&self) -> TenantTx {
        TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap()
    }

    async fn link_at(&self, issuer: &str, sub: &str) -> Option<[u8; 16]> {
        let mut t = self.tx().await;
        let row = t
            .federated_by_key(&identity_key(issuer, sub))
            .await
            .unwrap();
        t.commit().await.unwrap();
        row.map(|r| r.subject)
    }

    async fn orders(&self, class: &str) -> Vec<ClaimOrder> {
        let mut t = self.tx().await;
        let rows = t.outbox_payloads(&format!("claim.{class}")).await.unwrap();
        t.commit().await.unwrap();
        rows.iter()
            .map(|b| ClaimOrder::from_bytes(b).unwrap())
            .collect()
    }

    /// Gives `subject` a confirmed address of its own, where notices about it go.
    async fn add_email(&self, subject: [u8; 16], address: &str) {
        use access_identity_account::ports::{AccountDb as _, AccountTx as _};
        let pg = access_identity_account::adapters::pg::PgAccounts::sealed(
            self.db.app.clone(),
            self.kit.vault(),
        );
        let mut tx = pg.begin(self.tenant, self.realm).await.unwrap();
        let id = access_identity_account::domain::identifier::Identifier::new(
            access_identity_account::domain::identifier::IdentifierKind::Email,
            address,
        )
        .unwrap();
        assert!(tx.add_identifier(subject, &id).await.unwrap());
        tx.commit().await.unwrap();
    }

    async fn status(&self, subject: [u8; 16]) -> String {
        let mut t = self.tx().await;
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
                .header(header::ORIGIN, format!("https://{HOST}"))
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

    /// Follows the redirect `to` at the provider back to `name`'s callback with `iss`.
    async fn back(&mut self, e: &Env, to: &str, name: &str, iss: &str) -> Answer {
        assert!(to.starts_with("https://idp.test/authorize?"), "{to}");
        let p = Params::parse(to.split_once('?').unwrap().1).unwrap();
        e.provider.says.lock().unwrap().nonce = p.get("nonce").unwrap_or_default().to_owned();
        let state = p.get("state").unwrap().to_owned();
        assert_eq!(
            p.get("redirect_uri").unwrap(),
            format!("https://{HOST}/v1/login/upstream/{name}/callback")
        );
        let mut path = format!("/v1/login/upstream/{name}/callback?code=c-1&state={state}");
        if !iss.is_empty() {
            path.push_str("&iss=");
            access_identity_oauth::domain::issuer::form_encode(iss, &mut path);
        }
        self.send("GET", &path, None).await
    }

    async fn upstream(&mut self, e: &Env, name: &str, iss: &str) -> Answer {
        let start = self
            .send("GET", &format!("/v1/login/upstream/{name}"), None)
            .await;
        assert_eq!(start.status, StatusCode::SEE_OTHER, "{}", start.code());
        self.back(e, &start.location(), name, iss).await
    }
}

fn corp() -> Profile {
    let mut p = Profile::legacy(false);
    p.display_name = Some(String::from("Corp"));
    p
}

// OP-155 m.3 (h), TN-95, TN-108, TN-98, RFC 9207, §10.2.6, §10.1.2, INV-17, IDP-27,
// OP-155 m.3 (h), Ek B 4678, 4679, 4680, 4681, 4730, 4735, 4736, 4740, 4741
#[tokio::test]
async fn an_accepted_connection_signs_in_just_in_time_and_its_claims_carry_only_digests() {
    let e = env(0x61, "up-a").await;
    e.connection("corp", CORP, &corp(), true).await;
    e.says("emp-1", Some("ada@corp.example"));
    let mut w = e.browser(1);
    // TN-95
    let flow = w.send("POST", "/v1/login/flows", None).await;
    assert_eq!(flow.status, StatusCode::CREATED, "{}", flow.code());
    let nodes = flow.json()["nodes"].clone();
    let button = nodes
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["type"] == "provider" && n["provider"] == "corp")
        .cloned()
        .unwrap_or_else(|| panic!("{nodes}"));
    assert_eq!(button["label"]["id"], "action.sign_in_with");
    assert_eq!(button["label"]["text"], "Sign in with Corp");
    assert_eq!(button["href"], "/v1/login/upstream/corp");
    let start = w
        .send(
            "GET",
            "/v1/login/upstream/corp?ui_locales=tr%20de&domain_hint=other.example&login_hint=eve%40evil.example",
            None,
        )
        .await;
    assert_eq!(start.status, StatusCode::SEE_OTHER, "{}", start.code());
    let to = start.location();
    // TN-108
    assert!(
        to.contains("ui_locales=tr&") || to.ends_with("ui_locales=tr"),
        "{to}"
    );
    // TN-98
    assert!(
        !to.contains("login_hint") && !to.contains("domain_hint"),
        "{to}"
    );
    assert!(to.contains("client_id=corp-client"));
    let a = w.back(&e, &to, "corp", CORP).await;
    assert_eq!(a.status, StatusCode::SEE_OTHER, "{}", a.code());
    assert!(w.jar.contains_key("__Host-access-session"));
    // OP-155 m.3 (h)
    let form = e.provider.says.lock().unwrap().forms[0].clone();
    assert!(form.contains(
        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
    ));
    assert!(!form.contains("client_secret"));
    assert_eq!(e.assertions.0.load(Ordering::SeqCst), 1);
    // §10.2.6
    let subject = e.link_at(CORP, "emp-1").await.unwrap();
    assert_eq!(e.status(subject).await, "active");

    // §10.1.2 rule 1
    let token = e.provider.says.lock().unwrap().tokens[0].clone();
    let mut t = e.tx().await;
    let evidence = access_identity_federation::domain::connection::evidence(token.as_bytes());
    let (_, sealed) = t
        .upstream_assertion(subject, &evidence)
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    assert!(
        !sealed
            .windows(16)
            .any(|w| token.as_bytes().windows(16).any(|x| x == w))
    );
    let auth = e.orders("authentication").await;
    let last = auth.last().unwrap();
    let ClaimBody::Authentication(body) = (match &last.content {
        access_identity_account::domain::claims::Content::Body { body, .. } => body.clone(),
        other => panic!("{other:?}"),
    }) else {
        panic!("not an authentication body")
    };
    assert_eq!(body.method, access_kernel::claim::body::AuthMethod::Oidc);
    assert_eq!(body.evidence.unwrap().0, evidence);
    assert_eq!(body.upstream.as_ref().unwrap().iss, CORP);
    assert_eq!(body.upstream.as_ref().unwrap().amr, ["pwd"]);
    // IDP-27
    assert_eq!(last.assurance.get("aal"), Some(&1));
    let bindings = e.orders("identity_binding_person").await;
    assert_eq!(bindings.len(), 1);
    let raw = bindings[0].to_bytes().unwrap();
    assert!(
        !raw.windows(token.len().min(64))
            .any(|w| w == &token.as_bytes()[..64])
    );
    assert!(!raw.windows(16).any(|w| w == &b"ada@corp.example"[..]));

    // IDP-27, §10.1.2 rule 2
    e.assurance_map(
        "corp",
        &AssuranceMap {
            entries: vec![MapEntry {
                on: MatchOn::Acr,
                value: String::from("urn:corp:mfa"),
                aal: 2,
                loa_eidas: None,
            }],
        },
    )
    .await;
    e.says("emp-1", Some("ada@corp.example"));
    e.provider.says.lock().unwrap().acr = Some(String::from("urn:corp:mfa"));
    let mut w2 = e.browser(2);
    let b = w2.upstream(&e, "corp", CORP).await;
    assert_eq!(b.status, StatusCode::SEE_OTHER, "{}", b.code());
    assert_eq!(
        e.link_at(CORP, "emp-1").await,
        Some(subject),
        "found by (iss, sub)"
    );
    assert_eq!(
        e.orders("authentication")
            .await
            .last()
            .unwrap()
            .assurance
            .get("aal"),
        Some(&2)
    );
    e.provider.says.lock().unwrap().acr = Some(String::from("urn:corp:other"));
    let mut w3 = e.browser(3);
    let c = w3.upstream(&e, "corp", CORP).await;
    assert_eq!(c.status, StatusCode::SEE_OTHER, "{}", c.code());
    assert_eq!(
        e.orders("authentication")
            .await
            .last()
            .unwrap()
            .assurance
            .get("aal"),
        Some(&1),
        "an unmapped acr is the lowest class"
    );

    // RFC 9207 §2.4
    let mut w4 = e.browser(4);
    let d = w4.upstream(&e, "corp", "https://idp.test/evil").await;
    assert_eq!(d.status, StatusCode::UNAUTHORIZED);
    let mut w5 = e.browser(5);
    let f = w5.upstream(&e, "corp", "").await;
    assert_eq!(
        f.status,
        StatusCode::UNAUTHORIZED,
        "iss is advertised, so required"
    );
}

// TN-95, INV-17, SEC9, OP-155 m.3 (h), Ek B 4736
#[tokio::test]
async fn a_connection_without_an_acceptance_yields_nothing_and_its_cutoff_ends_its_sessions() {
    let e = env(0x62, "up-b").await;
    e.connection("corp", CORP, &corp(), false).await;
    e.says("emp-2", None);
    let mut w = e.browser(1);
    let a = w.upstream(&e, "corp", CORP).await;
    assert_eq!(
        (a.status, a.code().as_str()),
        (StatusCode::CONFLICT, "upstream-not-accepted")
    );
    assert!(e.link_at(CORP, "emp-2").await.is_none());
    assert!(e.orders("authentication").await.is_empty());
    assert!(
        e.provider.says.lock().unwrap().forms.is_empty(),
        "the code is never redeemed"
    );

    e.trust.0.lock().unwrap().push(issuer_id(CORP));
    let mut w2 = e.browser(2);
    let b = w2.upstream(&e, "corp", CORP).await;
    assert_eq!(b.status, StatusCode::SEE_OTHER, "{}", b.code());
    let subject = e.link_at(CORP, "emp-2").await.unwrap();
    let me = w2.send("GET", "/v1/account/linked", None).await;
    assert_eq!(me.status, StatusCode::OK, "{}", me.code());

    // SEC9
    e.trust.0.lock().unwrap().clear();
    let mut w3 = e.browser(3);
    let c = w3.upstream(&e, "corp", CORP).await;
    assert_eq!(c.code(), "upstream-not-accepted");
    let mut t = e.tx().await;
    assert!(t.live_sessions(subject).await.unwrap().is_empty());
    t.commit().await.unwrap();
    let gone = w2.send("GET", "/v1/account/linked", None).await;
    assert_eq!(gone.status, StatusCode::UNAUTHORIZED);
    let ended = e.orders("authentication").await;
    assert!(
        ended.last().unwrap().retract,
        "the session's authentication line ends"
    );
}

// TN-66, GHSA-x8cg-3c8h-gw55, TN-3, OP-155 m.3 (h), Ek B 4737, 4738
#[tokio::test]
async fn a_new_subject_for_a_known_address_is_a_conflict_and_never_reaches_the_account() {
    let e = env(0x63, "up-c").await;
    e.connection("corp", CORP, &corp(), true).await;
    e.connection("other", OTHER, &Profile::legacy(false), true)
        .await;
    e.says("emp-3", Some("bob@corp.example"));
    let mut w = e.browser(1);
    let a = w.upstream(&e, "corp", CORP).await;
    assert_eq!(a.status, StatusCode::SEE_OTHER, "{}", a.code());
    let bob = e.link_at(CORP, "emp-3").await.unwrap();
    e.add_email(bob, "bob@home.example").await;

    // GHSA-x8cg-3c8h-gw55
    e.says("emp-3-new", Some("bob@corp.example"));
    let mut w2 = e.browser(2);
    let b = w2.upstream(&e, "corp", CORP).await;
    assert_eq!(
        (b.status, b.code().as_str()),
        (StatusCode::CONFLICT, "upstream-subject-conflict")
    );
    assert!(!w2.jar.contains_key("__Host-access-session"));
    assert!(e.link_at(CORP, "emp-3-new").await.is_none());
    let mut t = e.tx().await;
    let conflicts = t.subject_conflicts(bob).await.unwrap();
    t.commit().await.unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].key, identity_key(CORP, "emp-3-new"));
    assert_eq!(e.notices.lock().unwrap().as_slice(), ["Corp"]);
    let mut w3 = e.browser(3);
    let again = w3.upstream(&e, "corp", CORP).await;
    assert_eq!(again.code(), "upstream-subject-conflict");
    assert_eq!(
        e.notices.lock().unwrap().len(),
        1,
        "one notice per conflict"
    );

    // GHSA-x8cg-3c8h-gw55
    e.says("emp-3", Some("bob@corp.example"));
    e.provider.says.lock().unwrap().iss = Some(String::from(OTHER));
    let mut w4 = e.browser(4);
    let c = w4.upstream(&e, "other", OTHER).await;
    assert_eq!(c.status, StatusCode::SEE_OTHER, "{}", c.code());
    let other = e.link_at(OTHER, "emp-3").await.unwrap();
    assert_ne!(other, bob, "never the existing account");

    // TN-66
    e.says("emp-3-new", Some("bob@corp.example"));
    let link = w
        .send(
            "POST",
            "/v1/account/linked",
            Some(json!({ "provider": "corp" })),
        )
        .await;
    assert_eq!(link.status, StatusCode::OK, "{}", link.code());
    let to = link.json()["redirect_to"].as_str().unwrap().to_owned();
    let d = w.back(&e, &to, "corp", CORP).await;
    assert_eq!(d.status, StatusCode::OK, "{}", d.code());
    assert_eq!(e.link_at(CORP, "emp-3-new").await, Some(bob));
    let mut t = e.tx().await;
    let conflicts = t.subject_conflicts(bob).await.unwrap();
    t.commit().await.unwrap();
    assert!(conflicts[0].resolved_ms.is_some());
}

// §8.13, OP-155 m.3 (h), Ek B 4731
#[tokio::test]
async fn an_upstream_that_does_not_answer_changes_no_account() {
    let e = env(0x64, "up-d").await;
    e.connection("corp", CORP, &corp(), true).await;
    e.says("emp-4", Some("cy@corp.example"));
    let mut w = e.browser(1);
    let a = w.upstream(&e, "corp", CORP).await;
    assert_eq!(a.status, StatusCode::SEE_OTHER);
    let cy = e.link_at(CORP, "emp-4").await.unwrap();
    e.provider.says.lock().unwrap().down = true;
    let mut w2 = e.browser(2);
    let b = w2.send("GET", "/v1/login/upstream/corp", None).await;
    assert_eq!(
        (b.status, b.code().as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "upstream-unreachable")
    );
    assert!(
        b.json()["title"]
            .as_str()
            .unwrap()
            .contains("isn't responding")
    );
    assert_eq!(e.status(cy).await, "active");
    assert_eq!(e.link_at(CORP, "emp-4").await, Some(cy));
}

// IDP-34, OP-155 m.3 (h), Ek B 4844, 4674
#[tokio::test]
async fn an_e_devlet_sign_in_seals_the_national_id_and_claims_only_its_keyed_digest() {
    let e = env(0x65, "up-e").await;
    let mut p = Profile::legacy(false);
    p.preset = Some(String::from("edevlet"));
    e.connection("corp", CORP, &p, true).await;
    e.says("ed-1", None);
    let tckn = "10000000146";
    e.provider.says.lock().unwrap().tckn = Some(String::from(tckn));
    let mut w = e.browser(1);
    let a = w.upstream(&e, "corp", CORP).await;
    assert_eq!(a.status, StatusCode::SEE_OTHER, "{}", a.code());
    let to_scope = e.provider.says.lock().unwrap().forms.len();
    assert_eq!(to_scope, 1);
    for class in ["authentication", "identity_binding_person"] {
        for o in e.orders(class).await {
            let raw = o.to_bytes().unwrap();
            assert!(!raw.windows(tckn.len()).any(|w| w == tckn.as_bytes()));
        }
    }
    e.says("ed-2", None);
    let mut w2 = e.browser(2);
    let b = w2.upstream(&e, "corp", CORP).await;
    assert_eq!(
        b.status,
        StatusCode::UNAUTHORIZED,
        "a preset's national id is required"
    );
}

// TN-98, TN-3, §10.2.6, OP-153 m.3 (gg), OP-155 m.3 (h), Ek B 3436, 3454, 3599, 5045
#[tokio::test]
async fn home_realm_discovery_is_off_until_the_realm_turns_it_on_and_no_hint_overrides_it() {
    let e = env(0x66, "up-f").await;
    let party = [0x0b; 16];
    let mut p = corp();
    p.organization = Some(b64url_encode(&party));
    e.connection("corp", CORP, &p, true).await;
    let mut t = e.tx().await;
    let org = t.insert_org(party, "Acme", &[1; 32]).await.unwrap();
    assert!(t.set_org_hrd(org, true).await.unwrap());
    t.commit().await.unwrap();
    let (mut tx, bound) = e.decision("idp.realm.hrd").await;
    tx.put_realm_hrd(&bound, true).await.unwrap();
    tx.commit().await.unwrap();
    let path = format!("/v1/organizations/{}/sign-in", b64url_encode(&party));
    // §10.2.6
    assert_eq!(
        e.browser(9).send("GET", &path, None).await.status,
        StatusCode::NOT_FOUND
    );
    let (mut tx, bound) = e.decision("idp.realm.hrd_close").await;
    tx.put_realm_hrd(&bound, false).await.unwrap();
    tx.commit().await.unwrap();
    let mut t = e.tx().await;
    let claim = t
        .insert_domain_claim(org, "acme.example", "dns_txt", &[1; 32])
        .await
        .unwrap();
    assert!(
        t.verify_domain(claim, 86_400, &[2; 32], &[3; 32])
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    let mut w = e.browser(1);
    // TN-98
    assert_eq!(
        w.send("GET", &path, None).await.status,
        StatusCode::NOT_FOUND
    );
    let (mut tx, bound) = e.decision("idp.realm.hrd").await;
    tx.put_realm_hrd(&bound, true).await.unwrap();
    tx.commit().await.unwrap();
    let a = w.send("GET", &path, None).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.code());
    assert_eq!(a.json()["confirm"], true);
    assert_eq!(a.json()["connection"]["name"], "corp");
    assert_eq!(a.json()["connection"]["start"], "/v1/login/upstream/corp");
    // TN-3
    assert_eq!(
        w.send("GET", "/v1/organizations/acme.example/sign-in", None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    // TN-98
    e.connection("other", OTHER, &Profile::legacy(false), true)
        .await;
    let start = w
        .send(
            "GET",
            "/v1/login/upstream/corp?domain_hint=other&login_hint=other",
            None,
        )
        .await;
    assert!(start.location().contains("client_id=corp-client"));
    let (mut tx, bound) = e.decision("idp.realm.hrd_close").await;
    tx.put_realm_hrd(&bound, false).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        w.send("GET", &path, None).await.status,
        StatusCode::NOT_FOUND
    );
}

const IDP: &str = "https://idp.test/saml";

fn saml_profile(unsolicited: bool) -> Profile {
    let mut p = corp();
    p.protocol = access_identity_federation::domain::connection::ConnectionProtocol::Saml;
    p.allow_unsolicited = unsolicited;
    p.saml = Some(access_identity_federation::domain::connection::SamlIdp {
        entity_id: String::from(IDP),
        sso_url: String::from("https://idp.test/sso"),
        certificates: vec![access_crypto::webhook::b64_encode(IDP_CERT)],
    });
    p
}

fn saml_facts(
    id: &str,
    name_id: &str,
    in_response_to: Option<&str>,
) -> access_internal_api::saml::AssertionFacts {
    let at = access_identity_saml::time::format(T0);
    let end = access_identity_saml::time::format(T0 + 300_000);
    access_internal_api::saml::AssertionFacts {
        id: id.to_owned(),
        issuer: String::from(IDP),
        issue_instant: at.clone(),
        name_id: name_id.to_owned(),
        name_id_format: None,
        audiences: vec![format!(
            "https://{HOST}/v1/login/upstream/corp/saml/metadata"
        )],
        not_before: Some(at.clone()),
        not_on_or_after: Some(end.clone()),
        recipient: Some(format!("https://{HOST}/v1/login/upstream/corp/saml/acs")),
        confirmation_not_on_or_after: Some(end),
        in_response_to: in_response_to.map(String::from),
        authn_instant: Some(at),
        session_index: Some(String::from("s1")),
        authn_context: Some(String::from(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        )),
        attributes: vec![(String::from("mail"), vec![String::from("sam@corp.example")])],
        signed: String::from("rsa-sha256"),
        in_response: true,
    }
}

impl Web {
    /// Posts `facts` to the ACS as the identity provider's browser POST, then as the page's own repost.
    async fn acs(
        &mut self,
        facts: &access_internal_api::saml::AssertionFacts,
        relay: Option<&str>,
    ) -> Answer {
        let response = access_crypto::webhook::b64_encode(&facts.encode().unwrap());
        let mut form = String::from("SAMLResponse=");
        access_identity_oauth::domain::issuer::form_encode(&response, &mut form);
        if let Some(r) = relay {
            form.push_str("&RelayState=");
            form.push_str(r);
        }
        let first = self
            .post_form("/v1/login/upstream/corp/saml/acs", &form)
            .await;
        assert_eq!(first.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&first.body).contains("name=\"hop\" value=\"1\""));
        form.push_str("&hop=1");
        self.post_form("/v1/login/upstream/corp/saml/acs", &form)
            .await
    }

    async fn post_form(&mut self, path: &str, form: &str) -> Answer {
        let mut req = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if !self.jar.is_empty() {
            let cookies: Vec<String> = self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect();
            req = req.header(header::COOKIE, cookies.join("; "));
        }
        let mut req = req.body(HttpBody::from(form.to_owned())).unwrap();
        req.extensions_mut().insert(Peer(IpAddr::V4(self.ip)));
        let response = self.app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        for c in headers.get_all(header::SET_COOKIE) {
            let c = c.to_str().unwrap();
            let (name, value) = c.split(';').next().unwrap().split_once('=').unwrap();
            self.jar.insert(name.to_owned(), value.to_owned());
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
}

// OP-155 m.3 (h), §10.6.1, §10.2.6, TN-95, Ek B 4784, 4682
#[tokio::test]
async fn a_saml_upstream_signs_in_by_answering_its_request_and_refuses_an_unsolicited_response() {
    let e = env(0x67, "up-g").await;
    e.connection("corp", IDP, &saml_profile(false), true).await;
    let day = u32::try_from((T0 + 300_000) / 86_400_000).unwrap();
    access_store::dpop::open_dpop_replay_day(&e.db.archive, day)
        .await
        .unwrap();
    let mut w = e.browser(1);
    let md = w
        .send("GET", "/v1/login/upstream/corp/saml/metadata", None)
        .await;
    assert_eq!(md.status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&md.body).contains("WantAssertionsSigned=\"true\""));
    let start = w.send("GET", "/v1/login/upstream/corp", None).await;
    assert_eq!(start.status, StatusCode::SEE_OTHER, "{}", start.code());
    let to = start.location();
    assert!(to.starts_with("https://idp.test/sso?SAMLRequest="), "{to}");
    let p = Params::parse(to.split_once('?').unwrap().1).unwrap();
    let relay = p.get("RelayState").unwrap().to_owned();
    let request = p.get("SAMLRequest").unwrap().to_owned();
    let id = request
        .split("ID=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();

    // §10.6.1
    let mut stray = e.browser(2);
    let _ = stray.send("GET", "/v1/login/upstream/corp", None).await;
    let a = w
        .acs(&saml_facts("a0", "sam-1", Some("_other")), Some(&relay))
        .await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.code());

    let start = w.send("GET", "/v1/login/upstream/corp", None).await;
    let p = Params::parse(start.location().split_once('?').unwrap().1).unwrap();
    let relay = p.get("RelayState").unwrap().to_owned();
    let id2 = p
        .get("SAMLRequest")
        .unwrap()
        .split("ID=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    assert_ne!(id, id2);
    let b = w
        .acs(&saml_facts("a1", "sam-1", Some(&id2)), Some(&relay))
        .await;
    assert_eq!(b.status, StatusCode::SEE_OTHER, "{}", b.code());
    assert!(w.jar.contains_key("__Host-access-session"));
    let sam = e.link_at(IDP, "sam-1").await.unwrap();
    let auth = e.orders("authentication").await;
    let last = auth.last().unwrap();
    let access_identity_account::domain::claims::Content::Body {
        body: ClaimBody::Authentication(body),
        ..
    } = &last.content
    else {
        panic!("not an authentication body")
    };
    assert_eq!(body.method, access_kernel::claim::body::AuthMethod::Saml);
    assert_eq!(body.upstream.as_ref().unwrap().iss, IDP);
    assert_eq!(e.status(sam).await, "active");

    // §10.6.1
    let start = w.send("GET", "/v1/login/upstream/corp", None).await;
    let p = Params::parse(start.location().split_once('?').unwrap().1).unwrap();
    let relay3 = p.get("RelayState").unwrap().to_owned();
    let mut replayed = saml_facts("a1", "sam-1", Some(&id2));
    replayed.in_response_to = Some(
        p.get("SAMLRequest")
            .unwrap()
            .split("ID=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_owned(),
    );
    let c = w.acs(&replayed, Some(&relay3)).await;
    assert_eq!(
        c.status,
        StatusCode::UNAUTHORIZED,
        "an assertion ID is used once"
    );

    // §10.2.6, Ek B 4682
    let mut idp_initiated = e.browser(3);
    let d = idp_initiated
        .acs(&saml_facts("a2", "sam-2", None), None)
        .await;
    assert_eq!(d.status, StatusCode::UNAUTHORIZED);
    assert!(e.link_at(IDP, "sam-2").await.is_none());
}

// OP-155 m.3 (h), Ek B 4682
#[tokio::test]
async fn an_unsolicited_saml_response_signs_in_only_where_the_connection_opens_it() {
    let e = env(0x68, "up-h").await;
    e.connection("corp", IDP, &saml_profile(true), true).await;
    let day = u32::try_from((T0 + 300_000) / 86_400_000).unwrap();
    access_store::dpop::open_dpop_replay_day(&e.db.archive, day)
        .await
        .unwrap();
    let mut w = e.browser(1);
    let a = w.acs(&saml_facts("u1", "sam-9", None), None).await;
    assert_eq!(a.status, StatusCode::SEE_OTHER, "{}", a.code());
    assert!(e.link_at(IDP, "sam-9").await.is_some());
}

// TN-134 (1), (3), TN-94, OP-155 m.3 (i), m.17 (i), Ek B 4872, 4874
#[tokio::test]
async fn an_organization_connection_speaks_only_for_its_verified_domains_and_signs_in_enforced_members()
 {
    let e = env(0x6a, "up-sso").await;
    let party = [0x0c; 16];
    let mut p = corp();
    p.organization = Some(b64url_encode(&party));
    e.connection("corp", CORP, &p, true).await;
    let mut t = e.tx().await;
    let org = t.insert_org(party, "Corp", &[1; 32]).await.unwrap();
    t.commit().await.unwrap();

    // TN-134 (1): no verified domain, no identity
    e.says("emp-9", Some("ada@corp.example"));
    let refused = e.browser(1).upstream(&e, "corp", CORP).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.code());
    assert_eq!(refused.code(), "upstream-identity-outside-organization");
    assert_eq!(e.link_at(CORP, "emp-9").await, None);
    let mut t = e.tx().await;
    let claim = t
        .insert_domain_claim(org, "corp.example", "dns_txt", &[1; 32])
        .await
        .unwrap();
    assert!(
        t.verify_domain(claim, 86_400, &[2; 32], &[3; 32])
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    e.says("emp-8", Some("eve@other.example"));
    let other = e.browser(2).upstream(&e, "corp", CORP).await;
    assert_eq!(other.status, StatusCode::FORBIDDEN, "{}", other.code());
    e.says("emp-9", Some("ada@corp.example"));
    let a = e.browser(3).upstream(&e, "corp", CORP).await;
    assert_eq!(a.status, StatusCode::SEE_OTHER, "{}", a.code());
    let subject = e.link_at(CORP, "emp-9").await.unwrap();

    // TN-94: an enforced member signs in through the organization's own connection
    let mut t = e.tx().await;
    t.insert_membership(org, subject, access_store::orgs::Source::Jit, false, None)
        .await
        .unwrap();
    t.commit().await.unwrap();
    let (mut tx, bound) = e.decision("idp.org.sso_enforce").await;
    tx.put_sso_enforcement(&bound, org, Some("cancel"))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    e.says("emp-9", Some("ada@corp.example"));
    let mut w = e.browser(4);
    let b = w.upstream(&e, "corp", CORP).await;
    assert_eq!(b.status, StatusCode::SEE_OTHER, "{}", b.code());
    assert!(w.jar.contains_key("__Host-access-session"));
}
