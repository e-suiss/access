//! Realms side by side for the conformance and security suites (OP-146 I11): each realm in its
//! own tenant over one real PostgreSQL, one real identity signer on a Unix socket, its own
//! DPoP nonce keys, three clients (`none`, `client_secret_basic`, `private_key_jwt`) and a
//! signed-in browser.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "test fixtures"
)]

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use access_crypto::Secret;
use access_crypto::dpop::{MAX_STALE_MS, NonceKey, NoncePolicy, NonceRing, Role};
use access_crypto::jose::JwsAlg;
use access_crypto::oauth::secret_digest;
use access_identity_oauth::adapters::dpop::PgReplayCache;
use access_identity_oauth::adapters::oauth::{HostedPages, OsRandom, PgOAuth};
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::oauth::{Env, OAuth, Realm, Reply, TokenHttp};
use access_identity_oauth::domain::dpop::DpopProfile;
use access_identity_oauth::domain::issuer::{IssuerStyle, RealmBase};
use access_identity_oauth::domain::request::Params;
use access_identity_oauth::ports::Unavailable;
use access_identity_oauth::ports::dpop::{Clock, ClockUnavailable};
use access_identity_oauth::ports::oauth::ClientKeys;
use access_identity_session::domain::assurance::{Factor, vector};
use access_identity_session::domain::session::cookie_digest;
use access_identity_signer::adapters::{DirVault, SealedFactory, now_ms, serve};
use access_identity_signer::protocol::{Realm as SignerRealm, Request, Response};
use access_identity_signer::service::Service;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::dpop::ath;
use access_kernel::verify::key_scope::thumbprint;
use access_store::Pool;
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::dpop::open_dpop_replay_day;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{ClientRow, Decision, bind, create_settings, insert_client};
use access_store::scope::DomainId;
use access_store::sessions::NewSession;
use access_store::tenancy::{HostKind, add_hostname, create_realm, create_tenant, set_issuer};
use access_store::testing::{TestDb, fresh};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use serde_json::Value;
use suiss_crypto::envelope::SoftKek;
use suiss_crypto::rotation::Policy;
use tokio::net::UnixListener;

/// The realm base every fixture realm's subdomain issuer hangs under.
pub const BASE: &str = "https://id.test";
/// The registered redirect URI of every fixture client.
pub const CB: &str = "https://shop.example/cb";
/// The registered loopback redirect URI of every fixture client (RFC 8252 §7.3).
pub const NATIVE: &str = "http://127.0.0.1/native";
/// The registered post-logout redirect URI.
pub const BYE: &str = "https://shop.example/bye";
/// The registered back-channel logout URI.
pub const BACKCHANNEL: &str = "https://shop.example/backchannel";
/// RFC 7636 appendix B.
pub const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// RFC 7636 appendix B.
pub const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// One hour, ms.
pub const HOUR: u64 = 3_600_000;
/// RFC 7523 client assertion type.
pub const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

pub struct SysClock;

impl Clock for SysClock {
    fn now(&self) -> Result<u64, ClockUnavailable> {
        Ok(u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap())
    }
}

pub fn now() -> u64 {
    SysClock.now().unwrap()
}

/// Client JWKS documents by URI.
#[derive(Clone, Default)]
pub struct StaticKeys(pub Arc<Mutex<HashMap<String, Vec<u8>>>>);

impl ClientKeys for StaticKeys {
    fn fetch(&self, uri: &str) -> impl Future<Output = Result<Vec<u8>, Unavailable>> {
        std::future::ready(self.0.lock().unwrap().get(uri).cloned().ok_or(Unavailable))
    }
}

/// The nonce keys of one realm.
#[derive(Clone)]
pub struct Rings {
    pub authorization: Arc<NonceRing>,
    pub resource: Arc<NonceRing>,
}

pub struct TestEnv {
    pub db: PgOAuth,
    pub signer: SignerKeys,
    pub keys: StaticKeys,
    pub directory: PgDirectory,
    pub pool: Pool,
    pub router: Pool,
    pub socket: PathBuf,
    pub rings: Arc<HashMap<RealmId, Rings>>,
    pub profile: DpopProfile,
}

impl Clone for TestEnv {
    fn clone(&self) -> Self {
        Self {
            db: PgOAuth::new(self.pool.clone()),
            signer: SignerKeys::new(self.socket.clone()),
            keys: self.keys.clone(),
            directory: PgDirectory::new(self.router.clone()),
            pool: self.pool.clone(),
            router: self.router.clone(),
            socket: self.socket.clone(),
            rings: self.rings.clone(),
            profile: self.profile.clone(),
        }
    }
}

impl Env for TestEnv {
    type Db = PgOAuth;
    type Signer = SignerKeys;
    type ClientKeys = StaticKeys;
    type Pages = HostedPages;
    type Clock = SysClock;
    type Random = OsRandom;
    type Directory = PgDirectory;
    type Replay = PgReplayCache;

    fn db(&self) -> &PgOAuth {
        &self.db
    }
    fn signer(&self) -> &SignerKeys {
        &self.signer
    }
    fn client_keys(&self) -> &StaticKeys {
        &self.keys
    }
    fn pages(&self) -> &HostedPages {
        &HostedPages
    }
    fn clock(&self) -> &SysClock {
        &SysClock
    }
    fn random(&self) -> &OsRandom {
        &OsRandom
    }
    fn directory(&self) -> &PgDirectory {
        &self.directory
    }
    fn replay(&self, tenant: TenantId, realm: RealmId) -> PgReplayCache {
        PgReplayCache::new(self.pool.clone(), tenant, realm)
    }
    fn nonces(&self, realm: RealmId, role: Role) -> Option<Arc<NonceRing>> {
        let r = self.rings.get(&realm)?;
        Some(match role {
            Role::AuthorizationServer => r.authorization.clone(),
            Role::ResourceServer => r.resource.clone(),
        })
    }
    fn dpop(&self) -> &DpopProfile {
        &self.profile
    }
}

pub fn temp(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "aio-sec-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A signer whose key sets for `realms` were opened two hours ago, so they are past their
/// publish lead and sign now (MD-6, SAI-46).
pub fn signer(dir: &Path, realms: &[RealmId]) -> PathBuf {
    let mut service = Service::start(
        SealedFactory::new(SoftKek::new("realm-kek", [7; 32])),
        DirVault::new(dir),
        Policy::REALM,
    )
    .unwrap();
    for r in realms {
        let opened = service.handle(
            Request::Open {
                realm: SignerRealm(*r.as_bytes()),
                alg: JwsAlg::Es256,
            },
            now_ms() - 2 * HOUR,
            7,
        );
        assert_eq!(opened, Response::Opened);
    }
    service.tick(now_ms(), 7);
    let path = dir.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(dir).unwrap());
    tokio::spawn(serve(
        listener,
        Arc::new(Mutex::new(service)),
        vec![uid],
        now_ms,
    ));
    path
}

fn ring(realm: RealmId, role: Role, key: u8) -> Arc<NonceRing> {
    Arc::new(NonceRing::new(
        *realm.as_bytes(),
        role,
        NoncePolicy::new(HOUR, MAX_STALE_MS).unwrap(),
        1,
        NonceKey::new(Secret::new([key; 32])),
    ))
}

/// A domain whose log holds ALLOW decisions at positions 1..=allows.
pub async fn domain(db: &TestDb, t: TenantId, seed: u8, allows: u8) -> DomainId {
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *t.as_bytes(), &g, &[])
        .await
        .unwrap();
    let (lease, mut head) = acquire_lease(&db.sequencer, &d, "a", Duration::from_secs(10))
        .await
        .unwrap();
    for i in 1..=allows {
        let pos = head.pos + 1;
        let leaf = [i; 32];
        let next = HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: leaf,
            recorded_at: 2,
            frontier: vec![leaf],
        };
        let batch = CommitBatch {
            epoch: lease.epoch,
            after: head.pos,
            records: vec![LogRecord {
                pos,
                kind: "decision",
                recorded_at: 2,
                leaf_hash: leaf,
                envelope: vec![0xa1, i],
            }],
            head: next.clone(),
            nonces: vec![NonceRow {
                nonce: vec![i; 16],
                actor: vec![1],
                intent_digest: [9; 32],
                decision_pos: pos,
                outcome: String::from("allow"),
            }],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            effects: vec![],
        };
        commit_batch(&db.sequencer, &d, *t.as_bytes(), &batch)
            .await
            .unwrap();
        head = next;
    }
    d
}

/// One realm of the cluster and what its tests present.
pub struct Fixture {
    pub realm: Realm,
    pub slug: String,
    pub issuer: String,
    pub host: String,
    pub subject: [u8; 16],
    pub cookie: String,
    pub public: String,
    pub confidential: String,
    pub keyed: String,
    pub secret: String,
    pub keyed_jwks: String,
    pub client_key: EcdsaKeyPair,
}

/// Realms side by side.
pub struct Cluster {
    pub db: TestDb,
    pub oauth: OAuth<TestEnv>,
    pub realms: Vec<Fixture>,
}

/// The `client_id` of fixture client `kind` (`a`, `b`, `c`) in realm number `n`
/// (`cli_` + 26 base32 characters, OP-146 m.13 (f)).
pub fn client_id(n: usize, kind: char) -> String {
    let digit = char::from(b'2' + u8::try_from(n).unwrap());
    format!("cli_{}{digit}{kind}", "0".repeat(24))
}

/// A client registration (OP-146 m.13 (f), m.16 (k)).
pub fn client_row(uuid: [u8; 16], id: &str, method: &str, secret: &str, jwks: &str) -> ClientRow {
    ClientRow {
        client_uuid: uuid,
        client_id: String::from(id),
        display_name: String::from("Shop"),
        auth_method: String::from(method),
        jwks_uri: (method == "private_key_jwt").then(|| String::from(jwks)),
        redirect_uris: vec![String::from(CB), String::from(NATIVE)],
        active: true,
        secret_hash: (method == "client_secret_basic").then(|| secret_digest(secret.as_bytes())),
        post_logout_redirect_uris: vec![String::from(BYE)],
        backchannel_logout_uri: Some(String::from(BACKCHANNEL)),
        jwks: None,
        platform_product: None,
        service_key: None,
        event_receiver: None,
        require_par: false,
    }
}

pub fn ec_jwk(k: &EcdsaKeyPair) -> String {
    let p = k.public_key().as_ref();
    format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
        b64url_encode(&p[1..33]),
        b64url_encode(&p[33..])
    )
}

pub fn sign(k: &EcdsaKeyPair, header: &str, payload: &str) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let sig = k.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(sig.as_ref()))
}

pub fn new_key() -> EcdsaKeyPair {
    EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap()
}

/// An extra client: `client_id`, method, secret and redirect URIs.
pub type Extra = (String, String, String, Vec<String>);

impl Cluster {
    /// Realms `slugs`, each in its own tenant, with the three fixture clients.
    pub async fn new(slugs: &[&str]) -> Self {
        Self::seeded(BASE, slugs, &[]).await
    }

    /// Realms `slugs` under the realm base `base`, with the three fixture clients and `extra`
    /// clients in every realm (the OIDF target).
    pub async fn seeded(base: &str, slugs: &[&str], extra: &[Extra]) -> Self {
        let db = fresh().await.unwrap();
        let day = u32::try_from(now() / 86_400_000).unwrap();
        for d in [day - 1, day, day + 1] {
            open_dpop_replay_day(&db.archive, d).await.unwrap();
        }
        let keys = StaticKeys::default();
        let mut seeded = Vec::new();
        for (n, slug) in slugs.iter().enumerate() {
            let seed = 40 + u8::try_from(n).unwrap();
            let t = create_tenant(&db.app, "pool-default").await.unwrap();
            let clients = 3 + extra.len();
            let d = domain(&db, t, seed, u8::try_from(clients).unwrap()).await;
            let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
            let r = create_realm(&mut tx, &d, slug, "pool-default")
                .await
                .unwrap();
            tx.enter_realm(r).await.unwrap();
            create_settings(&mut tx).await.unwrap();
            let issuer = RealmBase::parse(base)
                .unwrap()
                .issuer(slug, IssuerStyle::Subdomain)
                .unwrap();
            let hostname = issuer.authority().split(':').next().unwrap();
            add_hostname(&mut tx, hostname, HostKind::Subdomain)
                .await
                .unwrap();
            assert!(set_issuer(&mut tx, issuer.as_str()).await.unwrap());
            let secret = format!("{slug}-secret-{slug}-secret-{slug}-secret");
            let keyed_jwks = format!("https://shop.example/{slug}/jwks.json");
            let mut rows = vec![
                client_row(
                    [seed, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    &client_id(n, 'a'),
                    "none",
                    &secret,
                    &keyed_jwks,
                ),
                client_row(
                    [seed, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                    &client_id(n, 'b'),
                    "client_secret_basic",
                    &secret,
                    &keyed_jwks,
                ),
                client_row(
                    [seed, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
                    &client_id(n, 'c'),
                    "private_key_jwt",
                    &secret,
                    &keyed_jwks,
                ),
            ];
            for (i, (id, method, s, uris)) in extra.iter().enumerate() {
                let k = u8::try_from(i + 4).unwrap();
                let mut row = client_row(
                    [seed, k, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, k],
                    id,
                    method,
                    s,
                    &keyed_jwks,
                );
                row.redirect_uris.clone_from(uris);
                rows.push(row);
            }
            for (i, row) in rows.iter().enumerate() {
                let p = u8::try_from(i + 1).unwrap();
                let b = bind(
                    &mut tx,
                    &Decision {
                        domain: &d,
                        position: u64::from(p),
                        nonce: &[p; 16],
                        intent: [9; 32],
                        change: [5; 32],
                        action: "idp.client.register",
                    },
                )
                .await
                .unwrap()
                .unwrap();
                insert_client(&mut tx, &b, row).await.unwrap();
            }
            let subject = tx
                .insert_subject("active", "realm-kek:1", &[9; 40])
                .await
                .unwrap();
            tx.commit().await.unwrap();
            let client_key = new_key();
            keys.0.lock().unwrap().insert(
                keyed_jwks.clone(),
                format!(r#"{{"keys":[{}]}}"#, ec_jwk(&client_key)).into_bytes(),
            );
            seeded.push((
                r,
                (*slug).to_owned(),
                issuer,
                subject,
                secret,
                keyed_jwks,
                client_key,
                n,
                seed,
            ));
        }
        let ids: Vec<RealmId> = seeded.iter().map(|s| s.0).collect();
        let socket = signer(&temp("c"), &ids);
        let rings: HashMap<RealmId, Rings> = seeded
            .iter()
            .map(|s| {
                (
                    s.0,
                    Rings {
                        authorization: ring(s.0, Role::AuthorizationServer, s.8),
                        resource: ring(s.0, Role::ResourceServer, s.8.wrapping_add(100)),
                    },
                )
            })
            .collect();
        let env = TestEnv {
            db: PgOAuth::new(db.app.clone()),
            signer: SignerKeys::new(socket.clone()),
            keys,
            directory: PgDirectory::new(db.router.clone()),
            pool: db.app.clone(),
            router: db.router.clone(),
            socket,
            rings: Arc::new(rings),
            profile: DpopProfile::default(),
        };
        let oauth = OAuth::new(env);
        let mut realms = Vec::new();
        for (_, slug, issuer, subject, secret, keyed_jwks, client_key, n, _) in seeded {
            let host = String::from(issuer.authority());
            let realm = oauth.realm(&host, None).await.unwrap().unwrap();
            realms.push(Fixture {
                realm,
                slug,
                issuer: String::from(issuer.as_str()),
                host,
                subject,
                cookie: String::new(),
                public: client_id(n, 'a'),
                confidential: client_id(n, 'b'),
                keyed: client_id(n, 'c'),
                secret,
                keyed_jwks,
                client_key,
            });
        }
        let mut c = Self { db, oauth, realms };
        for i in 0..c.realms.len() {
            let cookie = c.at(i).sign_in(now() - 60_000).await;
            c.realms[i].cookie = cookie;
        }
        c
    }

    /// The environment, for a second `OAuth` behind a router.
    pub fn env(&self) -> TestEnv {
        self.oauth.env().clone()
    }

    /// Realm `i` with a fresh DPoP key.
    pub fn at(&self, i: usize) -> At<'_> {
        At {
            c: self,
            f: &self.realms[i],
            key: Arc::new(new_key()),
        }
    }
}

/// One realm as a client and its user's browser see it.
#[derive(Clone)]
pub struct At<'a> {
    pub c: &'a Cluster,
    pub f: &'a Fixture,
    pub key: Arc<EcdsaKeyPair>,
}

impl At<'_> {
    pub fn oauth(&self) -> &OAuth<TestEnv> {
        &self.c.oauth
    }

    pub fn realm(&self) -> &Realm {
        &self.f.realm
    }

    pub fn issuer(&self) -> &str {
        &self.f.issuer
    }

    /// The same realm with another DPoP key.
    pub fn with_key(&self, key: EcdsaKeyPair) -> Self {
        Self {
            c: self.c,
            f: self.f,
            key: Arc::new(key),
        }
    }

    /// A signed-in browser: a login session with a password-level assurance (I5).
    pub async fn sign_in(&self, at: u64) -> String {
        let value: [u8; 32] = access_crypto::random::bytes().unwrap();
        let assurance = serde_json::to_vec(&vector(&[Factor::password(at)])).unwrap();
        let mut tx = TenantTx::begin(&self.c.db.app, self.f.realm.tenant, self.f.realm.realm)
            .await
            .unwrap();
        let epoch = tx
            .subject(self.f.subject, false)
            .await
            .unwrap()
            .unwrap()
            .session_epoch;
        tx.insert_session(&NewSession {
            cookie_hash: &cookie_digest(&value),
            subject: self.f.subject,
            session_epoch: epoch,
            keep_signed_in: false,
            created_ms: i64::try_from(at).unwrap(),
            auth_time_ms: i64::try_from(at).unwrap(),
            idle_ms: i64::try_from(24 * HOUR).unwrap(),
            expires_ms: i64::try_from(at + 48 * HOUR).unwrap(),
            assurance: &assurance,
        })
        .await
        .unwrap();
        tx.commit().await.unwrap();
        b64url_encode(&value)
    }

    pub fn jkt(&self) -> String {
        let key = PublicKey::P256(self.key.public_key().as_ref().to_vec());
        b64url_encode(&thumbprint(&key))
    }

    pub fn rings(&self) -> Rings {
        self.c.oauth.env().rings[&self.f.realm.realm].clone()
    }

    /// A DPoP proof for `method uri`, with this realm's nonce for the role the URI serves.
    pub fn proof(&self, method: &str, uri: &str, access_token: Option<&str>) -> String {
        let rings = self.rings();
        let ring = if access_token.is_some() {
            rings.resource
        } else {
            rings.authorization
        };
        let nonce = ring.issue(now()).unwrap();
        self.proof_with(method, uri, access_token, &nonce)
    }

    pub fn proof_with(
        &self,
        method: &str,
        uri: &str,
        access_token: Option<&str>,
        nonce: &str,
    ) -> String {
        let jti = b64url_encode(&access_crypto::random::bytes::<16>().unwrap());
        let extra = access_token
            .map(|t| format!(r#","ath":"{}""#, ath(t)))
            .unwrap_or_default();
        sign(
            &self.key,
            &format!(
                r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{}}}"#,
                ec_jwk(&self.key)
            ),
            &format!(
                r#"{{"jti":"{jti}","htm":"{method}","htu":"{uri}","iat":{},"nonce":"{nonce}"{extra}}}"#,
                now() / 1000
            ),
        )
    }

    /// `/authorize` with the public client's defaults; `("k", "")` removes a parameter.
    pub async fn authorize(&self, pairs: &[(&str, &str)], cookie: Option<&str>) -> Reply {
        let mut p: Vec<(String, String)> = vec![
            ("client_id", self.f.public.as_str()),
            ("redirect_uri", CB),
            ("response_type", "code"),
            ("scope", "openid"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "st"),
            ("nonce", "n-1"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        for (k, v) in pairs {
            p.retain(|(n, _)| n != k);
            if !v.is_empty() {
                p.push(((*k).into(), (*v).into()));
            }
        }
        self.c
            .oauth
            .authorize(&self.f.realm, &Params::new(p).unwrap(), cookie)
            .await
    }

    /// A code for `client_id` from a freshly signed-in browser.
    pub async fn code(&self, client_id: &str) -> String {
        let cookie = self.sign_in(now() - 1000).await;
        let r = self
            .authorize(&[("client_id", client_id)], Some(&cookie))
            .await;
        query(&location(&r), "code")
    }

    pub async fn token(&self, pairs: &[(&str, &str)], authorization: Option<&str>) -> Reply {
        let proof = self.proof("POST", &format!("{}/token", self.f.issuer), None);
        self.token_with(pairs, authorization, &[&proof]).await
    }

    pub async fn token_with(
        &self,
        pairs: &[(&str, &str)],
        authorization: Option<&str>,
        dpop: &[&str],
    ) -> Reply {
        let p: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        self.c
            .oauth
            .token(
                &self.f.realm,
                &Params::new(p).unwrap(),
                TokenHttp {
                    authorization,
                    dpop,
                },
            )
            .await
    }

    /// The public client's code exchange.
    pub async fn exchange(&self, code: &str) -> Reply {
        self.token(
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &self.f.public),
                ("code", code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            None,
        )
        .await
    }

    /// The confidential client's code exchange.
    pub async fn exchange_confidential(&self, code: &str) -> Reply {
        self.token(
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            Some(&self.basic()),
        )
        .await
    }

    /// The public client's refresh.
    pub async fn refresh(&self, token: &str) -> Reply {
        self.token(
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &self.f.public),
                ("refresh_token", token),
            ],
            None,
        )
        .await
    }

    /// Fresh tokens for the public client from the signed-in browser.
    pub async fn tokens(&self) -> Value {
        let code = self.code(&self.f.public).await;
        body(&self.exchange(&code).await, 200)
    }

    /// The confidential client's `Basic` credentials.
    pub fn basic(&self) -> String {
        basic(&self.f.confidential, &self.f.secret)
    }

    /// RFC 7662 as the confidential client.
    pub async fn introspect(&self, token: &str) -> Value {
        let p = Params::new(vec![("token".into(), token.into())]).unwrap();
        body(
            &self
                .c
                .oauth
                .introspect(&self.f.realm, &p, Some(&self.basic()))
                .await,
            200,
        )
    }

    /// `/userinfo` with `access` as a DPoP token and a proof that binds it.
    pub async fn userinfo(&self, access: &str) -> Reply {
        let uri = format!("{}/userinfo", self.f.issuer);
        let proof = self.proof("GET", &uri, Some(access));
        self.c
            .oauth
            .userinfo(
                &self.f.realm,
                "GET",
                Some(&format!("DPoP {access}")),
                &[&proof],
            )
            .await
    }

    /// A `private_key_jwt` assertion of the keyed client.
    pub fn assertion(&self, aud: &str) -> String {
        let jti = b64url_encode(&access_crypto::random::bytes::<16>().unwrap());
        let id = &self.f.keyed;
        sign(
            &self.f.client_key,
            r#"{"alg":"ES256","typ":"JWT"}"#,
            &format!(
                r#"{{"iss":"{id}","sub":"{id}","aud":"{aud}","exp":{},"iat":{},"jti":"{jti}"}}"#,
                now() / 1000 + 60,
                now() / 1000
            ),
        )
    }

    pub async fn end_session(&self, pairs: &[(&str, &str)], cookie: Option<&str>) -> Reply {
        let p = Params::new(
            pairs
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
        )
        .unwrap();
        self.c.oauth.end_session(&self.f.realm, &p, cookie).await
    }

    /// Whether the browser holding `cookie` is still signed in here.
    pub async fn signed_in(&self, cookie: &str) -> bool {
        let r = self.authorize(&[("prompt", "none")], Some(cookie)).await;
        let to = location(&r);
        to.contains("code=")
    }
}

pub fn basic(id: &str, secret: &str) -> String {
    format!("Basic {}", b64_std(&format!("{id}:{secret}")))
}

pub fn b64_std(s: &str) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let b = s.as_bytes();
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.len();
        let v = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= n {
                out.push(char::from(A[((v >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn location(r: &Reply) -> String {
    match r {
        Reply::Redirect(l) => l.clone(),
        other => panic!("not a redirect: {other:?}"),
    }
}

pub fn query(url: &str, name: &str) -> String {
    query_opt(url, name).unwrap_or_else(|| panic!("{name} missing in {url}"))
}

pub fn query_opt(url: &str, name: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    Params::parse(q).ok()?.get(name).map(String::from)
}

pub fn body(r: &Reply, status: u16) -> Value {
    match r {
        Reply::Json {
            status: s, body, ..
        } if *s == status => serde_json::from_str(body).unwrap(),
        other => panic!("expected {status}: {other:?}"),
    }
}

pub fn error(r: &Reply) -> String {
    match r {
        Reply::Json { status, body, .. } if *status >= 400 => serde_json::from_str::<Value>(body)
            .unwrap()["error"]
            .as_str()
            .unwrap()
            .to_owned(),
        other => panic!("expected an error: {other:?}"),
    }
}

pub fn claims(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&b64url_decode(payload).unwrap()).unwrap()
}

pub fn header(jwt: &str) -> Value {
    let h = jwt.split('.').next().unwrap();
    serde_json::from_slice(&b64url_decode(h).unwrap()).unwrap()
}

/// The status of a reply as HTTP would carry it.
pub fn status(r: &Reply) -> u16 {
    match r {
        Reply::Redirect(_) => 303,
        Reply::Json { status, .. } | Reply::Problem { status, .. } => *status,
        Reply::Unavailable => 503,
        Reply::NotFound => 404,
    }
}
