//! The realm authorization server against real PostgreSQL and a real identity signer on a
//! Unix socket (OP-146 I7): the code flow with PKCE and DPoP from a signed-in session, refresh
//! rotation and reuse, client authentication methods, redirect URI exactness, errors with
//! `iss`, introspection, revocation and logout.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
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
use access_crypto::opaque_id::IdKey;
use access_identity_account::notify::delivery::Backoff;
use access_identity_oauth::adapters::dpop::PgReplayCache;
use access_identity_oauth::adapters::oauth::{HostedPages, OsRandom, PgLogoutQueue, PgOAuth};
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::backchannel::Courier;
use access_identity_oauth::app::oauth::{Env, OAuth, Realm, Reply, TokenHttp};
use access_identity_oauth::domain::dpop::DpopProfile;
use access_identity_oauth::domain::issuer::{IssuerStyle, RealmBase};
use access_identity_oauth::domain::request::Params;
use access_identity_oauth::ports::Unavailable;
use access_identity_oauth::ports::dpop::{Clock, ClockUnavailable};
use access_identity_oauth::ports::oauth::{
    ClientKeys, LogoutDelivery, PostFailure, TokenSigner as _,
};
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

const ISSUER: &str = "https://acme.id.test";
const HOST: &str = "acme.id.test";
const CB: &str = "https://shop.example/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const HOUR: u64 = 3_600_000;
const PUBLIC: &str = "cli_0000000000000000000000000a";
const CONFIDENTIAL: &str = "cli_0000000000000000000000000b";
const KEYED: &str = "cli_0000000000000000000000000c";
const KEYED_JWKS: &str = "https://shop.example/jwks.json";
const PUSHED: &str = "cli_0000000000000000000000000d";
/// A registered platform product client (OP-149 m.4): the one RFC 8707 resource besides the
/// realm (OP-149 m.26 (a)).
const PRODUCT: &str = "cli_0000000000000000000000000e";
/// A third party's product registered with the same `platform_product` role (OP-150 m.3 (m)).
const THIRD: &str = "cli_0000000000000000000000000f";
const SECRET: &str = "shop-secret-shop-secret-shop-secret-shop-se";

struct SysClock;

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

fn now() -> u64 {
    SysClock.now().unwrap()
}

#[derive(Clone, Default)]
struct StaticKeys(Arc<Mutex<HashMap<String, Vec<u8>>>>);

impl ClientKeys for StaticKeys {
    fn fetch(&self, uri: &str) -> impl Future<Output = Result<Vec<u8>, Unavailable>> {
        std::future::ready(self.0.lock().unwrap().get(uri).cloned().ok_or(Unavailable))
    }
}

struct TestEnv {
    db: PgOAuth,
    signer: SignerKeys,
    keys: StaticKeys,
    directory: PgDirectory,
    pool: Pool,
    as_ring: Arc<NonceRing>,
    rs_ring: Arc<NonceRing>,
    profile: DpopProfile,
    ids: IdKey,
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
    type Projections = access_internal_api::projections::Unserved;
    type Tenants = IdKey;

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
    fn nonces(&self, _realm: RealmId, role: Role) -> Option<Arc<NonceRing>> {
        Some(match role {
            Role::AuthorizationServer => self.as_ring.clone(),
            Role::ResourceServer => self.rs_ring.clone(),
        })
    }
    fn dpop(&self) -> &DpopProfile {
        &self.profile
    }
    fn projections(&self) -> &access_internal_api::projections::Unserved {
        &access_internal_api::projections::Unserved
    }
    fn tenant_ids(&self) -> &IdKey {
        &self.ids
    }
}

fn temp(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "aio-oauth-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A signer whose key set for `realm` was opened two hours ago, so it is past its publish
/// lead and signs now (MD-6: publish, wait, use).
fn signer(dir: &Path, realm: RealmId) -> PathBuf {
    let mut service = Service::start(
        SealedFactory::new(SoftKek::new("realm-kek", [7; 32])),
        DirVault::new(dir),
        Policy::REALM,
    )
    .unwrap();
    let opened = service.handle(
        Request::Open {
            realm: SignerRealm(*realm.as_bytes()),
            alg: JwsAlg::Es256,
        },
        now_ms() - 2 * HOUR,
        7,
    );
    assert_eq!(opened, Response::Opened);
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

fn ring(role: Role, key: u8) -> Arc<NonceRing> {
    Arc::new(NonceRing::new(
        [2; 16],
        role,
        NoncePolicy::new(HOUR, MAX_STALE_MS).unwrap(),
        1,
        NonceKey::new(Secret::new([key; 32])),
    ))
}

/// A domain whose log holds ALLOW decisions at positions 1..=allows.
async fn domain(db: &TestDb, t: TenantId, allows: u8) -> DomainId {
    let d = DomainId::from_bytes([40; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [40; 32],
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
        };
        commit_batch(&db.sequencer, &d, *t.as_bytes(), &batch)
            .await
            .unwrap();
        head = next;
    }
    d
}

struct World {
    db: TestDb,
    oauth: OAuth<TestEnv>,
    realm: Realm,
    subject: [u8; 16],
    cookie: String,
    dpop_key: EcdsaKeyPair,
    client_key: EcdsaKeyPair,
    keys: StaticKeys,
    socket: PathBuf,
}

fn client(n: u8, id: &str, method: &str) -> ClientRow {
    ClientRow {
        client_uuid: [n; 16],
        client_id: String::from(id),
        display_name: String::from("Shop"),
        auth_method: String::from(method),
        jwks_uri: (method == "private_key_jwt").then(|| String::from(KEYED_JWKS)),
        redirect_uris: vec![String::from(CB), String::from("http://127.0.0.1/native")],
        active: true,
        secret_hash: (method == "client_secret_basic").then(|| secret_digest(SECRET.as_bytes())),
        post_logout_redirect_uris: vec![String::from("https://shop.example/bye")],
        backchannel_logout_uri: Some(String::from("https://shop.example/backchannel")),
        jwks: None,
        platform_product: None,
        service_key: None,
        event_receiver: None,
        require_par: false,
        public_sub: false,
        sector_identifier_uri: None,
    }
}

fn ec_jwk(k: &EcdsaKeyPair) -> String {
    let p = k.public_key().as_ref();
    format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
        b64url_encode(&p[1..33]),
        b64url_encode(&p[33..])
    )
}

fn sign(k: &EcdsaKeyPair, header: &str, payload: &str) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let sig = k.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(sig.as_ref()))
}

async fn world() -> World {
    let db = fresh().await.unwrap();
    let day = u32::try_from(now() / 86_400_000).unwrap();
    for d in [day - 1, day, day + 1] {
        open_dpop_replay_day(&db.archive, d).await.unwrap();
    }
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 6).await;
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, &d, "acme", "pool-default")
        .await
        .unwrap();
    tx.enter_realm(r).await.unwrap();
    create_settings(&mut tx).await.unwrap();
    let issuer = RealmBase::parse("https://id.test")
        .unwrap()
        .issuer("acme", IssuerStyle::Subdomain)
        .unwrap();
    add_hostname(&mut tx, issuer.authority(), HostKind::Subdomain)
        .await
        .unwrap();
    assert!(set_issuer(&mut tx, issuer.as_str()).await.unwrap());
    for (i, (id, method)) in [
        (PUBLIC, "none"),
        (CONFIDENTIAL, "client_secret_basic"),
        (KEYED, "private_key_jwt"),
        (PUSHED, "client_secret_basic"),
        (PRODUCT, "private_key_jwt"),
        (THIRD, "private_key_jwt"),
    ]
    .into_iter()
    .enumerate()
    {
        let n = u8::try_from(i + 1).unwrap();
        let b = bind(
            &mut tx,
            &Decision {
                domain: &d,
                position: u64::from(n),
                nonce: &[n; 16],
                intent: [9; 32],
                change: [5; 32],
                action: "idp.client.register",
            },
        )
        .await
        .unwrap()
        .unwrap();
        let mut row = ClientRow {
            require_par: id == PUSHED,
            public_sub: false,
            sector_identifier_uri: None,
            ..client(n, id, method)
        };
        if id == PRODUCT || id == THIRD {
            let name = if id == PRODUCT { "work" } else { "acme-ledger" };
            row.platform_product = Some(String::from(name));
            row.service_key = Some(vec![0xa0]);
        }
        insert_client(&mut tx, &b, &row).await.unwrap();
    }
    let subject = tx
        .insert_subject("active", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let socket = signer(&temp("w"), r);
    let keys = StaticKeys::default();
    let client_key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    keys.0.lock().unwrap().insert(
        String::from(KEYED_JWKS),
        format!(r#"{{"keys":[{}]}}"#, ec_jwk(&client_key)).into_bytes(),
    );
    let env = TestEnv {
        db: PgOAuth::with_reader(db.app.clone(), db.reader.clone()),
        signer: SignerKeys::new(socket.clone()),
        keys: keys.clone(),
        directory: PgDirectory::new(db.router.clone()),
        pool: db.app.clone(),
        as_ring: ring(Role::AuthorizationServer, 1),
        rs_ring: ring(Role::ResourceServer, 2),
        profile: DpopProfile::default(),
        ids: IdKey::new(Secret::new([0x1d; 32])),
    };
    let oauth = OAuth::new(env);
    let realm = oauth.realm(HOST, None).await.unwrap().unwrap();
    let mut w = World {
        db,
        oauth,
        realm,
        subject,
        cookie: String::new(),
        dpop_key: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap(),
        client_key,
        keys,
        socket,
    };
    w.cookie = w.sign_in(now() - 60_000).await;
    w
}

impl World {
    /// A signed-in browser: a login session with a password-level assurance (I5).
    async fn sign_in(&self, at: u64) -> String {
        let value: [u8; 32] = access_crypto::random::bytes().unwrap();
        let assurance = serde_json::to_vec(&vector(&[Factor::password(at)])).unwrap();
        let mut tx = TenantTx::begin(&self.db.app, self.realm.tenant, self.realm.realm)
            .await
            .unwrap();
        tx.insert_session(&NewSession {
            cookie_hash: &cookie_digest(&value),
            subject: self.subject,
            session_epoch: 0,
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

    fn jkt(&self) -> String {
        let key = PublicKey::P256(self.dpop_key.public_key().as_ref().to_vec());
        b64url_encode(&thumbprint(&key))
    }

    fn proof(&self, method: &str, uri: &str, access_token: Option<&str>) -> String {
        self.proof_by(&self.dpop_key, method, uri, access_token)
    }

    fn proof_by(
        &self,
        key: &EcdsaKeyPair,
        method: &str,
        uri: &str,
        access_token: Option<&str>,
    ) -> String {
        let role = if access_token.is_some() {
            &self.oauth.env().rs_ring
        } else {
            &self.oauth.env().as_ring
        };
        let nonce = role.issue(now()).unwrap();
        let jti = b64url_encode(&access_crypto::random::bytes::<16>().unwrap());
        let extra = access_token
            .map(|t| format!(r#","ath":"{}""#, ath(t)))
            .unwrap_or_default();
        sign(
            key,
            &format!(
                r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{}}}"#,
                ec_jwk(key)
            ),
            &format!(
                r#"{{"jti":"{jti}","htm":"{method}","htu":"{uri}","iat":{},"nonce":"{nonce}"{extra}}}"#,
                now() / 1000
            ),
        )
    }

    async fn authorize(&self, pairs: &[(&str, &str)], cookie: Option<&str>) -> Reply {
        let mut p: Vec<(String, String)> = vec![
            ("client_id", PUBLIC),
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
        self.oauth
            .authorize(&self.realm, &Params::new(p).unwrap(), cookie)
            .await
    }

    async fn code(&self, client_id: &str) -> String {
        let r = self
            .authorize(&[("client_id", client_id)], Some(&self.cookie))
            .await;
        query(&location(&r), "code")
    }

    async fn token(&self, pairs: &[(&str, &str)], authorization: Option<&str>) -> Reply {
        let p: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        let proof = self.proof("POST", &format!("{ISSUER}/token"), None);
        self.oauth
            .token(
                &self.realm,
                &Params::new(p).unwrap(),
                TokenHttp {
                    authorization,
                    dpop: &[&proof],
                },
            )
            .await
    }

    async fn exchange(&self, code: &str) -> Reply {
        self.token(
            &[
                ("grant_type", "authorization_code"),
                ("client_id", PUBLIC),
                ("code", code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            None,
        )
        .await
    }

    async fn refresh(&self, token: &str) -> Reply {
        self.token(
            &[
                ("grant_type", "refresh_token"),
                ("client_id", PUBLIC),
                ("refresh_token", token),
            ],
            None,
        )
        .await
    }

    async fn introspect(&self, token: &str) -> Value {
        let p = Params::new(vec![("token".into(), token.into())]).unwrap();
        body(
            &self
                .oauth
                .introspect(&self.realm, &p, Some(&basic(CONFIDENTIAL, SECRET)))
                .await,
            200,
        )
    }

    async fn userinfo(&self, access: &str) -> Reply {
        let uri = format!("{ISSUER}/userinfo");
        let proof = self.proof("GET", &uri, Some(access));
        self.oauth
            .userinfo(
                &self.realm,
                "GET",
                Some(&format!("DPoP {access}")),
                &[&proof],
            )
            .await
    }
}

fn basic(id: &str, secret: &str) -> String {
    format!("Basic {}", base64_std::encode(&format!("{id}:{secret}")))
}

mod base64_std {
    pub(super) fn encode(s: &str) -> String {
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
}

fn location(r: &Reply) -> String {
    match r {
        Reply::Redirect(l) => l.clone(),
        other => panic!("not a redirect: {other:?}"),
    }
}

fn query(url: &str, name: &str) -> String {
    let q = url.split_once('?').unwrap().1;
    Params::parse(q)
        .unwrap()
        .get(name)
        .unwrap_or_else(|| panic!("{name} missing in {url}"))
        .to_owned()
}

fn body(r: &Reply, status: u16) -> Value {
    match r {
        Reply::Json {
            status: s, body, ..
        } if *s == status => serde_json::from_str(body).unwrap(),
        other => panic!("expected {status}: {other:?}"),
    }
}

fn error(r: &Reply) -> String {
    match r {
        Reply::Json { status, body, .. } if *status >= 400 => serde_json::from_str::<Value>(body)
            .unwrap()["error"]
            .as_str()
            .unwrap()
            .to_owned(),
        other => panic!("expected an error: {other:?}"),
    }
}

fn claims(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&b64url_decode(payload).unwrap()).unwrap()
}

// IDP-7, IDP-11, TN-27, TN-31, RFC 9207, MD-7, MD-10, OP-146 m.5 (c), §11.4.5 #20, CR-38: a
// signed-out browser goes to the hosted login with the request stored, comes back, gets a code
// with iss, and the code is exchanged once with PKCE and a DPoP proof for a cnf-bound access
// token, a short ID token with the pairwise sub and a refresh token
#[tokio::test]
async fn code_flow_with_pkce_and_dpop() {
    // G57, IDP-24, X41, K02, K03
    let w = world().await;
    let login = location(&w.authorize(&[("dpop_jkt", &w.jkt())], None).await);
    let prefix = format!("{ISSUER}/login?return_to=");
    assert!(login.starts_with(&prefix), "{login}");
    let return_to = query(&login, "return_to");
    assert!(access_identity_oauth::domain::login::return_to_ok(
        &w.realm.issuer,
        &return_to
    ));
    let back = Params::parse(return_to.split_once('?').unwrap().1).unwrap();
    let reply = w.oauth.authorize(&w.realm, &back, Some(&w.cookie)).await;
    let to = location(&reply);
    assert!(to.starts_with("https://shop.example/cb?code="), "{to}");
    assert_eq!(query(&to, "state"), "st");
    assert_eq!(query(&to, "iss"), ISSUER);
    // RFC 9126 §4: the stored request is used once
    let again = w.oauth.authorize(&w.realm, &back, Some(&w.cookie)).await;
    assert!(
        matches!(again, Reply::Problem { status: 400, .. }),
        "{again:?}"
    );

    let code = query(&to, "code");
    let tokens = body(&w.exchange(&code).await, 200);
    assert_eq!(tokens["token_type"], "DPoP");
    let at = claims(tokens["access_token"].as_str().unwrap());
    assert_eq!(at["cnf"]["jkt"], w.jkt());
    assert_eq!(at["aud"], ISSUER);
    assert_eq!(at["client_id"], PUBLIC);
    // OP-149 m.34 (a): the realm's own token names no tenant
    assert!(at.get("access_tenant").is_none());
    let id = claims(tokens["id_token"].as_str().unwrap());
    assert_eq!(id["aud"], PUBLIC);
    assert_eq!(id["nonce"], "n-1");
    assert_eq!(id["iss"], ISSUER);
    assert!(id["exp"].as_u64().unwrap() - id["iat"].as_u64().unwrap() <= 300);
    let sub = id["sub"].as_str().unwrap();
    assert_eq!(sub.len(), 43);
    assert_eq!(at["sub"], sub);
    assert_eq!(id["sid"], at["sid"]);

    // §11.4.5 #20, RFC 6749 §4.1.2: the code is single use; a second exchange revokes the grant
    assert_eq!(error(&w.exchange(&code).await), "invalid_grant");
    let refresh = tokens["refresh_token"].as_str().unwrap();
    assert_eq!(error(&w.refresh(refresh).await), "invalid_grant");

    // MD-10: another client sees another pairwise sub
    let code = w.code(CONFIDENTIAL).await;
    let other = body(
        &w.token(
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            Some(&basic(CONFIDENTIAL, SECRET)),
        )
        .await,
        200,
    );
    assert_ne!(claims(other["id_token"].as_str().unwrap())["sub"], sub);
}

/// The realm's tenant as every product-facing surface names it (OP-149 m.19 (a)).
fn tenant_id(w: &World) -> String {
    IdKey::new(Secret::new([0x1d; 32]))
        .encode("tnt", *w.realm.tenant.as_bytes())
        .unwrap()
}

// OP-149 m.26 (a), m.34 (a), RFC 8707, TN-27, PI-11, AG-8: a registered platform product client
// is the one resource a protocol-scope token may name besides the realm; the token's aud is then
// that client_id, it names the tenant in access_tenant, cnf and sid stay, the refresh keeps the
// audience and the tenant, introspection reports both, the realm's own userinfo refuses the
// token, and any other resource is invalid_target
#[tokio::test]
async fn a_platform_product_client_is_a_resource() {
    let w = world().await;
    let to = location(&w.authorize(&[("resource", PRODUCT)], Some(&w.cookie)).await);
    let code = query(&to, "code");
    // RFC 8707 §2.2: the token request may repeat the resource, never name another
    assert_eq!(
        error(
            &w.token(
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", PUBLIC),
                    ("code", &code),
                    ("redirect_uri", CB),
                    ("code_verifier", VERIFIER),
                    ("resource", ISSUER),
                ],
                None,
            )
            .await
        ),
        "invalid_target"
    );
    let tokens = body(
        &w.token(
            &[
                ("grant_type", "authorization_code"),
                ("client_id", PUBLIC),
                ("code", &code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
                ("resource", PRODUCT),
            ],
            None,
        )
        .await,
        200,
    );
    let access = tokens["access_token"].as_str().unwrap();
    let at = claims(access);
    assert_eq!(at["aud"], PRODUCT);
    assert_eq!(at["iss"], ISSUER);
    assert_eq!(at["client_id"], PUBLIC);
    assert_eq!(at["cnf"]["jkt"], w.jkt());
    assert_eq!(at["access_tenant"], tenant_id(&w));
    assert_eq!(at["sid"].as_str().unwrap().len(), 22);
    let id = claims(tokens["id_token"].as_str().unwrap());
    assert_eq!(id["aud"], PUBLIC);
    assert!(id.get("access_tenant").is_none());
    // RFC 9068 §4: the realm is not this token's audience
    assert!(matches!(
        w.userinfo(access).await,
        Reply::Json { status: 401, .. }
    ));
    let refresh = tokens["refresh_token"].as_str().unwrap();
    assert_eq!(
        error(
            &w.token(
                &[
                    ("grant_type", "refresh_token"),
                    ("client_id", PUBLIC),
                    ("refresh_token", refresh),
                    ("resource", "cli_0000000000000000000000000z"),
                ],
                None,
            )
            .await
        ),
        "invalid_target"
    );
    let again = claims(
        body(&w.refresh(refresh).await, 200)["access_token"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(again["aud"], PRODUCT);
    assert_eq!(again["access_tenant"], tenant_id(&w));

    // introspection by a confidential client of its own token names the audience
    let code = w
        .authorize(
            &[("client_id", CONFIDENTIAL), ("resource", PRODUCT)],
            Some(&w.cookie),
        )
        .await;
    let code = query(&location(&code), "code");
    let t = body(
        &w.token(
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            Some(&basic(CONFIDENTIAL, SECRET)),
        )
        .await,
        200,
    );
    let a = w.introspect(t["access_token"].as_str().unwrap()).await;
    assert_eq!(
        (a["active"].as_bool(), a["aud"].as_str()),
        (Some(true), Some(PRODUCT))
    );
    assert_eq!(a["access_tenant"], tenant_id(&w));
    let plain = w.introspect(access).await;
    assert_eq!(plain["active"], false);

    // only a registered platform product client is a resource
    for other in [
        KEYED,
        "cli_0000000000000000000000000z",
        "https://api.example",
    ] {
        let r = location(&w.authorize(&[("resource", other)], Some(&w.cookie)).await);
        assert_eq!(query(&r, "error"), "invalid_target", "{other}");
    }
    let realm = location(&w.authorize(&[("resource", ISSUER)], Some(&w.cookie)).await);
    assert!(realm.contains("code="), "{realm}");
}

// OP-150 m.3 (m), MUST-NEVER-13, XI-18: a third party's product registered with the
// platform_product role is an RFC 8707 resource exactly as Suiss Work is; the token's aud is
// its client_id, the realm's userinfo refuses it, and a grant for one product never answers
// for the other
#[tokio::test]
async fn a_third_party_product_is_a_resource_like_a_first_party_one() {
    // OP-149 m.26 (a), (f), RFC 8707 §2.2, RFC 9068 §4, PI-13
    let w = world().await;
    let mut tokens = Vec::new();
    for product in [PRODUCT, THIRD] {
        let to = location(&w.authorize(&[("resource", product)], Some(&w.cookie)).await);
        let code = query(&to, "code");
        let other = if product == PRODUCT { THIRD } else { PRODUCT };
        assert_eq!(
            error(
                &w.token(
                    &[
                        ("grant_type", "authorization_code"),
                        ("client_id", PUBLIC),
                        ("code", &code),
                        ("redirect_uri", CB),
                        ("code_verifier", VERIFIER),
                        ("resource", other),
                    ],
                    None,
                )
                .await
            ),
            "invalid_target"
        );
        let t = body(
            &w.token(
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", PUBLIC),
                    ("code", &code),
                    ("redirect_uri", CB),
                    ("code_verifier", VERIFIER),
                    ("resource", product),
                ],
                None,
            )
            .await,
            200,
        );
        let access = t["access_token"].as_str().unwrap().to_owned();
        let at = claims(&access);
        assert_eq!(at["aud"], product);
        assert_eq!(at["iss"], ISSUER);
        assert_eq!(at["cnf"]["jkt"], w.jkt());
        assert_eq!(at["access_tenant"], tenant_id(&w));
        assert!(matches!(
            w.userinfo(&access).await,
            Reply::Json { status: 401, .. }
        ));
        tokens.push(at);
    }
    let shape = |c: &Value| {
        let mut keys: Vec<&String> = c.as_object().unwrap().keys().collect();
        keys.sort();
        keys.into_iter().cloned().collect::<Vec<_>>()
    };
    assert_eq!(shape(&tokens[0]), shape(&tokens[1]));
}

// IDP-7, CR-39, RFC 9449 §10, TN-27, §10.4.1: the exchange checks the exact redirect URI, the
// PKCE verifier, the client and the DPoP key bound with dpop_jkt
#[tokio::test]
async fn the_exchange_checks_redirect_pkce_client_and_key() {
    let w = world().await;
    let code = w.code(PUBLIC).await;
    let bad = |pairs: Vec<(&'static str, String)>| {
        let mut p = vec![
            ("grant_type", String::from("authorization_code")),
            ("client_id", String::from(PUBLIC)),
            ("code", code.clone()),
            ("redirect_uri", String::from(CB)),
            ("code_verifier", String::from(VERIFIER)),
        ];
        for (k, v) in pairs {
            p.retain(|(n, _)| *n != k);
            p.push((k, v));
        }
        p
    };
    for pairs in [
        bad(vec![(
            "redirect_uri",
            String::from("https://shop.example/cb/"),
        )]),
        bad(vec![("code_verifier", VERIFIER.replace('d', "e"))]),
        bad(vec![("code_verifier", String::from("short"))]),
        bad(vec![("code", String::from("x"))]),
    ] {
        let p: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(error(&w.token(&p, None).await), "invalid_grant", "{p:?}");
    }
    // a code is another client's
    let p = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", CB),
        ("code_verifier", VERIFIER),
    ];
    assert_eq!(
        error(&w.token(&p, Some(&basic(CONFIDENTIAL, SECRET))).await),
        "invalid_grant"
    );
    // TN-27: no proof, no token
    let p = Params::new(vec![
        ("grant_type".into(), "authorization_code".into()),
        ("client_id".into(), PUBLIC.into()),
        ("code".into(), code.clone()),
        ("redirect_uri".into(), CB.into()),
        ("code_verifier".into(), VERIFIER.into()),
    ])
    .unwrap();
    let none = w
        .oauth
        .token(
            &w.realm,
            &p,
            TokenHttp {
                authorization: None,
                dpop: &[],
            },
        )
        .await;
    assert_eq!(error(&none), "invalid_dpop_proof");
    // RFC 9449 §10: a code bound with dpop_jkt is redeemed only with that key
    let other_key = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    let r = w
        .authorize(&[("dpop_jkt", other_key)], Some(&w.cookie))
        .await;
    let bound = query(&location(&r), "code");
    assert_eq!(error(&w.exchange(&bound).await), "invalid_dpop_proof");
    // the right code still works after all of that
    assert!(body(&w.exchange(&code).await, 200)["access_token"].is_string());
    // RFC 6749 §5.2, OP-146 m.6: no ROPC, no implicit; device code later
    for grant in [
        "password",
        "urn:ietf:params:oauth:grant-type:device_code",
        "implicit",
    ] {
        let p = [("grant_type", grant), ("client_id", PUBLIC)];
        assert_eq!(error(&w.token(&p, None).await), "unsupported_grant_type");
    }
    // §10.4.1: client credentials only for a confidential client
    let p = [("grant_type", "client_credentials"), ("client_id", PUBLIC)];
    assert_eq!(error(&w.token(&p, None).await), "unauthorized_client");
}

// TN-31, RR-18, CR-38, TN-50, G57: the refresh token rotates; presenting a rotated one revokes
// the grant and raises the session epoch, which ends the browser session too
#[tokio::test]
async fn refresh_rotates_and_reuse_ends_everything() {
    // AS-M8, §12.2.1
    let w = world().await;
    let code = w.code(PUBLIC).await;
    let first = body(&w.exchange(&code).await, 200);
    let r1 = first["refresh_token"].as_str().unwrap();
    let second = body(&w.refresh(r1).await, 200);
    let r2 = second["refresh_token"].as_str().unwrap();
    assert_ne!(r1, r2);
    assert_eq!(
        claims(second["id_token"].as_str().unwrap())["sid"],
        claims(first["id_token"].as_str().unwrap())["sid"]
    );
    let access = second["access_token"].as_str().unwrap();
    assert_eq!(
        body(&w.userinfo(access).await, 200)["sub"]
            .as_str()
            .unwrap()
            .len(),
        43
    );
    // reuse of r1
    assert_eq!(error(&w.refresh(r1).await), "invalid_grant");
    assert_eq!(error(&w.refresh(r2).await), "invalid_grant");
    assert!(matches!(
        w.userinfo(access).await,
        Reply::Json { status: 401, .. }
    ));
    let gone = w.authorize(&[("prompt", "none")], Some(&w.cookie)).await;
    assert_eq!(query(&location(&gone), "error"), "login_required");
}

// TN-31, §10.4.3 m.4: a public client's refresh token is bound to its DPoP key
#[tokio::test]
async fn a_public_refresh_token_needs_its_key() {
    let mut w = world().await;
    let code = w.code(PUBLIC).await;
    let t = body(&w.exchange(&code).await, 200);
    w.dpop_key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    assert_eq!(
        error(&w.refresh(t["refresh_token"].as_str().unwrap()).await),
        "invalid_dpop_proof"
    );
}

// §11.4.5, RFC 7523 §3, §10.4.5, CR-38, RFC 6749 §2.3: none, client_secret_basic and
// private_key_jwt each authenticate only by their registered method; an assertion is used once
#[tokio::test]
async fn client_authentication_methods() {
    let world = world().await;
    let w = &world;
    let exchange = |code: String| {
        vec![
            ("grant_type", String::from("authorization_code")),
            ("code", code),
            ("redirect_uri", String::from(CB)),
            ("code_verifier", String::from(VERIFIER)),
        ]
    };
    let pairs = |v: &Vec<(&'static str, String)>| -> Vec<(&'static str, String)> { v.clone() };
    let call = |p: Vec<(&'static str, String)>, auth: Option<String>| async move {
        let p: Vec<(&str, &str)> = p.iter().map(|(k, v)| (*k, v.as_str())).collect();
        w.token(&p, auth.as_deref()).await
    };
    let code = w.code(CONFIDENTIAL).await;
    assert_eq!(
        error(&call(exchange(code.clone()), Some(basic(CONFIDENTIAL, "wrong"))).await),
        "invalid_client"
    );
    let mut as_public = exchange(code.clone());
    as_public.push(("client_id", String::from(CONFIDENTIAL)));
    assert_eq!(error(&call(as_public, None).await), "invalid_client");
    assert!(
        body(
            &call(exchange(code), Some(basic(CONFIDENTIAL, SECRET))).await,
            200
        )["id_token"]
            .is_string()
    );

    let assertion = |aud: &str| {
        let jti = b64url_encode(&access_crypto::random::bytes::<16>().unwrap());
        sign(
            &w.client_key,
            r#"{"alg":"ES256","typ":"JWT"}"#,
            &format!(
                r#"{{"iss":"{KEYED}","sub":"{KEYED}","aud":"{aud}","exp":{},"iat":{},"jti":"{jti}"}}"#,
                now() / 1000 + 60,
                now() / 1000
            ),
        )
    };
    let with = |code: String, a: String| {
        let mut p = exchange(code);
        p.push((
            "client_assertion_type",
            String::from("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
        ));
        p.push(("client_assertion", a));
        p
    };
    let a = assertion(ISSUER);
    let code = w.code(KEYED).await;
    assert!(body(&call(with(code, a.clone()), None).await, 200)["access_token"].is_string());
    let code = w.code(KEYED).await;
    assert_eq!(
        error(&call(with(code.clone(), a), None).await),
        "invalid_client"
    );
    assert_eq!(
        error(&call(with(code.clone(), assertion("https://evil.test")), None).await),
        "invalid_client"
    );
    let ok = with(code, assertion(&format!("{ISSUER}/token")));
    assert!(body(&call(pairs(&ok), None).await, 200)["access_token"].is_string());
    w.keys.0.lock().unwrap().clear();
    let code = w.code(KEYED).await;
    assert_eq!(
        call(with(code, assertion(ISSUER)), None).await,
        Reply::Unavailable
    );
}

// IDP-7, must-never #16, TN-104, X41, RFC 9207, CR-40, RFC 9126: a bad client or redirect URI is
// shown, not redirected; everything else goes back with iss; loopback ports are free; PAR
// requests are used once and only by their client
#[tokio::test]
async fn redirect_exactness_errors_and_par() {
    let w = world().await;
    for (k, v) in [
        ("redirect_uri", "https://shop.example/cb/"),
        ("redirect_uri", "https://evil.example/cb"),
        ("client_id", "cli_00000000000000000000000zzz"),
    ] {
        let r = w.authorize(&[(k, v)], Some(&w.cookie)).await;
        assert!(
            matches!(r, Reply::Problem { status: 400, .. }),
            "{k}={v}: {r:?}"
        );
    }
    let native = w
        .authorize(
            &[("redirect_uri", "http://127.0.0.1:61234/native")],
            Some(&w.cookie),
        )
        .await;
    assert!(location(&native).starts_with("http://127.0.0.1:61234/native?code="));
    for (k, v, e) in [
        ("response_type", "token", "unsupported_response_type"),
        ("code_challenge_method", "plain", "invalid_request"),
        ("resource", "https://api.example", "invalid_target"),
    ] {
        let to = location(&w.authorize(&[(k, v)], Some(&w.cookie)).await);
        assert_eq!(query(&to, "error"), e);
        assert_eq!(query(&to, "iss"), ISSUER);
        assert_eq!(query(&to, "state"), "st");
    }
    // CR-40: prompt=none without a session answers login_required, account or not
    let to = location(&w.authorize(&[("prompt", "none")], None).await);
    assert_eq!(query(&to, "error"), "login_required");
    assert_eq!(query(&to, "iss"), ISSUER);
    // §10.4.6: prompt=login sends a signed-in browser to the login once
    let login = location(&w.authorize(&[("prompt", "login")], Some(&w.cookie)).await);
    assert!(login.contains("reason=reauthenticate"), "{login}");

    let p = Params::new(
        [
            ("redirect_uri", CB),
            ("response_type", "code"),
            ("scope", "openid"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "par"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect(),
    )
    .unwrap();
    let pushed = body(
        &w.oauth
            .par(&w.realm, &p, Some(&basic(CONFIDENTIAL, SECRET)), &[])
            .await,
        201,
    );
    let uri = pushed["request_uri"].as_str().unwrap();
    assert!(uri.starts_with("urn:ietf:params:oauth:request_uri:"));
    let use_it = |client: &str| {
        Params::new(vec![
            ("client_id".into(), client.into()),
            ("request_uri".into(), uri.into()),
        ])
        .unwrap()
    };
    let other = w
        .oauth
        .authorize(&w.realm, &use_it(PUBLIC), Some(&w.cookie))
        .await;
    assert!(matches!(other, Reply::Problem { .. }), "{other:?}");
    let to = location(
        &w.oauth
            .authorize(&w.realm, &use_it(CONFIDENTIAL), Some(&w.cookie))
            .await,
    );
    assert_eq!(query(&to, "state"), "par");
    let again = w
        .oauth
        .authorize(&w.realm, &use_it(CONFIDENTIAL), Some(&w.cookie))
        .await;
    assert!(matches!(again, Reply::Problem { .. }), "{again:?}");
    assert_eq!(
        error(
            &w.oauth
                .par(&w.realm, &p, Some(&basic(CONFIDENTIAL, "x")), &[])
                .await
        ),
        "invalid_client"
    );
}

fn push_params(extra: &[(&str, &str)]) -> Params {
    let mut p: Vec<(String, String)> = [
        ("redirect_uri", CB),
        ("response_type", "code"),
        ("scope", "openid"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("state", "par"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    p.extend(extra.iter().map(|(k, v)| ((*k).into(), (*v).into())));
    Params::new(p).unwrap()
}

fn use_uri(client: &str, uri: &str) -> Params {
    Params::new(vec![
        ("client_id".into(), client.into()),
        ("request_uri".into(), uri.into()),
    ])
    .unwrap()
}

fn keyed_assertion(w: &World, aud: &str) -> String {
    let jti = b64url_encode(&access_crypto::random::bytes::<16>().unwrap());
    sign(
        &w.client_key,
        r#"{"alg":"ES256","typ":"JWT"}"#,
        &format!(
            r#"{{"iss":"{KEYED}","sub":"{KEYED}","aud":"{aud}","exp":{},"iat":{},"jti":"{jti}"}}"#,
            now() / 1000 + 60,
            now() / 1000
        ),
    )
}

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

// RFC 9126 §2.1, RFC 7523, RFC 9449 §10.1, IDP-11, TN-27: a private_key_jwt client pushes its
// request; a DPoP proof sent with it binds the code to the proof key like dpop_jkt, so only that
// key redeems it; a proof that does not match dpop_jkt or the endpoint is refused
#[tokio::test]
async fn par_with_private_key_jwt_and_dpop() {
    // RFC 9126
    // IDP-11
    let w = world().await;
    let w = &w;
    let par_uri = format!("{ISSUER}/par");
    let push = |assertion: String, extra: Vec<(&'static str, String)>, dpop: Vec<String>| {
        let mut pairs: Vec<(&str, String)> = vec![
            ("client_assertion_type", String::from(ASSERTION_TYPE)),
            ("client_assertion", assertion),
        ];
        pairs.extend(extra);
        let p = push_params(
            &pairs
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect::<Vec<_>>(),
        );
        let w = &w;
        async move {
            let proofs: Vec<&str> = dpop.iter().map(String::as_str).collect();
            w.oauth.par(&w.realm, &p, None, &proofs).await
        }
    };
    let redeem = |uri: String| async move {
        let to = location(
            &w.oauth
                .authorize(&w.realm, &use_uri(KEYED, &uri), Some(&w.cookie))
                .await,
        );
        assert_eq!(query(&to, "state"), "par");
        query(&to, "code")
    };
    let exchange = |code: String| async move {
        w.token(
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &keyed_assertion(w, ISSUER)),
            ],
            None,
        )
        .await
    };

    // RFC 7523 §3: the assertion's audience is the issuer or the endpoint it is sent to
    for aud in [ISSUER, par_uri.as_str()] {
        let pushed = body(&push(keyed_assertion(w, aud), vec![], vec![]).await, 201);
        assert_eq!(pushed["expires_in"], 60);
    }
    assert_eq!(
        error(&push(keyed_assertion(w, "https://evil.test"), vec![], vec![]).await),
        "invalid_client"
    );

    // the proof key at /par is the key the code is bound to
    let proof = w.proof("POST", &par_uri, None);
    let pushed = push(keyed_assertion(w, ISSUER), vec![], vec![proof]).await;
    let Reply::Json { dpop_nonce, .. } = &pushed else {
        panic!("{pushed:?}");
    };
    assert!(dpop_nonce.is_some());
    let uri = body(&pushed, 201)["request_uri"]
        .as_str()
        .unwrap()
        .to_owned();
    let t = body(&exchange(redeem(uri).await).await, 200);
    assert_eq!(t["token_type"], "DPoP");

    let other = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    let proof = w.proof_by(&other, "POST", &par_uri, None);
    let pushed = push(keyed_assertion(w, ISSUER), vec![], vec![proof]).await;
    let uri = body(&pushed, 201)["request_uri"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        error(&exchange(redeem(uri).await).await),
        "invalid_dpop_proof"
    );

    // RFC 9449 §10.1: dpop_jkt and the proof name one key
    let proof = w.proof_by(&other, "POST", &par_uri, None);
    assert_eq!(
        error(
            &push(
                keyed_assertion(w, ISSUER),
                vec![("dpop_jkt", w.jkt())],
                vec![proof]
            )
            .await
        ),
        "invalid_dpop_proof"
    );
    let proof = w.proof("POST", &par_uri, None);
    body(
        &push(
            keyed_assertion(w, ISSUER),
            vec![("dpop_jkt", w.jkt())],
            vec![proof],
        )
        .await,
        201,
    );
    let wrong = w.proof("POST", &format!("{ISSUER}/token"), None);
    assert_eq!(
        error(&push(keyed_assertion(w, ISSUER), vec![], vec![wrong]).await),
        "invalid_dpop_proof"
    );
}

// RFC 9126 §6, §2.2, §4, §10.4.3: a client registered to require PAR is refused at /authorize
// without a pushed request, and served with one; a pushed request past its expiry is refused
#[tokio::test]
async fn par_required_per_client_and_expiry() {
    // RFC 9126
    let w = world().await;
    let direct = location(&w.authorize(&[("client_id", PUSHED)], Some(&w.cookie)).await);
    assert!(direct.starts_with(CB), "{direct}");
    assert_eq!(query(&direct, "error"), "invalid_request");
    assert_eq!(query(&direct, "iss"), ISSUER);
    assert_eq!(query(&direct, "state"), "st");
    // the other clients may still send their requests directly
    assert!(query(&location(&w.authorize(&[], Some(&w.cookie)).await), "code").len() > 10);

    let pushed = body(
        &w.oauth
            .par(
                &w.realm,
                &push_params(&[]),
                Some(&basic(PUSHED, SECRET)),
                &[],
            )
            .await,
        201,
    );
    let uri = pushed["request_uri"].as_str().unwrap();
    let to = location(
        &w.oauth
            .authorize(&w.realm, &use_uri(PUSHED, uri), Some(&w.cookie))
            .await,
    );
    assert_eq!(query(&to, "state"), "par");
    assert!(query(&to, "code").len() > 10);

    // RFC 9126 §2.2: a request_uri is refused past its expiry
    let handle: [u8; 32] = access_crypto::random::bytes().unwrap();
    let request = access_identity_oauth::domain::request::AuthRequest {
        client_id: String::from(CONFIDENTIAL),
        redirect_uri: String::from(CB),
        scope: vec![String::from("openid")],
        state: Some(String::from("late")),
        nonce: None,
        code_challenge: b64url_decode(CHALLENGE).unwrap().try_into().unwrap(),
        prompt: access_identity_oauth::domain::request::Prompt::default(),
        max_age_s: None,
        acr_values: Vec::new(),
        dpop_jkt: None,
        authority: None,
        resource: None,
    };
    let params = serde_json::to_vec(&request).unwrap();
    let at = now();
    let mut tx = TenantTx::begin(&w.db.app, w.realm.tenant, w.realm.realm)
        .await
        .unwrap();
    tx.insert_oauth_request(&access_store::oauth::NewRequest {
        day: i32::try_from(at / 86_400_000).unwrap(),
        hash: &access_crypto::oauth::opaque_digest(
            access_identity_oauth::app::oauth::REQUEST_CONTEXT,
            &handle,
        ),
        client: [2; 16],
        pushed: true,
        params: &params,
        created_ms: i64::try_from(at - 61_000).unwrap(),
        expires_ms: i64::try_from(at - 1_000).unwrap(),
    })
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let late = format!(
        "urn:ietf:params:oauth:request_uri:{}",
        b64url_encode(&handle)
    );
    let r = w
        .oauth
        .authorize(&w.realm, &use_uri(CONFIDENTIAL, &late), Some(&w.cookie))
        .await;
    assert!(matches!(r, Reply::Problem { status: 400, .. }), "{r:?}");
}

// RFC 7662, RFC 7009, MD-8, P-ID-8, PI-10: introspection answers for the caller's own live
// tokens; revocation ends the grant; with the primary out of reach every token is inactive
#[tokio::test]
async fn introspection_and_revocation() {
    // EP-3, CMP-15.1
    let w = world().await;
    let code = w.code(CONFIDENTIAL).await;
    let t = body(
        &w.token(
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            Some(&basic(CONFIDENTIAL, SECRET)),
        )
        .await,
        200,
    );
    let access = t["access_token"].as_str().unwrap();
    let refresh = t["refresh_token"].as_str().unwrap();
    let a = w.introspect(access).await;
    assert_eq!(a["active"], true);
    assert_eq!(a["token_type"], "DPoP");
    assert_eq!(a["cnf"]["jkt"], w.jkt());
    let r = w.introspect(refresh).await;
    assert_eq!(r["active"], true);
    assert_eq!(r["sub"], a["sub"]);
    assert_eq!(w.introspect("nonsense").await["active"], false);
    let public = w
        .oauth
        .introspect(
            &w.realm,
            &Params::new(vec![
                ("token".into(), access.into()),
                ("client_id".into(), PUBLIC.into()),
            ])
            .unwrap(),
            None,
        )
        .await;
    assert_eq!(error(&public), "invalid_client");

    let revoke = Params::new(vec![("token".into(), refresh.into())]).unwrap();
    let done = w
        .oauth
        .revoke(&w.realm, &revoke, Some(&basic(CONFIDENTIAL, SECRET)))
        .await;
    assert_eq!(body(&done, 200), serde_json::json!({}));
    assert_eq!(w.introspect(access).await["active"], false);
    assert_eq!(w.introspect(refresh).await["active"], false);

    let code = w.code(CONFIDENTIAL).await;
    let t = body(
        &w.token(
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            Some(&basic(CONFIDENTIAL, SECRET)),
        )
        .await,
        200,
    );
    let access = t["access_token"].as_str().unwrap().to_owned();
    w.db.app.close().await;
    assert_eq!(w.introspect(&access).await["active"], false);
    assert_eq!(
        w.refresh(t["refresh_token"].as_str().unwrap()).await,
        Reply::Unavailable
    );
}

// §10.4.6, G57, MD-7, IDP-24, RP-Initiated Logout 1.0, Back-Channel Logout 1.0: a sign-out tied
// to the session by id_token_hint ends it, revokes its grants and queues a signed logout token
// with sid and no nonce; the post-logout redirect URI must match exactly
#[tokio::test]
async fn logout_ends_the_session_and_notifies_clients() {
    let w = world().await;
    let code = w.code(PUBLIC).await;
    let t = body(&w.exchange(&code).await, 200);
    let id_token = t["id_token"].as_str().unwrap();
    let end = |pairs: Vec<(&str, &str)>, cookie: Option<String>| {
        let p = Params::new(
            pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
        .unwrap();
        let w = &w;
        async move { w.oauth.end_session(&w.realm, &p, cookie.as_deref()).await }
    };
    let bad = end(
        vec![
            ("id_token_hint", id_token),
            ("post_logout_redirect_uri", "https://shop.example/bye/"),
        ],
        Some(w.cookie.clone()),
    )
    .await;
    assert!(matches!(bad, Reply::Problem { status: 400, .. }), "{bad:?}");
    let unhinted = end(vec![], Some(w.cookie.clone())).await;
    assert_eq!(location(&unhinted), format!("{ISSUER}/sign-out"));
    let out = end(
        vec![
            ("id_token_hint", id_token),
            ("post_logout_redirect_uri", "https://shop.example/bye"),
            ("state", "s 2"),
        ],
        Some(w.cookie.clone()),
    )
    .await;
    assert_eq!(location(&out), "https://shop.example/bye?state=s+2");
    assert_eq!(
        error(&w.refresh(t["refresh_token"].as_str().unwrap()).await),
        "invalid_grant"
    );
    let to = location(&w.authorize(&[("prompt", "none")], Some(&w.cookie)).await);
    assert_eq!(query(&to, "error"), "login_required");
    let courier = w.courier(Posted::default());
    let delivered = deliver(&courier, 1).await;
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].0, "https://shop.example/backchannel");
    let lt = claims(&delivered[0].1);
    assert_eq!(lt["aud"], PUBLIC);
    assert_eq!(lt["iss"], ISSUER);
    assert_eq!(lt["sid"], claims(id_token)["sid"]);
    assert_eq!(lt["sub"], claims(id_token)["sub"]);
    assert!(lt.get("nonce").is_none());
    assert!(lt["events"]["http://schemas.openid.net/event/backchannel-logout"].is_object());
    let again = courier.step().await.unwrap();
    assert_eq!((again.delivered, again.undelivered), (0, 0));
}

/// Posts made and answers left.
type Script = (Vec<(String, String)>, Vec<Result<(), PostFailure>>);

/// A client endpoint that answers from a script, then 200.
#[derive(Clone, Default)]
struct Posted(Arc<Mutex<Script>>);

impl Posted {
    fn scripted(answers: Vec<Result<(), PostFailure>>) -> Self {
        Self(Arc::new(Mutex::new((Vec::new(), answers))))
    }

    fn sent(&self) -> Vec<(String, String)> {
        self.0.lock().unwrap().0.clone()
    }
}

impl LogoutDelivery for Posted {
    fn post(&self, uri: &str, token: &str) -> impl Future<Output = Result<(), PostFailure>> {
        let mut g = self.0.lock().unwrap();
        g.0.push((String::from(uri), String::from(token)));
        let answer = if g.1.is_empty() {
            Ok(())
        } else {
            g.1.remove(0)
        };
        std::future::ready(answer)
    }
}

type TestCourier = Courier<PgOAuth, SignerKeys, OsRandom, SysClock, PgLogoutQueue, Posted>;

impl World {
    fn courier(&self, posted: Posted) -> TestCourier {
        Courier::new(
            PgOAuth::new(self.db.app.clone()),
            SignerKeys::new(self.socket.clone()),
            OsRandom,
            SysClock,
            PgLogoutQueue {
                reader: self.db.reader.clone(),
                app: self.db.app.clone(),
            },
            posted,
            Backoff {
                base_ms: 1,
                max_ms: 2,
            },
        )
    }
}

/// Steps the courier until `n` posts were made; the outbox shows a commit once every older
/// transaction ended.
async fn deliver(courier: &TestCourier, n: usize) -> Vec<(String, String)> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        courier.step().await.unwrap();
        let sent = courier.delivery().sent();
        if sent.len() >= n {
            return sent;
        }
        assert!(std::time::Instant::now() < deadline, "no logout delivered");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// TN-50, MD-7, §10.4.6, OP-73, Back-Channel Logout 1.0 §2.8: a session_epoch step (sign out
// everywhere, disablement) revokes the grants and notifies their clients; a transient failure
// is retried, a final refusal is recorded once and passed
#[tokio::test]
async fn an_epoch_step_notifies_clients_and_records_refusals() {
    let w = world().await;
    let code = w.code(PUBLIC).await;
    body(&w.exchange(&code).await, 200);
    let mut tx = TenantTx::begin(&w.db.app, w.realm.tenant, w.realm.realm)
        .await
        .unwrap();
    tx.end_sessions(w.subject).await.unwrap();
    tx.commit().await.unwrap();
    let courier = w.courier(Posted::scripted(vec![
        Err(PostFailure::Transient {
            retry_after_ms: None,
        }),
        Err(PostFailure::Rejected { status: 400 }),
    ]));
    let sent = deliver(&courier, 1).await;
    assert_eq!(sent.len(), 1);
    let retried = courier.step().await.unwrap();
    assert_eq!((retried.delivered, retried.undelivered), (0, 1));
    let mut tx = TenantTx::begin(&w.db.app, w.realm.tenant, w.realm.realm)
        .await
        .unwrap();
    let recorded = tx.list_backchannel_undelivered(10).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        (recorded[0].reason.as_str(), recorded[0].client_status),
        ("rejected", Some(400))
    );
    let after = courier.step().await.unwrap();
    assert_eq!((after.delivered, after.undelivered), (0, 0));
    assert_eq!(courier.delivery().sent().len(), 2);
}

// G57, §10.4.6: the hosted login's sign-out ends the session in the store, which revokes its
// grants and queues their notices in the same transaction
#[tokio::test]
async fn a_session_end_notifies_clients() {
    let w = world().await;
    let code = w.code(PUBLIC).await;
    let t = body(&w.exchange(&code).await, 200);
    let mut tx = TenantTx::begin(&w.db.app, w.realm.tenant, w.realm.realm)
        .await
        .unwrap();
    let value: [u8; 32] = b64url_decode(&w.cookie).unwrap().try_into().unwrap();
    let session = tx
        .session_by_cookie(&cookie_digest(&value))
        .await
        .unwrap()
        .unwrap();
    assert!(tx.end_session(session.id, 1, "logout").await.unwrap());
    tx.commit().await.unwrap();
    assert_eq!(
        error(&w.refresh(t["refresh_token"].as_str().unwrap()).await),
        "invalid_grant"
    );
    let courier = w.courier(Posted::default());
    let sent = deliver(&courier, 1).await;
    assert_eq!(
        claims(&sent[0].1)["sid"],
        claims(t["id_token"].as_str().unwrap())["sid"]
    );
}

/// A `private_key_jwt` assertion of the platform product `client_id`; PRODUCT and THIRD publish
/// the keyed client's JWKS.
fn product_assertion(w: &World, client_id: &str, aud: &str) -> String {
    let jti = b64url_encode(&access_crypto::random::bytes::<16>().unwrap());
    sign(
        &w.client_key,
        r#"{"alg":"ES256","typ":"JWT"}"#,
        &format!(
            r#"{{"iss":"{client_id}","sub":"{client_id}","aud":"{aud}","exp":{},"iat":{},"jti":"{jti}"}}"#,
            now() / 1000 + 60,
            now() / 1000
        ),
    )
}

/// Binds the service Party a product's pairing with this realm would have bound (OP-149 m.4).
async fn pair(w: &World, client_id: &str, party: [u8; 16]) {
    let mut tx = TenantTx::begin(&w.db.app, w.realm.tenant, w.realm.realm)
        .await
        .unwrap();
    assert!(tx.bind_platform_party(client_id, &party).await.unwrap());
    tx.commit().await.unwrap();
}

/// `client_credentials` as the platform product `client_id`, with its assertion and a proof.
async fn service(w: &World, client_id: &str, pairs: &[(&str, &str)]) -> Reply {
    let a = product_assertion(w, client_id, ISSUER);
    let mut all = vec![
        ("grant_type", "client_credentials"),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", a.as_str()),
    ];
    all.extend_from_slice(pairs);
    w.token(&all, None).await
}

/// RFC 7662 as the product `client_id`.
async fn introspect_as(w: &World, client_id: &str, token: &str) -> Value {
    let a = product_assertion(w, client_id, ISSUER);
    let p = Params::new(vec![
        ("token".into(), token.into()),
        ("client_assertion_type".into(), ASSERTION_TYPE.into()),
        ("client_assertion".into(), a),
    ])
    .unwrap();
    body(&w.oauth.introspect(&w.realm, &p, None).await, 200)
}

// OP-149 m.31 (a), m.26 (a), E39, MD-7, MD-10, AG-8, TN-27, RFC 8707 §2.2, RFC 9068: a
// platform product naming another platform product as its resource gets an identity-assertion
// service token: one audience (the other product), the caller, its tenant, the pairwise value
// the audience reads of the caller's service Party, cnf-bound, at most 5 minutes, and nothing an
// authority token carries; only products call products, never themselves; the target or the
// caller introspects it; the realm's userinfo refuses it
#[tokio::test]
async fn a_platform_product_gets_a_service_token_for_another_product() {
    // OP-150 m.3 (m), IDP-11, RFC 7523, RFC 9068 §4
    let w = world().await;
    let (party_a, party_b) = ([0xa1; 16], [0xb2; 16]);

    // no Party here yet: the product has not paired with this realm
    assert_eq!(
        error(&service(&w, PRODUCT, &[("resource", THIRD)]).await),
        "unauthorized_client"
    );
    pair(&w, PRODUCT, party_a).await;
    pair(&w, THIRD, party_b).await;

    let t = body(&service(&w, PRODUCT, &[("resource", THIRD)]).await, 200);
    assert_eq!(t["token_type"], "DPoP");
    assert_eq!(t["expires_in"], 300);
    for absent in [
        "refresh_token",
        "scope",
        "authorization_details",
        "id_token",
    ] {
        assert!(t.get(absent).is_none(), "{absent}");
    }
    let token = t["access_token"].as_str().unwrap();
    let header: Value =
        serde_json::from_slice(&b64url_decode(token.split('.').next().unwrap()).unwrap()).unwrap();
    assert_eq!(header["typ"], "at+jwt");
    // the realm's own key signed it
    let jwks = w.oauth.env().signer.jwks(w.realm.realm).await.unwrap();
    let keys = access_identity_oauth::domain::jwt::realm_key_set(jwks.as_bytes()).unwrap();
    access_kernel::verify::jws::verify_compact(
        &access_crypto::AwsLcBackend,
        token,
        &keys,
        "at+jwt",
        access_kernel::verify::jws::Origin::Native,
    )
    .unwrap();
    let c = claims(token);
    let tenant = tenant_id(&w);
    assert_eq!(c["iss"], ISSUER);
    assert_eq!(c["aud"], THIRD);
    assert_eq!(c["client_id"], PRODUCT);
    assert_eq!(c["access_tenant"], tenant);
    assert_eq!(c["cnf"]["jkt"], w.jkt());
    assert!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap() <= 300);
    assert!(c["jti"].as_str().unwrap().len() >= 16);
    let sub = c["sub"].as_str().unwrap().to_owned();
    assert_eq!(sub.len(), 43);
    for absent in [
        "scope",
        "sid",
        "rev",
        "auth_time",
        "acr",
        "authorization_details",
        "access_contract",
        "family",
        "status",
    ] {
        assert!(c.get(absent).is_none(), "{absent}");
    }

    // MD-10: the sub is stable for this pair, resolves back to the caller's Party for the
    // target's sector (OP-149 m.19 (g)), and is not what the caller reads of the target
    let again = body(&service(&w, PRODUCT, &[("resource", THIRD)]).await, 200);
    assert_eq!(claims(again["access_token"].as_str().unwrap())["sub"], sub);
    let mut tx = TenantTx::begin(&w.db.app, w.realm.tenant, w.realm.realm)
        .await
        .unwrap();
    assert_eq!(
        tx.platform_party_by_pairwise([6; 16], &sub).await.unwrap(),
        Some(party_a)
    );
    assert_eq!(
        tx.platform_party_by_pairwise([5; 16], &sub).await.unwrap(),
        None
    );
    tx.commit().await.unwrap();
    let back = body(&service(&w, THIRD, &[("resource", PRODUCT)]).await, 200);
    let back = claims(back["access_token"].as_str().unwrap());
    assert_eq!(back["aud"], PRODUCT);
    assert_eq!(back["client_id"], THIRD);
    assert_ne!(back["sub"], sub);

    // RFC 8707 §2, AG-8: never itself, never a non-product client, never an unknown value
    for (caller, resource) in [
        (PRODUCT, PRODUCT),
        (PRODUCT, KEYED),
        (PRODUCT, CONFIDENTIAL),
        (PRODUCT, "cli_0000000000000000000000000z"),
        (PRODUCT, "https://api.example"),
    ] {
        assert_eq!(
            error(&service(&w, caller, &[("resource", resource)]).await),
            "invalid_target",
            "{caller} -> {resource}"
        );
    }
    // the realm itself and no resource stay the projection path's refusals
    for pairs in [vec![("resource", ISSUER)], vec![]] {
        assert_eq!(
            error(&service(&w, PRODUCT, &pairs).await),
            "invalid_target",
            "{pairs:?}"
        );
    }
    // TN-27: no proof, no token
    let a = product_assertion(&w, PRODUCT, ISSUER);
    let p = Params::new(vec![
        ("grant_type".into(), "client_credentials".into()),
        ("client_assertion_type".into(), ASSERTION_TYPE.into()),
        ("client_assertion".into(), a),
        ("resource".into(), THIRD.into()),
    ])
    .unwrap();
    assert_eq!(
        error(
            &w.oauth
                .token(
                    &w.realm,
                    &p,
                    TokenHttp {
                        authorization: None,
                        dpop: &[],
                    },
                )
                .await
        ),
        "invalid_dpop_proof"
    );

    // RFC 7662, MD-8: the target reads it, so does the caller; another client learns nothing
    for asking in [THIRD, PRODUCT] {
        let i = introspect_as(&w, asking, token).await;
        assert_eq!(i["active"], true, "{asking}");
        assert_eq!(i["aud"], THIRD);
        assert_eq!(i["client_id"], PRODUCT);
        assert_eq!(i["access_tenant"], tenant);
        assert_eq!(i["sub"], sub);
        assert_eq!(i["cnf"]["jkt"], w.jkt());
        assert_eq!(i["token_type"], "DPoP");
        assert_eq!((&i["exp"], &i["iat"]), (&c["exp"], &c["iat"]));
        assert!(i.get("authorization_details").is_none());
        assert!(i.get("scope").is_none());
    }
    assert_eq!(w.introspect(token).await["active"], false);
    // RFC 9068 §4, AG-8: the realm is not this token's audience
    assert!(matches!(
        w.userinfo(token).await,
        Reply::Json { status: 401, .. }
    ));
    // RFC 7009 §2.2: there is no grant to revoke; the answer is 200 without effect
    let p = Params::new(vec![("token".into(), token.into())]).unwrap();
    assert!(matches!(
        w.oauth
            .revoke(&w.realm, &p, Some(&basic(CONFIDENTIAL, SECRET)))
            .await,
        Reply::Json { status: 200, .. }
    ));
    assert_eq!(introspect_as(&w, THIRD, token).await["active"], true);
}

// OP-149 m.34 (b), m.31 (a), MD-10, AG-8, TN-27, RFC 8707 §2.2, RFC 9068: a confidential
// client of a tenant realm naming a registered platform product as its resource gets the same
// identity-assertion service token: aud the product, client_id the caller, access_tenant the
// caller's tenant, sub the pairwise pseudonym of the client itself (it has no service Party),
// cnf-bound, at most 5 minutes, nothing an authority token carries; private_key_jwt and
// client_secret_basic alike; a public client gets none, a non-product is no resource; the
// product or the caller introspects it; the realm's userinfo refuses it
#[tokio::test]
async fn a_tenant_api_client_gets_a_service_token_for_a_product() {
    // RFC 6749 §4.4, RFC 7523, RFC 7662, OP-150 m.9
    let w = world().await;
    let tenant = tenant_id(&w);

    let t = body(&service(&w, KEYED, &[("resource", THIRD)]).await, 200);
    assert_eq!(t["token_type"], "DPoP");
    assert_eq!(t["expires_in"], 300);
    for absent in [
        "refresh_token",
        "scope",
        "authorization_details",
        "id_token",
    ] {
        assert!(t.get(absent).is_none(), "{absent}");
    }
    let token = t["access_token"].as_str().unwrap();
    let header: Value =
        serde_json::from_slice(&b64url_decode(token.split('.').next().unwrap()).unwrap()).unwrap();
    assert_eq!(header["typ"], "at+jwt");
    let c = claims(token);
    assert_eq!(c["iss"], ISSUER);
    assert_eq!(c["aud"], THIRD);
    assert_eq!(c["client_id"], KEYED);
    assert_eq!(c["access_tenant"], tenant);
    assert_eq!(c["cnf"]["jkt"], w.jkt());
    assert!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap() <= 300);
    assert!(c["jti"].as_str().unwrap().len() >= 16);
    let sub = c["sub"].as_str().unwrap().to_owned();
    assert_eq!(sub.len(), 43);
    for absent in [
        "scope",
        "sid",
        "rev",
        "auth_time",
        "acr",
        "authorization_details",
        "access_contract",
        "family",
        "status",
    ] {
        assert!(c.get(absent).is_none(), "{absent}");
    }

    // MD-10: the sub is stable for this pair, resolves back to the client for the product's
    // sector only (OP-149 m.19 (g)), and another product reads another pseudonym
    let again = body(&service(&w, KEYED, &[("resource", THIRD)]).await, 200);
    assert_eq!(claims(again["access_token"].as_str().unwrap())["sub"], sub);
    let mut tx = TenantTx::begin(&w.db.app, w.realm.tenant, w.realm.realm)
        .await
        .unwrap();
    assert_eq!(
        tx.client_by_pairwise([6; 16], &sub).await.unwrap(),
        Some([3; 16])
    );
    assert_eq!(tx.client_by_pairwise([5; 16], &sub).await.unwrap(), None);
    assert_eq!(
        tx.platform_party_by_pairwise([6; 16], &sub).await.unwrap(),
        None
    );
    tx.commit().await.unwrap();
    let other = body(&service(&w, KEYED, &[("resource", PRODUCT)]).await, 200);
    let other = claims(other["access_token"].as_str().unwrap());
    assert_eq!(other["aud"], PRODUCT);
    assert_ne!(other["sub"], sub);

    // client_secret_basic is as good as private_key_jwt; another client, another pseudonym
    let b = body(
        &w.token(
            &[("grant_type", "client_credentials"), ("resource", THIRD)],
            Some(&basic(CONFIDENTIAL, SECRET)),
        )
        .await,
        200,
    );
    let b = claims(b["access_token"].as_str().unwrap());
    assert_eq!(b["aud"], THIRD);
    assert_eq!(b["client_id"], CONFIDENTIAL);
    assert_eq!(b["access_tenant"], tenant);
    assert_ne!(b["sub"], sub);

    // RFC 6749 §4.4: no public client; RFC 8707 §2: only a product is a resource
    assert_eq!(
        error(
            &w.token(
                &[
                    ("grant_type", "client_credentials"),
                    ("client_id", PUBLIC),
                    ("resource", THIRD),
                ],
                None,
            )
            .await
        ),
        "unauthorized_client"
    );
    for resource in [CONFIDENTIAL, KEYED, "cli_0000000000000000000000000z"] {
        assert_eq!(
            error(&service(&w, KEYED, &[("resource", resource)]).await),
            "invalid_target",
            "{resource}"
        );
    }

    // RFC 7662, MD-8: the product reads it, so does the caller; another client learns nothing
    for asking in [THIRD, KEYED] {
        let i = introspect_as(&w, asking, token).await;
        assert_eq!(i["active"], true, "{asking}");
        assert_eq!(i["aud"], THIRD);
        assert_eq!(i["client_id"], KEYED);
        assert_eq!(i["access_tenant"], tenant);
        assert_eq!(i["sub"], sub);
        assert_eq!(i["cnf"]["jkt"], w.jkt());
        assert!(i.get("scope").is_none());
    }
    assert_eq!(introspect_as(&w, PRODUCT, token).await["active"], false);
    assert_eq!(w.introspect(token).await["active"], false);
    // RFC 9068 §4, AG-8: the realm is not this token's audience
    assert!(matches!(
        w.userinfo(token).await,
        Reply::Json { status: 401, .. }
    ));
}
