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
use access_store::identity::{Cursor, RealmId, TenantId, TenantTx, poll};
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
    fn nonces(&self, _realm: RealmId, role: Role) -> Option<Arc<NonceRing>> {
        Some(match role {
            Role::AuthorizationServer => self.as_ring.clone(),
            Role::ResourceServer => self.rs_ring.clone(),
        })
    }
    fn dpop(&self) -> &DpopProfile {
        &self.profile
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
    let d = domain(&db, t, 3).await;
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
        insert_client(&mut tx, &b, &client(n, id, method))
            .await
            .unwrap();
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
        db: PgOAuth::new(db.app.clone()),
        signer: SignerKeys::new(socket),
        keys: keys.clone(),
        directory: PgDirectory::new(db.router.clone()),
        pool: db.app.clone(),
        as_ring: ring(Role::AuthorizationServer, 1),
        rs_ring: ring(Role::ResourceServer, 2),
        profile: DpopProfile::default(),
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
            &self.dpop_key,
            &format!(
                r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{}}}"#,
                ec_jwk(&self.dpop_key)
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
    // RFC 6749 §5.2, OP-146 m.6: no ROPC, no implicit; client credentials and device code later
    for grant in [
        "password",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
        "implicit",
    ] {
        let p = [("grant_type", grant), ("client_id", PUBLIC)];
        assert_eq!(error(&w.token(&p, None).await), "unsupported_grant_type");
    }
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
            .par(&w.realm, &p, Some(&basic(CONFIDENTIAL, SECRET)))
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
                .par(&w.realm, &p, Some(&basic(CONFIDENTIAL, "x")))
                .await
        ),
        "invalid_client"
    );
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
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let logout: Vec<Value> = loop {
        let found: Vec<Value> = poll(&w.db.reader, Cursor::default(), 100)
            .await
            .unwrap()
            .iter()
            .filter(|e| e.kind == "oauth.backchannel_logout")
            .map(|e| serde_json::from_slice(&e.payload).unwrap())
            .collect();
        if !found.is_empty() {
            break found;
        }
        assert!(std::time::Instant::now() < deadline, "no logout event");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(logout.len(), 1);
    assert_eq!(logout[0]["uri"], "https://shop.example/backchannel");
    let lt = claims(logout[0]["logout_token"].as_str().unwrap());
    assert_eq!(lt["aud"], PUBLIC);
    assert_eq!(lt["sid"], claims(id_token)["sid"]);
    assert!(lt.get("nonce").is_none());
    assert!(lt["events"]["http://schemas.openid.net/event/backchannel-logout"].is_object());
}
