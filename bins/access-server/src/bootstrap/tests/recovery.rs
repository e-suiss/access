//! Account recovery end to end against the real router, PostgreSQL and the realm's keys in the
//! token (OP-153 m.3 (d), (e), (gg)): the neutral start, the proofs and their throttle, the
//! objection window and its notices, the credential-only rebind consumed once, the grace period,
//! the owner's own sign-in cancelling a recovery, and the configuration-time refusal of a
//! recovery weaker than the account.

#![allow(
    clippy::many_single_char_names,
    clippy::too_many_lines,
    reason = "test code; short names for the console, transaction and vault"
)]

use std::sync::Mutex as StdMutex;

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::SystemEntropy;
use access_identity_account::app::accounts::{
    PasswordServices, change_status, create, set_password,
};
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::notify::NotifyError;
use access_identity_account::notify::envelope::EventId;
use access_identity_account::notify::message::{Address, Body as MessageBody, Message, Notice};
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_account::notify::ports::Notifier;
use access_identity_account::ports::{AccountTx, BreachRanges, RangeUnavailable};
use access_identity_risk::domain::assess::Breach;
use access_identity_risk::ports::{BoxFuture, BreachProbe};
use access_identity_ui::ports::Messages;
use access_kernel::json::b64url_encode;
use access_store::identity::TenantTx;
use axum::body::Body;
use axum::http::{Method, StatusCode, header};

use super::management::{Console, console, now, send};
use super::*;

const WHO: Actor<'static> = Actor {
    actor: "test",
    correlation: "test",
};

const PW: &str = "correct horse battery staple";

/// One message the realm would hand Relay.
#[derive(Clone, Debug)]
pub(super) struct Sent {
    pub(super) to: String,
    pub(super) kind: &'static str,
    pub(super) secret: Option<String>,
    pub(super) until_ms: Option<u64>,
}

/// The Relay seam: the production outbox, and a log of what it was given.
#[derive(Clone, Default)]
pub(super) struct Recording(pub(super) Arc<StdMutex<Vec<Sent>>>);

pub(super) struct RecordingNotifier<'a> {
    inner: OutboxNotifier<'a>,
    log: &'a StdMutex<Vec<Sent>>,
}

impl Notifier for RecordingNotifier<'_> {
    async fn notify(&self, tx: &mut TenantTx, m: &Message) -> Result<EventId, NotifyError> {
        let to = match &m.to {
            Address::Email(v) | Address::Phone(v) => v.clone(),
        };
        let (secret, until_ms) = match &m.body {
            MessageBody::Otp { code, .. } => (Some(code.expose().clone()), None),
            MessageBody::Link { link, .. } => (Some(link.expose().clone()), None),
            MessageBody::Notice { until_ms, .. } => (None, *until_ms),
            _ => (None, None),
        };
        self.log.lock().unwrap().push(Sent {
            to,
            kind: m.body.kind(),
            secret,
            until_ms,
        });
        self.inner.notify(tx, m).await
    }
}

impl Messages for Recording {
    type For<'a> = RecordingNotifier<'a>;

    fn notifier<'a>(&'a self, realm: &'a Realm<'a>) -> RecordingNotifier<'a> {
        RecordingNotifier {
            inner: OutboxNotifier::new(
                realm,
                &SystemEntropy,
                &access_identity_account::adapters::system::SystemClock,
            ),
            log: &self.0,
        }
    }
}

impl Recording {
    pub(super) fn sent(&self) -> Vec<Sent> {
        self.0.lock().unwrap().clone()
    }

    pub(super) fn last_code_to(&self, to: &str) -> String {
        self.sent()
            .iter()
            .rev()
            .find(|s| s.to == to && s.kind == "relay.message.otp.v1")
            .and_then(|s| s.secret.clone())
            .unwrap()
    }
}

/// The breach corpus lists nothing (the check itself runs; an outage would refuse, G50).
struct Clean;

impl BreachProbe for Clean {
    fn check<'a>(
        &'a self,
        _: &'a access_identity_account::domain::password::Password,
    ) -> BoxFuture<'a, Breach> {
        Box::pin(async { Breach::Clean })
    }
}

struct Corpus;

impl BreachRanges for Corpus {
    fn range(&self, _: &str) -> impl Future<Output = Result<String, RangeUnavailable>> + Send {
        std::future::ready(Ok(String::new()))
    }
}

fn hasher() -> access_identity_account::app::hasher::Hasher {
    use access_identity_account::adapters::system::{cgroup_memory_budget, cores};
    use access_identity_account::app::hasher::{Hasher, HasherConfig};
    use access_identity_account::domain::password::Argon2Params;
    Hasher::new(HasherConfig::sized(
        Argon2Params::CANONICAL,
        cores(),
        cgroup_memory_budget(),
    ))
}

/// The realm's hosted surface as `main` mounts it, over the token's realm keys, with the
/// recording Relay seam.
pub(super) fn hosted(c: &Console, messages: Recording) -> axum::Router {
    routes(c, messages, false)
}

/// [`hosted`] with the Frontend API's device Instance routes over the authority plane and the
/// realm issuer's courier (OP-149 m.6, OP-153 m.3 (c)).
pub(super) fn hosted_with_devices(c: &Console, messages: Recording) -> axum::Router {
    routes(c, messages, true)
}

fn routes(c: &Console, messages: Recording, devices: bool) -> axum::Router {
    use access_identity_account::adapters::system::SystemClock;
    use access_identity_account::app::local::LocalLimiter;
    use access_identity_account::app::login::LoginGate;
    use access_identity_account::domain::throttle::ThrottlePolicy;
    use access_identity_oauth::adapters::PgDirectory;
    use access_identity_oauth::app::Discovery as RealmDiscovery;
    use access_identity_session::domain::session::SessionPolicy;
    use access_identity_ui::app::Hosted;
    let w = &c.w;
    let mut risk = access_identity_session::app::RiskServices::without_sources();
    risk.breach = Arc::new(Clean);
    let hosted = Arc::new(Hosted {
        kits: crate::login::HsmKits::new(
            crate::login::RealmKeks::new(Arc::clone(&w.keys)),
            w.db.router.clone(),
            w.db.app.clone(),
            SessionPolicy::DEFAULT,
        ),
        db: w.db.app.clone(),
        products: w.db.reader.clone(),
        clock: SystemClock,
        messages,
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        hasher: hasher(),
        redirect_to: String::from("/"),
        hooks: Arc::new(access_identity_hooks::ports::NoHooks),
        risk,
        signup: access_identity_ui::app::signup::Signup::without_providers().unwrap(),
    });
    let discovery = || {
        RealmDiscovery::new(
            PgDirectory::new(w.db.router.clone()),
            SignerKeys::new(w.identity_signer.clone()),
        )
    };
    let login = access_http::login::router(discovery(), hosted.clone(), None);
    if !devices {
        return login;
    }
    login.merge(access_http::login::me_router(
        discovery(),
        hosted,
        access_identity_ui::app::Devices {
            signer: SignerKeys::new(w.identity_signer.clone()),
            instances: w.plane.clone(),
            approvals: w.plane.clone(),
            claims: Arc::new(courier(c)),
            pep: String::from(access_identity_ui::domain::frontend::IDENTITY_PEP),
        },
    ))
}

/// The realm issuer's courier of this process over the token's issuer keys (OP-150 L2).
pub(super) fn courier(c: &Console) -> crate::claims::ClaimsCourier<TestDomains> {
    let w = &c.w;
    access_identity_account::app::claims::Courier {
        app: w.db.app.clone(),
        reader: w.db.reader.clone(),
        signer: SignerKeys::new(w.identity_signer.clone()),
        ingest: access_authority_ingest::app::Ingest::new(
            w.domains.clone(),
            crate::ingest::PgSubmissions(w.db.app.clone()),
            crate::ingest::Trusted(tokio::sync::Mutex::new(
                access_authority_sequencer::adapters::SourcesClock::new(w.db.app.clone()),
            )),
        ),
        clock: access_identity_account::adapters::system::SystemClock,
    }
}

/// A browser on the realm's host: its cookie jar.
#[derive(Default)]
pub(super) struct Page {
    pub(super) jar: BTreeMap<String, String>,
}

pub(super) struct Got {
    pub(super) status: StatusCode,
    pub(super) retry_after: Option<u64>,
    pub(super) json: serde_json::Value,
}

impl Page {
    pub(super) async fn call(
        &mut self,
        app: &axum::Router,
        method: &Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Got {
        let mut b = axum::http::Request::builder()
            .method(method.clone())
            .uri(format!("/realms/acme{path}"))
            .header(header::HOST, "access.test");
        if !self.jar.is_empty() {
            let cookie = self
                .jar
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            b = b.header(header::COOKIE, cookie);
        }
        if *method != Method::GET {
            b = b
                .header(header::ORIGIN, "https://access.test")
                .header("sec-fetch-site", "same-origin")
                .header(
                    "idempotency-key",
                    b64url_encode(&access_crypto::random::bytes::<16>().unwrap()),
                )
                .header(header::CONTENT_TYPE, "application/json");
        }
        let body = body.map_or_else(Body::empty, |v| Body::from(v.to_string()));
        let (r, bytes) = send(app, b.body(body).unwrap()).await;
        for c in r.headers().get_all(header::SET_COOKIE) {
            let c = c.to_str().unwrap();
            let (name, value) = c.split(';').next().unwrap().split_once('=').unwrap();
            if c.contains("Max-Age=0") {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        Got {
            status: r.status(),
            retry_after: r
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok()),
            json: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        }
    }
}

pub(super) fn vault_of(c: &Console) -> access_identity_account::app::vault::Vault {
    crate::login::RealmKeks::new(c.w.keys.clone())
        .vault(c.route.realm)
        .unwrap()
}

/// An active account with `email` and, when `password`, the test password.
pub(super) async fn account(c: &Console, email: &str, password: bool) -> [u8; 16] {
    let ids = crate::ids::CellIds::new(c.w.keys.clone()).key().unwrap();
    let v = vault_of(c);
    let realm = Realm {
        tenant: c.route.tenant,
        realm: c.route.realm,
        kek: &*v.kek,
        ids: &ids,
    };
    let db = PgAccounts::sealed(c.w.db.app.clone(), v.clone());
    let id = Identifier::new(IdentifierKind::Email, email).unwrap();
    let subject = create(&db, &realm, &[id], &WHO).await.unwrap();
    for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
        change_status(&db, &realm, subject, to, &WHO).await.unwrap();
    }
    if password {
        let h = hasher();
        set_password(
            &db,
            &realm,
            &PasswordServices {
                hasher: &h,
                ranges: &Corpus,
                entropy: &SystemEntropy,
            },
            subject,
            PW,
            &WHO,
        )
        .await
        .unwrap();
    }
    subject
}

/// A live session of `subject`, as a sign-in leaves it; its cookie value.
pub(super) async fn session(c: &Console, subject: [u8; 16]) -> String {
    let value: [u8; 32] = access_crypto::random::bytes().unwrap();
    let at = now();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let epoch = t
        .subject(subject, false)
        .await
        .unwrap()
        .unwrap()
        .session_epoch;
    t.insert_session(&access_store::sessions::NewSession {
        cookie_hash: &access_identity_session::domain::session::cookie_digest(&value),
        subject,
        session_epoch: epoch,
        keep_signed_in: false,
        created_ms: i64::try_from(at).unwrap(),
        auth_time_ms: i64::try_from(at).unwrap(),
        idle_ms: 3_600_000,
        expires_ms: i64::try_from(at + 3_600_000).unwrap(),
        assurance: &serde_json::to_vec(&access_identity_session::domain::assurance::vector(&[
            access_identity_session::domain::assurance::Factor::password(at),
        ]))
        .unwrap(),
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    b64url_encode(&value)
}

fn signed_in(cookie: &str) -> Page {
    let mut p = Page::default();
    p.jar
        .insert(String::from("__Host-access-session"), cookie.to_owned());
    p
}

fn attempt_id(v: &serde_json::Value) -> [u8; 16] {
    <[u8; 16]>::try_from(
        access_kernel::json::b64url_decode(v["attempt"].as_str().unwrap()).unwrap(),
    )
    .unwrap()
}

async fn states(c: &Console, attempt: [u8; 16]) -> Vec<String> {
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let ts = t.recovery_transitions(attempt).await.unwrap();
    t.commit().await.unwrap();
    ts.into_iter().map(|t| t.state).collect()
}

// TN-54, TN-55, TN-57, TN-59, TN-64, U67, X38, SEC18, CR-40, OP-153 m.3 (d), (e), (gg)
// TN-54, Ek B 3421, 3526, 3540, 3542, 3545, 3546, 3556, 3557, 3656, 3664, 3846, 4016
#[tokio::test]
async fn a_recovery_runs_from_the_neutral_start_to_the_grace_period() {
    let c = console("recovery-flow", false).await;
    let sent = Recording::default();
    let app = hosted(&c, sent.clone());
    let rae = account(&c, "rae@example.com", true).await;
    let old = session(&c, rae).await;
    let mut me = signed_in(&old);

    // TN-57
    let setup = me
        .call(
            &app,
            &Method::PUT,
            "/v1/account/recovery-contacts",
            Some(serde_json::json!({"recovery_email": "rae.backup@example.net"})),
        )
        .await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.json);
    assert_eq!(setup.json["recovery_email"], "rae.backup@example.net");
    assert_eq!(setup.json["notice_addresses"], 1);
    assert_eq!(setup.json["weakest_aal"], "aal1");

    // CR-40
    let mut stranger = Page::default();
    let none = stranger
        .call(
            &app,
            &Method::POST,
            "/v1/recovery",
            Some(serde_json::json!({"identifier": "nobody@example.com", "method": "sent_code"})),
        )
        .await;
    let mut thief = Page::default();
    let started = thief
        .call(
            &app,
            &Method::POST,
            "/v1/recovery",
            Some(serde_json::json!({"identifier": "rae@example.com", "method": "sent_code"})),
        )
        .await;
    assert_eq!(started.status, StatusCode::CREATED, "{}", started.json);
    assert_eq!(none.status, started.status);
    let keys = |v: &serde_json::Value| {
        v.as_object()
            .unwrap()
            .iter()
            .filter(|(k, _)| *k != "attempt")
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
    };
    assert_eq!(keys(&none.json), keys(&started.json));
    let attempt = started.json["attempt"].as_str().unwrap().to_owned();
    let id = attempt_id(&started.json);

    // TN-57
    let code = sent.last_code_to("rae.backup@example.net");
    assert_eq!(code.len(), 8);
    let log = sent.sent();
    let requested: Vec<_> = log
        .iter()
        .filter(|s| s.kind == Notice::RecoveryRequested.kind())
        .collect();
    assert_eq!(requested.len(), 1);
    assert_eq!(requested[0].to, "rae@example.com");
    assert!(
        log.iter()
            .all(|s| s.to != "rae.backup@example.net"
                || !s.kind.starts_with("relay.message.recovery")),
        "no notice goes to the recovery channel"
    );
    assert!(log.iter().all(|s| s.to != "nobody@example.com"));

    // TN-59, OP-153 m.3 (d)
    let path = format!("/v1/recovery/{attempt}");
    let wrong = thief
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"code": "00000000"})),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let again = thief
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"code": code})),
        )
        .await;
    assert_eq!(again.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(again.retry_after.unwrap() >= 1);
    access_store::testing::age_recovery(&c.w.db, id)
        .await
        .unwrap();
    let met = thief
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"code": code})),
        )
        .await;
    assert_eq!(met.status, StatusCode::OK, "{}", met.json);
    assert_eq!(met.json["state"], "cooling_down");
    assert_eq!(met.json["text"], "recovery.cooling");
    // OP-153 m.3 (e)
    let cooling: Vec<_> = sent
        .sent()
        .into_iter()
        .filter(|s| s.kind == Notice::RecoveryCooling.kind())
        .collect();
    assert_eq!(cooling.len(), 1);
    assert_eq!(cooling[0].to, "rae@example.com");
    let until = cooling[0].until_ms.unwrap();
    assert!(until >= now() + 86_400_000 - 60_000);

    // TN-55
    let early = thief
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"resume": true})),
        )
        .await;
    assert_eq!(early.status, StatusCode::CONFLICT);
    assert!(early.retry_after.unwrap() > 86_000);
    let replay = thief
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"code": code})),
        )
        .await;
    assert_eq!(
        replay.status,
        StatusCode::CONFLICT,
        "spent evidence opens nothing"
    );

    access_store::testing::age_recovery(&c.w.db, id)
        .await
        .unwrap();
    let open = thief
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"resume": true})),
        )
        .await;
    assert_eq!(open.status, StatusCode::OK, "{}", open.json);
    assert_eq!(open.json["state"], "rebind_open");
    let rebind = thief.jar.get("__Host-access-rebind").cloned().unwrap();

    // TN-53 rule 2
    let mut other = Page::default();
    other.jar.insert(
        String::from("__Host-access-recovery"),
        thief.jar["__Host-access-recovery"].clone(),
    );
    let no_token = other
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"new_password": "a new long passphrase"})),
        )
        .await;
    assert_eq!(no_token.status, StatusCode::CONFLICT);

    // Ek B 4016, TN-54
    let mut twin = Page {
        jar: thief.jar.clone(),
    };
    let body = serde_json::json!({"new_password": "a new long passphrase"});
    let (one, two) = tokio::join!(
        thief.call(&app, &Method::POST, &path, Some(body.clone())),
        twin.call(&app, &Method::POST, &path, Some(body.clone())),
    );
    let wins = [&one, &two]
        .iter()
        .filter(|g| g.status == StatusCode::OK)
        .count();
    assert_eq!(wins, 1, "{} {}", one.json, two.json);
    let (won, page) = if one.status == StatusCode::OK {
        (&one, &mut thief)
    } else {
        (&two, &mut twin)
    };
    assert!(rebind.len() > 20);
    // X38, TN-55, Ek B 3656
    assert_eq!(won.json["state"], "grace_period");
    assert_eq!(won.json["text"], "recovery.complete");
    let after = won.json["sensitive_actions_after"].as_str().unwrap();
    assert_ne!(after, "");
    assert!(page.jar.contains_key("__Host-access-session"));
    assert!(!page.jar.contains_key("__Host-access-rebind"));

    // TN-64
    let stale = me
        .call(&app, &Method::GET, "/v1/account/recovery-contacts", None)
        .await;
    assert_eq!(stale.status, StatusCode::UNAUTHORIZED);

    // TN-56
    for (method, route, body) in [
        (Method::POST, "/v1/account/recovery-codes", None),
        (
            Method::PUT,
            "/v1/account/recovery-contacts",
            Some(serde_json::json!({"recovery_email": "elsewhere@example.net"})),
        ),
        (
            Method::POST,
            "/v1/account/link-codes",
            Some(serde_json::json!({})),
        ),
        (
            Method::POST,
            "/v1/account/totp",
            Some(serde_json::json!({})),
        ),
    ] {
        let g = page.call(&app, &method, route, body).await;
        assert_eq!(g.status, StatusCode::FORBIDDEN, "{route}: {}", g.json);
        assert_eq!(g.json["code"], "recovery-grace");
        assert!(g.retry_after.unwrap() > 86_000, "{route}");
    }
    let log = sent.sent();
    assert!(
        log.iter()
            .any(|s| s.kind == Notice::RecoveryCompleted.kind() && s.to == "rae@example.com")
    );

    // TN-54, Ek B 3846
    assert_eq!(
        states(&c, id).await,
        [
            "requested",
            "throttled",
            "evidence_met",
            "cooling_down",
            "rebind_open",
            "grace_period"
        ]
    );
    let rewrite = access_store::testing::rewrite_recovery_steps(&c.w.db).await;
    assert!(rewrite.is_err(), "a step is never rewritten");
}

// TN-54, U67, OP-153 m.3 (e), Ek B 3543, 3421
#[tokio::test]
async fn the_owners_own_sign_in_denies_a_running_recovery() {
    let c = console("recovery-denied", false).await;
    let sent = Recording::default();
    let app = hosted(&c, sent.clone());
    let sam = account(&c, "sam@example.com", true).await;
    let mut me = signed_in(&session(&c, sam).await);
    let setup = me
        .call(
            &app,
            &Method::PUT,
            "/v1/account/recovery-contacts",
            Some(serde_json::json!({"recovery_email": "sam.alt@example.net"})),
        )
        .await;
    assert_eq!(setup.status, StatusCode::OK);
    let mut thief = Page::default();
    let started = thief
        .call(
            &app,
            &Method::POST,
            "/v1/recovery",
            Some(serde_json::json!({"identifier": "sam@example.com", "method": "sent_code"})),
        )
        .await;
    let attempt = started.json["attempt"].as_str().unwrap().to_owned();
    let path = format!("/v1/recovery/{attempt}");
    let code = sent.last_code_to("sam.alt@example.net");
    let met = thief
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"code": code})),
        )
        .await;
    assert_eq!(met.json["state"], "cooling_down");

    let mut owner = Page::default();
    let flow = owner
        .call(&app, &Method::POST, "/v1/login/flows", None)
        .await;
    assert_eq!(flow.status, StatusCode::CREATED);
    let action = |g: &Got| {
        let a = g.json["action"].as_str().unwrap();
        a.strip_prefix("/realms/acme").unwrap_or(a).to_owned()
    };
    let id = owner
        .call(
            &app,
            &Method::POST,
            &action(&flow),
            Some(serde_json::json!({"method": "identifier", "fields": {"identifier": "sam@example.com"}})),
        )
        .await;
    let done = owner
        .call(
            &app,
            &Method::POST,
            &action(&id),
            Some(serde_json::json!({"method": "password", "fields": {"password": PW}})),
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.json);
    assert!(owner.jar.contains_key("__Host-access-session"));

    let read = thief.call(&app, &Method::GET, &path, None).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.json["state"], "denied");
    assert_eq!(read.json["text"], "recovery.denied");
    let resume = thief
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"resume": true})),
        )
        .await;
    assert_eq!(resume.status, StatusCode::GONE);
    // TN-54
    let still = me
        .call(&app, &Method::GET, "/v1/account/recovery-contacts", None)
        .await;
    assert_eq!(still.status, StatusCode::OK);
}

// TN-52, TN-53, INV-40 (i), TNI-4, Ek B 3527, 4042
#[tokio::test]
async fn an_aal2_account_cannot_rest_its_recovery_on_one_email() {
    let c = console("recovery-weak", false).await;
    let sent = Recording::default();
    let app = hosted(&c, sent);
    let ana = account(&c, "ana@example.com", false).await;
    let mut t = access_identity_account::adapters::pg::PgTx::new(
        TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
            .await
            .unwrap(),
    );
    t.insert_credential(&access_store::accounts::NewCredential {
        subject: ana,
        kind: "totp",
        algorithm: "hmac-sha1",
        sealed: &access_store::accounts::SealedSecret {
            kek_id: String::from("unused"),
            wrapped_dek: vec![0; 40],
            nonce: [0; 12],
            ciphertext: vec![0; 32],
            pepper_version: None,
        },
    })
    .await
    .unwrap();
    AccountTx::commit(t).await.unwrap();
    let mut me = signed_in(&session(&c, ana).await);
    let weak = me
        .call(
            &app,
            &Method::PUT,
            "/v1/account/recovery-contacts",
            Some(serde_json::json!({"recovery_email": "ana.alt@example.net"})),
        )
        .await;
    assert_eq!(weak.status, StatusCode::CONFLICT, "{}", weak.json);
    assert_eq!(weak.json["code"], "recovery-too-weak");
    let read = me
        .call(&app, &Method::GET, "/v1/account/recovery-contacts", None)
        .await;
    assert_eq!(read.json["account_aal"], "aal2");
    assert_eq!(read.json["recovery_email"], serde_json::Value::Null);
    let enough = me
        .call(
            &app,
            &Method::PUT,
            "/v1/account/recovery-contacts",
            Some(serde_json::json!({
                "recovery_email": "ana.alt@example.net",
                "contacts": ["friend@example.org"],
            })),
        )
        .await;
    assert_eq!(enough.status, StatusCode::OK, "{}", enough.json);
    assert_eq!(enough.json["contacts"][0], "friend@example.org");
}

/// Drafts `operation` on `key` through the console BFF and commits it at `path` with the
/// browser's AIS: the management API's single write path (TN-110).
async fn admin_write(
    c: &Console,
    operation: &str,
    key: Option<&str>,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    use access_authority_core::genesis::IDP_ANCHOR;
    use access_http::console::domain::read_intent;
    use access_kernel::combinator::Mode;
    use access_kernel::meta::{ExerciseBasis, kind};
    let domain = c.domain;
    let basis = ExerciseBasis::Anchor(access_kernel::meta::object_id(
        &domain,
        kind::ANCHOR,
        IDP_ANCHOR,
    ));
    let mut ask = serde_json::json!({"operation": operation, "body": body});
    if let Some(k) = key {
        ask["key"] = k.into();
    }
    let proof = c.browser.ais(
        domain,
        &access_crypto::random::bytes::<16>().unwrap(),
        read_intent(&Method::POST, "/admin/v1/realms/acme/intents"),
        Mode::Check,
        basis,
    );
    let (r, bytes) = send(
        &c.management,
        c.browser
            .request(
                &Method::POST,
                "/console/api/proxy/admin/realms/acme/intents",
                "x",
            )
            .header("x-access-ais", proof)
            .body(Body::from(ask.to_string()))
            .unwrap(),
    )
    .await;
    let draft: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    if r.status() != StatusCode::OK {
        return (r.status(), draft);
    }
    let digest = Digest(
        <[u8; 32]>::try_from(
            access_kernel::json::b64url_decode(draft["intent_digest"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
    );
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let ais = c.browser.ais(domain, &nonce, digest, Mode::Commit, basis);
    let method = if path.ends_with("recovery-policy") {
        Method::PUT
    } else {
        Method::POST
    };
    let (r, bytes) = send(
        &c.management,
        c.browser
            .request(&method, &format!("/console/api/proxy{path}"), "x")
            .header("x-access-ais", ais)
            .header("idempotency-key", b64url_encode(&nonce))
            .body(Body::from(draft["body"].to_string()))
            .unwrap(),
    )
    .await;
    (
        r.status(),
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// The newest Relay message of `kind` for `subject` in the identity outbox, opened with the
/// subject's key as the courier opens it.
async fn relayed(c: &Console, subject: [u8; 16], kind: &str) -> Message {
    let ids = crate::ids::CellIds::new(c.w.keys.clone()).key().unwrap();
    let v = vault_of(c);
    let realm = Realm {
        tenant: c.route.tenant,
        realm: c.route.realm,
        kek: &*v.kek,
        ids: &ids,
    };
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let row = t.subject(subject, false).await.unwrap().unwrap();
    t.commit().await.unwrap();
    let dek = access_identity_account::app::sealing::subject_key(&realm, &row).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let mut cursor = access_store::identity::Cursor::default();
        let mut found = None;
        loop {
            let batch = access_store::identity::poll(&c.w.db.reader, cursor, 500)
                .await
                .unwrap();
            let Some(last) = batch.last() else { break };
            cursor = access_store::identity::Cursor {
                xid: last.xid,
                id: last.id,
            };
            for e in batch.iter().filter(|e| e.kind == kind) {
                if let Ok(env) = access_identity_account::notify::envelope::parse(&e.payload)
                    && let Ok(m) = env.open(&e.kind, &dek)
                    && m.subject == subject
                {
                    found = Some(m);
                }
            }
        }
        if let Some(m) = found {
            return m;
        }
        assert!(std::time::Instant::now() < deadline, "no {kind} after 20 s");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

async fn audited(c: &Console, event: &str) -> Vec<access_store::audit::AuditRow> {
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let rows: Vec<_> = t
        .list_audit(1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.event_type == event)
        .collect();
    t.commit().await.unwrap();
    rows
}

// TN-61, TN-62, TN-60, MD-14, HL-38, TNI-6, TN-55, OP-153 m.3 (a), (f), (gg)
// TN-61, Ek B 3555, 3557, 3845, 3550, 3531, 4041
#[tokio::test]
async fn a_reset_intent_is_an_exercise_and_opens_a_rebind_window_once() {
    let c = console("recovery-intent", false).await;
    let sent = Recording::default();
    let app = hosted(&c, sent.clone());
    let ids = crate::ids::CellIds::new(c.w.keys.clone()).key().unwrap();
    let ivy = account(&c, "ivy@example.com", true).await;
    let key = ids
        .encode(access_identity_account::app::SUBJECT_PREFIX, ivy)
        .unwrap();
    let before = c.w.domains.head(c.domain).await.unwrap().0;

    // TN-61, MD-14
    let (status, body) = admin_write(
        &c,
        "createResetIntent",
        Some(&key),
        &format!("/admin/realms/acme/accounts/{key}/reset-intents"),
        serde_json::json!({"password": "chosen-by-the-admin"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = admin_write(
        &c,
        "createResetIntent",
        Some(&key),
        &format!("/admin/realms/acme/accounts/{key}/reset-intents"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let position: u64 = body["position"].as_str().unwrap().parse().unwrap();
    assert!(position > before, "the intent is a recorded Exercise");
    let issued = audited(&c, "recovery.reset_intent.issued").await;
    assert_eq!(issued.len(), 1);
    let founder = ids
        .encode(access_identity_account::app::SUBJECT_PREFIX, c.subject)
        .unwrap();
    assert_eq!(issued[0].actor, founder, "the issue names the issuer");
    assert_eq!(issued[0].target, key);

    // TN-61
    let m = relayed(&c, ivy, "relay.message.reset_intent.v1").await;
    let Address::Email(to) = &m.to else {
        panic!("not an e-mail")
    };
    assert_eq!(to, "ivy@example.com");
    let MessageBody::Link {
        link,
        expires_at_ms,
        ..
    } = &m.body
    else {
        panic!("not a link")
    };
    assert!(
        *expires_at_ms <= now() + 3_600_000 + 60_000,
        "one hour by default"
    );
    let token = link.expose().split_once("#intent=").unwrap().1.to_owned();

    // TN-61, HL-38
    let mut page = Page::default();
    let opened = page
        .call(
            &app,
            &Method::POST,
            &format!("/v1/recovery/intents/{token}"),
            None,
        )
        .await;
    assert_eq!(opened.status, StatusCode::OK, "{}", opened.json);
    assert_eq!(opened.json["state"], "rebind_open");
    assert_eq!(opened.json["method"], "reset_intent");
    let mut again = Page::default();
    let reused = again
        .call(
            &app,
            &Method::POST,
            &format!("/v1/recovery/intents/{token}"),
            None,
        )
        .await;
    assert_eq!(reused.status, StatusCode::GONE);
    assert_eq!(audited(&c, "recovery.reset_intent.used").await.len(), 1);
    let attempt = opened.json["attempt"].as_str().unwrap().to_owned();
    let bound = page
        .call(
            &app,
            &Method::POST,
            &format!("/v1/recovery/{attempt}"),
            Some(serde_json::json!({"new_password": "ivy picks this one herself"})),
        )
        .await;
    assert_eq!(bound.status, StatusCode::OK, "{}", bound.json);
    assert_eq!(bound.json["state"], "grace_period");

    // TN-62
    let (status, body) = admin_write(
        &c,
        "createResetIntent",
        Some(&founder),
        &format!("/admin/realms/acme/accounts/{founder}/reset-intents"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "self-issue-refused");
    let (status, body) = admin_write(
        &c,
        "createTemporaryAccessPass",
        Some(&key),
        &format!("/admin/realms/acme/accounts/{key}/temporary-access-passes"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "recovery-option-off");

    // TN-55, §10.1.3
    let mut policy = serde_json::to_value(
        access_identity_account::domain::recovery_policy::RecoveryPolicy::DEFAULT,
    )
    .unwrap();
    policy["cooling"]["sent_code_ms"] = (2 * 86_400_000_u64).into();
    let (status, body) = admin_write(
        &c,
        "putRecoveryPolicy",
        None,
        "/admin/realms/acme/settings/recovery-policy",
        policy.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // TN-55, OP-153 m.3 (e)
    let mut below = policy.clone();
    below["cooling"]["sent_code_ms"] = 3_600_000_u64.into();
    let (status, body) = admin_write(
        &c,
        "putRecoveryPolicy",
        None,
        "/admin/realms/acme/settings/recovery-policy",
        below,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid-recovery-policy");
    let mut loosen = policy;
    loosen["tap"] = true.into();
    let (status, body) = admin_write(
        &c,
        "putRecoveryPolicy",
        None,
        "/admin/realms/acme/settings/recovery-policy",
        loosen,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let stored = t.recovery_realm_policy().await.unwrap().unwrap();
    t.commit().await.unwrap();
    let stored =
        access_identity_account::domain::recovery_policy::RecoveryPolicy::from_bytes(&stored)
            .unwrap();
    assert!(stored.tap);
    assert_eq!(stored.cooling.sent_code_ms, 2 * 86_400_000);
    let (status, body) = admin_write(
        &c,
        "createTemporaryAccessPass",
        Some(&key),
        &format!("/admin/realms/acme/accounts/{key}/temporary-access-passes"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(audited(&c, "recovery.tap.issued").await.len(), 1);
}
