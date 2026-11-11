//! Sign-in flows, sessions, second factors and epochs on a real PostgreSQL with a software
//! WebAuthn authenticator (OP-146 I5, m.4 (g)).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "../../identity-webauthn/tests/support/mod.rs"]
mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_crypto::totp::{TotpAlgorithm, hotp, step_of};
use access_crypto::webauthn::DecoyKey;
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::SystemEntropy;
use access_identity_account::app::accounts::{
    PasswordServices, change_status, create, deactivate, set_password,
};
use access_identity_account::app::hasher::{Hasher, HasherConfig};
use access_identity_account::app::local::LocalLimiter;
use access_identity_account::app::login::LoginGate;
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::claims::{Bind, authentication_line};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::login::REJECTED;
use access_identity_account::domain::password::Argon2Params;
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::domain::throttle::ThrottlePolicy;
use access_identity_account::notify::NotifyError;
use access_identity_account::notify::envelope::EventId;
use access_identity_account::notify::message::{Body, Message};
use access_identity_account::notify::ports::Notifier;
use access_identity_account::ports::{BreachRanges, Clock, RangeUnavailable};
use access_identity_hooks::domain::{
    Call, HookPoint, Outcome as HookOutcome, Refusal as HookRefusal,
};
use access_identity_hooks::ports::{CallFuture, HookCaller};
use access_identity_session::SessionError;
use access_identity_session::adapters::OsRandom;
use access_identity_session::adapters::passkeys::PgPasskeys;
use access_identity_session::app::HOOK_REFUSED;
use access_identity_session::app::epochs::Epochs;
use access_identity_session::app::sessions::SessionStatus;
use access_identity_session::app::signin::{Identify, LinkOutcome, LinkPreview, PasswordStep};
use access_identity_session::app::{
    Auth, CODE_NOT_ACCEPTED, FLOW_GONE, FlowRef, Passkeys, Refusal, RiskServices, Sl2, Step,
};
use access_identity_session::domain::assurance::{Aal, CtCeiling, MethodClass};
use access_identity_session::domain::requirement::{AuthPolicy, MfaPolicy, Requirement};
use access_identity_session::domain::session::{SessionCheck, SessionPolicy};
use access_identity_webauthn::adapters::{MemorySignals, RealmDecoyKeys};
use access_identity_webauthn::app::RegistrationOutcome;
use access_identity_webauthn::domain::ceremony::{
    AssertionResponse, ClientExtensionResults, RegistrationResponse,
};
use access_identity_webauthn::domain::ids::RealmId as WaRealm;
use access_identity_webauthn::domain::policy::RealmPolicy;
use access_identity_webauthn::domain::rp::{RelyingParty, RpId};
use access_kernel::json::b64url_decode;
use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use support::{Authenticator, Key, ORIGIN, RP_ID};

struct TestClock(AtomicU64);

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

/// The Relay seam as a recorder: what would be queued, with its secret.
#[derive(Default)]
struct Outbox(Mutex<Vec<([u8; 16], String)>>);

impl Notifier for Outbox {
    fn notify(
        &self,
        _: &mut TenantTx,
        m: &Message,
    ) -> impl Future<Output = Result<EventId, NotifyError>> {
        let secret = match &m.body {
            Body::Otp { code, .. } => code.expose().clone(),
            Body::MagicLink { link, .. } => link.expose().clone(),
            _ => String::new(),
        };
        self.0.lock().unwrap().push((m.subject, secret));
        std::future::ready(Ok(EventId([1; 16])))
    }
}

impl Outbox {
    fn last(&self) -> Option<([u8; 16], String)> {
        self.0.lock().unwrap().last().cloned()
    }

    fn count(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};
const LINK_BASE: &str = "https://acme.example/login/link#";
const PW: &str = "correct horse battery";

struct Env {
    db: TestDb,
    domain: DomainId,
    tenant: TenantId,
    realm: RealmId,
    kek: SoftKek,
    vault: access_identity_account::app::vault::Vault,
    ids: IdKey,
    clock: TestClock,
    hasher: Hasher,
    gate: LoginGate,
    outbox: Outbox,
    signals: MemorySignals,
    decoys: RealmDecoyKeys,
    rp: RelyingParty,
    wa_policy: RealmPolicy,
    policy: AuthPolicy,
    hook: ScriptedHook,
    risk: RiskServices,
    client: Option<IpAddr>,
}

/// A `post_login` hook answering what the test sets; none set is no hook (TN-135).
#[derive(Default)]
struct ScriptedHook(Mutex<Option<HookOutcome>>);

impl HookCaller for ScriptedHook {
    fn call(&self, _: TenantId, _: RealmId, call: Call) -> CallFuture<'_> {
        assert_eq!(call.point(), HookPoint::PostLogin);
        let answer = self
            .0
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(HookOutcome::proceed);
        Box::pin(async move { answer })
    }
}

type TestAuth<'a> =
    Auth<'a, PgAccounts, TestClock, OsRandom, Outbox, PgPasskeys<'a>, MemorySignals>;

impl Env {
    fn realm(&self) -> Realm<'_> {
        Realm {
            tenant: self.tenant,
            realm: self.realm,
            kek: &self.kek,
            ids: &self.ids,
        }
    }

    async fn with<T>(&self, f: impl AsyncFnOnce(&TestAuth<'_>) -> T) -> T {
        let db = PgAccounts::sealed(self.db.app.clone(), self.vault.clone());
        let registry = PgPasskeys {
            pool: &self.db.app,
            tenant: self.tenant,
            kek: &self.kek,
            ids: &self.ids,
        };
        let auth = Auth {
            db: &db,
            realm: self.realm(),
            policy: self.policy,
            lifetimes: SessionPolicy::DEFAULT,
            clock: &self.clock,
            random: &OsRandom,
            notifier: &self.outbox,
            link_base: LINK_BASE,
            gate: &self.gate,
            hasher: &self.hasher,
            hooks: &self.hook,
            passkeys: Passkeys {
                registry: &registry,
                signals: &self.signals,
                decoys: &self.decoys,
                rp: &self.rp,
                policy: &self.wa_policy,
            },
            risk: Sl2 {
                services: &self.risk,
                client: self.client,
            },
        };
        f(&auth).await
    }

    fn advance(&self, ms: u64) {
        self.clock.0.fetch_add(ms, Ordering::SeqCst);
    }

    async fn account(&self, who: &str) -> [u8; 16] {
        let pg = PgAccounts::sealed(self.db.app.clone(), self.vault.clone());
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
    Env {
        db,
        domain: d,
        tenant,
        realm,
        kek: SoftKek::new("realm-kek:1", [seed; 32]),
        vault: access_identity_account::app::vault::Vault::in_memory(
            std::sync::Arc::new(SoftKek::new("realm-kek:1", [seed; 32])),
            [seed; 32],
        ),
        ids: IdKey::new(Secret::new([seed.wrapping_add(1); 32])),
        clock: TestClock(AtomicU64::new(1_800_000_000_000)),
        hasher: Hasher::new(HasherConfig::sized(Argon2Params::CANONICAL, 4, None)),
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        outbox: Outbox::default(),
        signals: MemorySignals::default(),
        decoys: RealmDecoyKeys::default().with(wa, DecoyKey::new(Secret::new([9; 32]))),
        rp: RelyingParty {
            realm: wa,
            rp_id: RpId::parse(RP_ID).unwrap(),
            name: "Acme".into(),
            pinned: true,
            related: Vec::new(),
        },
        wa_policy: RealmPolicy::default(),
        policy: AuthPolicy::DEFAULT,
        hook: ScriptedHook::default(),
        risk: RiskServices::without_sources(),
        client: Some(ip()),
    }
}

fn ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}

async fn start(e: &Env, who: Option<&str>, marker: Option<&str>) -> (String, String) {
    let s = e
        .with(async |a| {
            a.identify(&Identify {
                identifier: who,
                marker,
                remember_device: true,
                ..Identify::default()
            })
            .await
        })
        .await
        .unwrap();
    (s.handle, s.device)
}

async fn password(e: &Env, flow: &(String, String), who: &str, pw: &str) -> Step {
    let r = FlowRef {
        handle: &flow.0,
        device: &flow.1,
    };
    e.with(async |a| {
        a.password(
            &r,
            &PasswordStep {
                identifier: who,
                password: pw,
                ip: ip(),
                correlation: "req",
            },
        )
        .await
    })
    .await
    .unwrap()
}

fn cookie_value(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .and_then(|kv| kv.split_once('='))
        .map(|(_, v)| v.to_owned())
        .unwrap()
}

fn signed_in(step: Step) -> (String, access_identity_session::app::SignedIn) {
    match step {
        Step::SignedIn(s) => (cookie_value(s.set_cookie.as_deref().unwrap()), *s),
        other => panic!("not signed in: {other:?}"),
    }
}

async fn sign_in(e: &Env, who: &str) -> String {
    let flow = start(e, Some(who), None).await;
    signed_in(password(e, &flow, who, PW).await).0
}

async fn status(e: &Env, cookie: &str) -> SessionStatus {
    e.with(async |a| a.check_session(cookie).await)
        .await
        .unwrap()
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

fn totp_now(e: &Env, seed: &[u8]) -> String {
    hotp(
        seed,
        TotpAlgorithm::Sha1,
        step_of(e.clock.now_ms() / 1000, 30),
        6,
    )
}

/// Turns TOTP on from `cookie`'s session; returns the seed and the recovery codes.
async fn enable_totp(e: &Env, cookie: &str) -> (Vec<u8>, Vec<String>) {
    let enrollment = e
        .with(async |a| a.begin_totp(cookie, "Acme", "alice").await)
        .await
        .unwrap()
        .unwrap();
    let seed = base32_decode(enrollment.secret.expose());
    assert!(
        enrollment
            .uri
            .expose()
            .starts_with("otpauth://totp/Acme:alice?secret=")
    );
    let code = totp_now(e, &seed);
    let handle = enrollment.handle.clone();
    let confirmed = e
        .with(async |a| a.confirm_totp(cookie, &handle, &code, "req").await)
        .await
        .unwrap()
        .unwrap_or_else(|s| panic!("{s:?}"));
    let codes = confirmed
        .recovery_codes
        .unwrap()
        .iter()
        .map(|c| c.expose().clone())
        .collect();
    (seed, codes)
}

fn ref_of(flow: &(String, String)) -> FlowRef<'_> {
    FlowRef {
        handle: &flow.0,
        device: &flow.1,
    }
}

// TN-96, CR-40, X34, TN-82, TN-97
#[tokio::test]
async fn identifier_first_does_not_tell_whether_the_account_exists() {
    let e = env(1, "is-a").await;
    e.account("alice@example.com").await;
    let gone = e.account("gone@example.com").await;
    deactivate(
        &PgAccounts::sealed(e.db.app.clone(), e.vault.clone()),
        &e.realm(),
        gone,
        &ADMIN,
    )
    .await
    .unwrap();
    let mut shapes = Vec::new();
    for who in [
        "alice@example.com",
        "nobody@example.com",
        "gone@example.com",
    ] {
        let s = e
            .with(async |a| {
                a.identify(&Identify {
                    identifier: Some(who),
                    ..Identify::default()
                })
                .await
            })
            .await
            .unwrap();
        let mut o = s.options.passkey.clone();
        o["challenge"] = serde_json::Value::Null;
        let allow = o["allowCredentials"].as_array().unwrap().len();
        assert!((1..=2).contains(&allow));
        o["allowCredentials"] = serde_json::Value::Null;
        shapes.push((
            o,
            s.options.password,
            s.options.email_code,
            s.options.magic_link,
        ));
        assert!(s.set_cookie.unwrap().starts_with("__Host-access-flow="));
    }
    assert_eq!(shapes[0], shapes[1]);
    assert_eq!(shapes[0], shapes[2]);
    let mut answers = Vec::new();
    for who in [
        "alice@example.com",
        "nobody@example.com",
        "gone@example.com",
    ] {
        let flow = start(&e, Some(who), None).await;
        let wrong = password(&e, &flow, who, "not the password").await;
        answers.push(match wrong {
            Step::Rejected(r) => r.problem,
            other => panic!("{other:?}"),
        });
    }
    e.advance(60_000);
    let gone_right = password(
        &e,
        &start(&e, Some("gone@example.com"), None).await,
        "gone@example.com",
        PW,
    )
    .await;
    assert!(matches!(gone_right, Step::Rejected(Refusal { problem, .. }) if problem == REJECTED));
    assert!(answers.iter().all(|p| *p == REJECTED));
    let flow = start(&e, Some("alice@example.com"), None).await;
    let other = password(&e, &flow, "nobody@example.com", PW).await;
    assert!(matches!(other, Step::Rejected(Refusal { problem, .. }) if problem == REJECTED));
}

// TN-36, CR-38, TN-103, G57, EP-2, XI-23, §10.1.6
// TN-135, MD-8, OP-151 m.3 (j)
#[tokio::test]
async fn tn_135_a_post_login_hook_may_only_refuse() {
    let e = env(40, "is-hook").await;
    e.account("ada@example.com").await;
    for refusal in [
        HookRefusal::Denied {
            reason_code: Some(String::from("blocked")),
        },
        HookRefusal::Unanswered,
        HookRefusal::Violation,
    ] {
        *e.hook.0.lock().unwrap() = Some(HookOutcome::Refused(refusal));
        let flow = start(&e, Some("ada@example.com"), None).await;
        let step = password(&e, &flow, "ada@example.com", PW).await;
        assert!(
            matches!(step, Step::Rejected(Refusal { problem, .. }) if problem == HOOK_REFUSED),
            "{step:?}"
        );
    }
    *e.hook.0.lock().unwrap() = Some(HookOutcome::proceed());
    let flow = start(&e, Some("ada@example.com"), None).await;
    let (cookie, _) = signed_in(password(&e, &flow, "ada@example.com", PW).await);
    assert!(matches!(status(&e, &cookie).await, SessionStatus::Valid(_)));
}

#[tokio::test]
async fn a_password_opens_a_session_and_sign_out_ends_it() {
    let e = env(2, "is-b").await;
    let alice = e.account("alice@example.com").await;
    let flow = start(&e, Some("ALICE@example.com"), None).await;
    let (cookie, s) = signed_in(password(&e, &flow, "alice@example.com", PW).await);
    assert_eq!(s.result.subject, alice);
    assert_eq!(s.result.methods, [MethodClass::Password]);
    assert_eq!(s.result.assurance.aal, Aal::Aal1);
    assert!(!s.result.assurance.phishing_resistant);
    assert_eq!(s.result.ct, CtCeiling::None);
    assert_eq!(s.result.assurance.loa_eidas, None);
    let set = s.set_cookie.unwrap();
    assert!(set.starts_with("__Host-access-session="));
    assert!(set.contains("HttpOnly") && !set.contains("Max-Age"));
    assert_eq!(b64url_decode(&cookie).unwrap().len(), 32);
    let SessionStatus::Valid(v) = status(&e, &cookie).await else {
        panic!("not valid");
    };
    assert_eq!(v.subject, alice);
    let flow_reuse = password(&e, &flow, "alice@example.com", PW).await;
    assert!(matches!(flow_reuse, Step::Rejected(Refusal { problem, .. }) if problem == FLOW_GONE));
    let cleared = e
        .with(async |a| a.sign_out(&cookie, "req").await)
        .await
        .unwrap();
    assert!(cleared.contains("Max-Age=0"));
    assert_eq!(
        status(&e, &cookie).await,
        SessionStatus::Invalid(SessionCheck::Ended)
    );
    assert_eq!(status(&e, "not-a-cookie").await, SessionStatus::Unknown);
    // §12.0.3, §7.1, X36, OP-150 L6
    let orders = claim_orders(&e, |o| o.iter().any(|x| x.retract)).await;
    let line = authentication_line(&s.session);
    let signed = orders
        .iter()
        .find(|o| !o.retract && o.class == "authentication")
        .unwrap();
    assert_eq!(signed.line, Some(line));
    let ended = orders.iter().find(|o| o.retract).unwrap();
    assert_eq!(ended.class, "authentication");
    assert_eq!(ended.line, Some(line));
    assert_eq!(ended.bind, Bind::Session(s.session));
    assert_eq!(ended.subject, alice);
    assert_eq!(orders.iter().filter(|o| o.retract).count(), 1);
}

// TN-36
#[tokio::test]
async fn sessions_expire_when_idle_and_keep_me_signed_in_persists_the_cookie() {
    let e = env(3, "is-c").await;
    e.account("alice@example.com").await;
    let flow = e
        .with(async |a| {
            a.identify(&Identify {
                identifier: Some("alice@example.com"),
                keep_signed_in: true,
                ..Identify::default()
            })
            .await
        })
        .await
        .unwrap();
    let flow = (flow.handle, flow.device);
    let (cookie, s) = signed_in(password(&e, &flow, "alice@example.com", PW).await);
    assert!(
        s.set_cookie
            .unwrap()
            .ends_with(&format!("Max-Age={}", 30 * 86_400))
    );
    e.advance(6 * 86_400_000);
    assert!(matches!(status(&e, &cookie).await, SessionStatus::Valid(_)));
    e.advance(7 * 86_400_000 + 1);
    assert_eq!(
        status(&e, &cookie).await,
        SessionStatus::Invalid(SessionCheck::IdleExpired)
    );
}

// TN-132, TN-64, RFC 6238, §10.2.2, TN-59
#[tokio::test]
async fn totp_is_required_once_enrolled_and_cannot_be_replayed() {
    let e = env(4, "is-d").await;
    e.account("alice@example.com").await;
    let other = sign_in(&e, "alice@example.com").await;
    let current = sign_in(&e, "alice@example.com").await;
    let (seed, codes) = enable_totp(&e, &current).await;
    assert_eq!(codes.len(), 10);
    assert!(matches!(
        status(&e, &current).await,
        SessionStatus::Valid(_)
    ));
    assert!(matches!(
        status(&e, &other).await,
        SessionStatus::Invalid(SessionCheck::Ended)
    ));

    let flow = start(&e, Some("alice@example.com"), None).await;
    let step = password(&e, &flow, "alice@example.com", PW).await;
    let Step::Continue { needs, enrolled } = step else {
        panic!("{step:?}");
    };
    assert_eq!(needs, [Requirement::SecondFactor]);
    assert!(enrolled.unwrap().totp);
    let wrong = e
        .with(async |a| a.totp(&ref_of(&flow), "000000", "req").await)
        .await
        .unwrap();
    assert!(
        matches!(wrong, Step::Rejected(Refusal { problem, .. }) if problem == CODE_NOT_ACCEPTED)
    );
    e.advance(30_000);
    let code = totp_now(&e, &seed);
    let ok = e
        .with(async |a| {
            let c = code.clone();
            let f = flow.clone();
            a.totp(&ref_of(&f), &c, "req").await
        })
        .await
        .unwrap();
    let (_, s) = signed_in(ok);
    assert_eq!(s.result.methods, [MethodClass::Password, MethodClass::Totp]);
    assert_eq!(s.result.assurance.aal, Aal::Aal2);
    assert!(s.marker_cookie.is_some());

    let replay_flow = start(&e, Some("alice@example.com"), None).await;
    password(&e, &replay_flow, "alice@example.com", PW).await;
    let replay = e
        .with(async |a| {
            let c = code.clone();
            let f = replay_flow.clone();
            a.totp(&ref_of(&f), &c, "req").await
        })
        .await
        .unwrap();
    assert!(
        matches!(replay, Step::Rejected(Refusal { problem, .. }) if problem == CODE_NOT_ACCEPTED)
    );

    let typed = codes[0].to_lowercase().replace('-', " ");
    let used = e
        .with(async |a| {
            let f = replay_flow.clone();
            let t = typed.clone();
            a.recovery_code(&ref_of(&f), &t, "req").await
        })
        .await
        .unwrap();
    let (_, s) = signed_in(used);
    assert_eq!(
        s.result.methods,
        [MethodClass::Password, MethodClass::RecoveryCode]
    );
    let again = start(&e, Some("alice@example.com"), None).await;
    password(&e, &again, "alice@example.com", PW).await;
    let reused = e
        .with(async |a| {
            let f = again.clone();
            let t = codes[0].clone();
            a.recovery_code(&ref_of(&f), &t, "req").await
        })
        .await
        .unwrap();
    assert!(
        matches!(reused, Step::Rejected(Refusal { problem, .. }) if problem == CODE_NOT_ACCEPTED)
    );
    let before = start(&e, Some("alice@example.com"), None).await;
    let skipped = e
        .with(async |a| {
            let f = before.clone();
            let c = codes[1].clone();
            a.recovery_code(&ref_of(&f), &c, "req").await
        })
        .await
        .unwrap();
    assert!(matches!(skipped, Step::Rejected(Refusal { problem, .. }) if problem == REJECTED));
}

// X33, TN-50, MD-7
#[tokio::test]
async fn a_device_marker_skips_the_second_step_until_sign_out_everywhere() {
    let e = env(5, "is-e").await;
    let alice = e.account("alice@example.com").await;
    let cookie = sign_in(&e, "alice@example.com").await;
    let (seed, _) = enable_totp(&e, &cookie).await;
    e.advance(30_000);
    let flow = start(&e, Some("alice@example.com"), None).await;
    password(&e, &flow, "alice@example.com", PW).await;
    let code = totp_now(&e, &seed);
    let (_, s) = signed_in(
        e.with(async |a| {
            let f = flow.clone();
            a.totp(&ref_of(&f), &code, "req").await
        })
        .await
        .unwrap(),
    );
    let marker = cookie_value(&s.marker_cookie.unwrap());
    let with_marker = start(&e, Some("alice@example.com"), Some(&marker)).await;
    let (_, s) = signed_in(password(&e, &with_marker, "alice@example.com", PW).await);
    assert_eq!(s.result.methods, [MethodClass::Password]);
    assert_eq!(s.result.assurance.aal, Aal::Aal1);
    e.with(async |a| a.sign_out_everywhere(alice, "usr", "req").await)
        .await
        .unwrap();
    let after = start(&e, Some("alice@example.com"), Some(&marker)).await;
    let step = password(&e, &after, "alice@example.com", PW).await;
    assert!(
        matches!(step, Step::Continue { ref needs, .. } if needs == &[Requirement::SecondFactor])
    );
}

// TN-102, TNI-9, §10.2.2, CR-40
#[tokio::test]
async fn email_code_and_magic_link_are_suspendable_single_use_steps() {
    let e = env(6, "is-f").await;
    let alice = e.account("alice@example.com").await;
    let unknown = start(&e, Some("nobody@example.com"), None).await;
    let s = e
        .with(async |a| {
            let f = unknown.clone();
            {
                a.send_email(&ref_of(&f), MethodClass::EmailOtp, "req")
                    .await
            }
        })
        .await
        .unwrap();
    assert_eq!(
        s,
        Step::Suspended {
            method: MethodClass::EmailOtp
        }
    );
    assert_eq!(e.outbox.count(), 0);
    let flow = start(&e, Some("alice@example.com"), None).await;
    let s = e
        .with(async |a| {
            let f = flow.clone();
            {
                a.send_email(&ref_of(&f), MethodClass::EmailOtp, "req")
                    .await
            }
        })
        .await
        .unwrap();
    assert_eq!(
        s,
        Step::Suspended {
            method: MethodClass::EmailOtp
        }
    );
    let (to, code) = e.outbox.last().unwrap();
    assert_eq!(to, alice);
    assert_eq!(code.len(), 8);
    let wrong = e
        .with(async |a| {
            let f = flow.clone();
            a.email_code(&ref_of(&f), "12345678", "req").await
        })
        .await
        .unwrap();
    assert!(matches!(wrong, Step::Rejected(Refusal { problem, .. }) if problem == REJECTED));
    let (_, s) = signed_in(
        e.with(async |a| {
            let f = flow.clone();
            let c = code.clone();
            a.email_code(&ref_of(&f), &c, "req").await
        })
        .await
        .unwrap(),
    );
    assert_eq!(s.result.methods, [MethodClass::EmailOtp]);
    assert_eq!(s.result.ct, CtCeiling::None);

    let flow = start(&e, Some("alice@example.com"), None).await;
    e.with(async |a| {
        let f = flow.clone();
        {
            a.send_email(&ref_of(&f), MethodClass::MagicLink, "req")
                .await
        }
    })
    .await
    .unwrap();
    let (_, link) = e.outbox.last().unwrap();
    let token = link.strip_prefix(LINK_BASE).unwrap().to_owned();
    for _ in 0..3 {
        let p = e
            .with(async |a| {
                let t = token.clone();
                a.preview_link(&t, None).await
            })
            .await
            .unwrap();
        assert_eq!(p, LinkPreview::Confirm { same_device: false });
    }
    let other = e
        .with(async |a| {
            let t = token.clone();
            a.confirm_link(&t, None, false, "req").await
        })
        .await
        .unwrap();
    assert_eq!(other, LinkOutcome::NeedsConfirmation);
    let waiting = e
        .with(async |a| {
            let f = flow.clone();
            a.resume(&ref_of(&f), "req").await
        })
        .await
        .unwrap();
    assert_eq!(
        waiting,
        Step::Suspended {
            method: MethodClass::MagicLink
        }
    );
    let confirmed = e
        .with(async |a| {
            let t = token.clone();
            a.confirm_link(&t, None, true, "req").await
        })
        .await
        .unwrap();
    assert_eq!(confirmed, LinkOutcome::Confirmed { same_device: false });
    let again = e
        .with(async |a| {
            let t = token.clone();
            a.confirm_link(&t, Some("x"), true, "req").await
        })
        .await
        .unwrap();
    assert_eq!(again, LinkOutcome::Invalid);
    let stolen = e
        .with(async |a| {
            let f = flow.clone();
            {
                a.resume(
                    &FlowRef {
                        handle: &f.0,
                        device: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    },
                    "req",
                )
                .await
            }
        })
        .await
        .unwrap();
    assert!(matches!(stolen, Step::Rejected(Refusal { problem, .. }) if problem == FLOW_GONE));
    let (_, s) = signed_in(
        e.with(async |a| {
            let f = flow.clone();
            a.resume(&ref_of(&f), "req").await
        })
        .await
        .unwrap(),
    );
    assert_eq!(s.result.methods, [MethodClass::MagicLink]);
}

// TN-102 rule 3
#[tokio::test]
async fn a_suspended_code_expires() {
    let e = env(7, "is-g").await;
    e.account("alice@example.com").await;
    let flow = start(&e, Some("alice@example.com"), None).await;
    e.with(async |a| {
        let f = flow.clone();
        {
            a.send_email(&ref_of(&f), MethodClass::EmailOtp, "req")
                .await
        }
    })
    .await
    .unwrap();
    let (_, code) = e.outbox.last().unwrap();
    e.advance(15 * 60_000);
    let late = e
        .with(async |a| {
            let f = flow.clone();
            a.email_code(&ref_of(&f), &code, "req").await
        })
        .await
        .unwrap();
    assert!(matches!(late, Step::Rejected(Refusal { problem, .. }) if problem == REJECTED));
}

async fn register_passkey(e: &Env, cookie: &str, auth: &mut Authenticator) -> Vec<u8> {
    let reg = e
        .with(async |a| a.begin_passkey(cookie, "alice@example.com", "Alice").await)
        .await
        .unwrap()
        .unwrap();
    let challenge = b64url_decode(reg.options["challenge"].as_str().unwrap()).unwrap();
    let (cdj, att) = auth.register(RP_ID, ORIGIN, &challenge);
    let id = auth.credential_id.clone();
    let outcome = e
        .with(async |a| {
            let h = reg.handle.clone();
            {
                a.finish_passkey(
                    cookie,
                    &h,
                    &RegistrationResponse {
                        raw_id: &id,
                        client_data_json: &cdj,
                        attestation_object: &att,
                        transports: &[],
                        extensions: ClientExtensionResults::default(),
                    },
                    "req",
                )
                .await
            }
        })
        .await
        .unwrap()
        .unwrap_or_else(|s| panic!("{s:?}"));
    assert!(matches!(outcome, RegistrationOutcome::Registered(_)));
    b64url_decode(reg.options["user"]["id"].as_str().unwrap()).unwrap()
}

async fn assert_passkey(
    e: &Env,
    flow: &(String, String),
    challenge_source: &serde_json::Value,
    auth: &mut Authenticator,
    handle: &[u8],
) -> Step {
    let challenge = b64url_decode(challenge_source["challenge"].as_str().unwrap()).unwrap();
    let (cdj, ad, sig) = auth.assert(RP_ID, ORIGIN, &challenge);
    let id = auth.credential_id.clone();
    e.with(async |a| {
        let f = flow.clone();
        {
            a.passkey(
                &ref_of(&f),
                &AssertionResponse {
                    raw_id: &id,
                    client_data_json: &cdj,
                    authenticator_data: &ad,
                    signature: &sig,
                    user_handle: Some(handle),
                },
                "req",
            )
            .await
        }
    })
    .await
    .unwrap()
}

// §10.2.4, OP-146 m.9, §10.3.1, IDP-8, TN-68, TN-44, OP-149 m.6, m.8
#[tokio::test]
async fn a_passkey_signs_in_phishing_resistant_and_steps_up() {
    let e = env(8, "is-h").await;
    e.account("alice@example.com").await;
    let cookie = sign_in(&e, "alice@example.com").await;
    let mut key = Authenticator::new(Key::es256());
    let handle = register_passkey(&e, &cookie, &mut key).await;
    // OP-151 m.3 (i)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let rows = access_store::identity::poll(
            &e.db.reader,
            access_store::identity::Cursor::default(),
            1_000,
        )
        .await
        .unwrap();
        if let Some(r) = rows
            .iter()
            .filter(|r| r.kind == "event.credential.changed")
            .find(|r| String::from_utf8_lossy(&r.payload).contains("\"webauthn\""))
        {
            assert!(String::from_utf8_lossy(&r.payload).contains("\"added\""));
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no credential.changed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let started = e
        .with(async |a| {
            a.identify(&Identify {
                identifier: Some("alice@example.com"),
                ..Identify::default()
            })
            .await
        })
        .await
        .unwrap();
    let allow = started.options.passkey["allowCredentials"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(allow.len(), 1);
    let flow = (started.handle.clone(), started.device.clone());
    let challenge = b64url_decode(started.options.passkey["challenge"].as_str().unwrap()).unwrap();
    let (cdj, ad, sig) = key.assert(RP_ID, ORIGIN, &challenge);
    let id = key.credential_id.clone();
    let response = AssertionResponse {
        raw_id: &id,
        client_data_json: &cdj,
        authenticator_data: &ad,
        signature: &sig,
        user_handle: None,
    };
    let first = e
        .with(async |a| {
            let f = flow.clone();
            a.passkey(&ref_of(&f), &response, "req").await
        })
        .await
        .unwrap();
    let (_, s) = signed_in(first);
    assert_eq!(s.result.methods, [MethodClass::Passkey]);
    assert_eq!(s.result.assurance.aal, Aal::Aal3);
    assert!(s.result.assurance.phishing_resistant && s.result.assurance.hardware_bound);
    assert_eq!(s.result.ct, CtCeiling::Ct3);

    let discoverable = e
        .with(async |a| a.identify(&Identify::default()).await)
        .await
        .unwrap();
    assert_eq!(
        discoverable.options.passkey["allowCredentials"],
        serde_json::json!([])
    );
    let flow2 = (discoverable.handle.clone(), discoverable.device.clone());
    let ok = assert_passkey(&e, &flow2, &discoverable.options.passkey, &mut key, &handle).await;
    signed_in(ok);

    let flow3 = start(&e, Some("alice@example.com"), None).await;
    let replayed = e
        .with(async |a| {
            let f = flow3.clone();
            a.passkey(&ref_of(&f), &response, "req").await
        })
        .await
        .unwrap();
    assert!(matches!(replayed, Step::Rejected(Refusal { problem, .. }) if problem == REJECTED));

    let up = e
        .with(async |a| a.step_up(&cookie, Some(&cookie), 300_000, Aal::Aal2).await)
        .await
        .unwrap()
        .unwrap();
    let up_flow = (up.handle.clone(), up.device.clone());
    e.advance(60_000);
    let stepped = assert_passkey(&e, &up_flow, &up.options.passkey, &mut key, &handle).await;
    let Step::SignedIn(s) = stepped else {
        panic!("{stepped:?}");
    };
    assert!(s.set_cookie.is_none());
    let SessionStatus::Valid(v) = status(&e, &cookie).await else {
        panic!("not valid");
    };
    assert_eq!(v.assurance.aal, Aal::Aal3);
    assert_eq!(v.auth_time_ms, e.clock.now_ms());
    assert_eq!(v.step_up_ms, Some(e.clock.now_ms()));
    device_instances_need_a_fresh_step_up(&e, &cookie).await;
}

/// OP-149 m.6, m.8: a stepped-up session registers a device key once per challenge, and its
/// `auth_context` carries the step-up time.
async fn device_instances_need_a_fresh_step_up(e: &Env, cookie: &str) {
    use access_identity_session::app::devices::DeviceRefusal;
    use access_identity_session::domain::device::{Assurance, KeyRejection, cose_key, kid};
    use suiss_crypto::signer::{Signer, SoftSigner};

    const ISSUER: &str = "https://acme.suiss.example";
    let device = SoftSigner::generate_p256().unwrap().0;
    let key = cose_key(&device.public_key());
    let claim = async |challenge: &str, key: &[u8]| {
        let bytes: [u8; 32] = b64url_decode(challenge).unwrap().try_into().unwrap();
        e.with(async |a| a.claim_instance_challenge(cookie, key, &bytes, "req").await)
            .await
            .unwrap()
    };
    let c = e
        .with(async |a| a.instance_challenge(cookie).await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        claim(&c.challenge, &[0xa0]).await,
        Err(DeviceRefusal::Key(KeyRejection::Key))
    );
    assert_eq!(
        claim(&c.challenge, &key).await,
        Err(DeviceRefusal::Challenge),
        "a challenge is used up by any claim"
    );
    assert_eq!(
        claim(&access_kernel::json::b64url_encode(&[7; 32]), &key).await,
        Err(DeviceRefusal::Challenge)
    );
    let c = e
        .with(async |a| a.instance_challenge(cookie).await)
        .await
        .unwrap()
        .unwrap();
    let proven = claim(&c.challenge, &key).await.unwrap();
    assert_eq!(proven.kid, kid(&device.public_key()));
    assert_eq!(proven.key, device.public_key());
    assert_eq!(
        claim(&c.challenge, &key).await,
        Err(DeviceRefusal::Challenge)
    );
    let (context, session) = e
        .with(async |a| a.auth_context(cookie, ISSUER, None).await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(context.step_up_time, Some(e.clock.now_ms()));
    assert_eq!(context.aal, Aal::Aal3);
    // OP-149 m.30 (c)
    assert_eq!(session, proven.session.id);
    assert_eq!(context.instance, None);

    e.advance(5 * 60 * 1000 + 1);
    let c = e
        .with(async |a| a.instance_challenge(cookie).await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        claim(&c.challenge, &key).await,
        Err(DeviceRefusal::Assurance(Assurance::Stale))
    );
    assert_eq!(
        e.with(async |a| a.stepped_up_session(cookie).await)
            .await
            .unwrap()
            .map(|_| ()),
        Err(DeviceRefusal::Assurance(Assurance::Stale))
    );
}

// OP-149 m.6, m.8
#[tokio::test]
async fn a_password_session_cannot_register_a_device() {
    use access_identity_session::app::devices::DeviceRefusal;
    use access_identity_session::domain::device::Assurance;

    let e = env(31, "is-dev").await;
    e.account("alice@example.com").await;
    let cookie = sign_in(&e, "alice@example.com").await;
    assert_eq!(
        e.with(async |a| a.stepped_up_session(&cookie).await)
            .await
            .unwrap()
            .map(|_| ()),
        Err(DeviceRefusal::Assurance(Assurance::TooWeak))
    );
    let (context, _) = e
        .with(async |a| {
            a.auth_context(&cookie, "https://acme.suiss.example", None)
                .await
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(context.aal, Aal::Aal1);
    assert_eq!(context.step_up_time, None);
    assert!(matches!(
        e.with(async |a| a.instance_challenge("bm90LWEtY29va2ll").await)
            .await
            .unwrap(),
        Err(SessionStatus::Unknown)
    ));
}

// TN-50, OP-146 m.10 (a)
#[tokio::test]
async fn deactivation_ends_sessions_in_the_same_transaction() {
    let e = env(9, "is-i").await;
    let alice = e.account("alice@example.com").await;
    let cookie = sign_in(&e, "alice@example.com").await;
    deactivate(
        &PgAccounts::sealed(e.db.app.clone(), e.vault.clone()),
        &e.realm(),
        alice,
        &ADMIN,
    )
    .await
    .unwrap();
    assert_eq!(
        status(&e, &cookie).await,
        SessionStatus::Invalid(SessionCheck::Ended)
    );
    let live = e.with(async |a| a.sessions(alice).await).await.unwrap();
    assert_eq!(
        live,
        [] as [access_identity_session::app::sessions::SessionView; 0]
    );
}

// TN-132, §12.4.2
#[tokio::test]
async fn required_mfa_without_a_second_factor_never_signs_in() {
    let mut e = env(10, "is-j").await;
    e.policy = AuthPolicy {
        mfa: MfaPolicy::Required,
        ..AuthPolicy::DEFAULT
    };
    e.account("alice@example.com").await;
    let flow = start(&e, Some("alice@example.com"), None).await;
    let step = password(&e, &flow, "alice@example.com", PW).await;
    assert!(
        matches!(step, Step::Continue { ref needs, .. } if needs == &[Requirement::EnrollSecondFactor])
    );
}

// G48, MD-8, OP-45
#[tokio::test]
async fn login_fails_closed_when_the_database_is_unreachable() {
    let e = env(11, "is-k").await;
    e.account("alice@example.com").await;
    let flow = start(&e, Some("alice@example.com"), None).await;
    e.db.app.close().await;
    let err = e
        .with(async |a| {
            a.identify(&Identify {
                identifier: Some("alice@example.com"),
                ..Identify::default()
            })
            .await
        })
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        SessionError::Store(_) | SessionError::Account(_)
    ));
    // OP-45, EP-1, Ek B 5736
    let p = err.problem();
    assert_eq!(
        (p.status, p.code, p.retry_after_s),
        (503, "degraded-identity", Some(1))
    );
    let r = ref_of(&flow);
    let err = e
        .with(async |a| {
            a.password(
                &r,
                &PasswordStep {
                    identifier: "alice@example.com",
                    password: PW,
                    ip: ip(),
                    correlation: "req",
                },
            )
            .await
        })
        .await
        .unwrap_err();
    assert_eq!(err.problem().status, 503);
}

// MD-7, TN-37, OP-21, G49
#[tokio::test]
async fn the_epoch_cache_fails_closed_and_learns_revocations() {
    let e = env(12, "is-l").await;
    let alice = e.account("alice@example.com").await;
    let db = PgAccounts::sealed(e.db.app.clone(), e.vault.clone());
    let epochs = Epochs::new(e.tenant, e.realm, 250);
    let now = e.clock.now_ms();
    assert!(!epochs.current(&db, [7; 16], 0, now).await.unwrap());
    assert!(epochs.current(&db, alice, 0, now).await.unwrap());
    assert!(epochs.current(&db, alice, 0, now + 100).await.unwrap());
    e.with(async |a| a.sign_out_everywhere(alice, "usr", "req").await)
        .await
        .unwrap();
    assert_eq!(epochs.poll(&db, Some(0), now + 150).await.unwrap(), 1);
    assert!(!epochs.current(&db, alice, 0, now + 160).await.unwrap());
    assert!(epochs.current(&db, alice, 1, now + 170).await.unwrap());
    e.db.app.close().await;
    assert!(epochs.current(&db, alice, 1, now + 10_000).await.is_err());
}

/// The queued Claim orders once `ready` holds for them; the outbox shows a row only once every
/// older transaction in the cluster has ended.
async fn claim_orders(
    e: &Env,
    ready: impl Fn(&[access_identity_account::domain::claims::ClaimOrder]) -> bool,
) -> Vec<access_identity_account::domain::claims::ClaimOrder> {
    use access_identity_account::domain::claims::{ClaimOrder, OUTBOX_PREFIX};
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let orders: Vec<ClaimOrder> = access_store::identity::poll(
            &e.db.reader,
            access_store::identity::Cursor::default(),
            1000,
        )
        .await
        .unwrap()
        .into_iter()
        .filter(|o| o.kind.starts_with(OUTBOX_PREFIX))
        .map(|o| ClaimOrder::from_bytes(&o.payload).unwrap())
        .collect();
        if ready(&orders) {
            return orders;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "claim orders: {:?}",
            orders.iter().map(|o| &o.class).collect::<Vec<_>>()
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

fn risk_names(orders: &[access_identity_account::domain::claims::ClaimOrder]) -> Vec<String> {
    use access_identity_account::domain::claims::{Content, RISK_SIGNAL};
    orders
        .iter()
        .filter(|o| o.class == RISK_SIGNAL)
        .filter_map(|o| match &o.content {
            Content::Scalar(access_kernel::model::EqValue::Text(t)) => Some(t.clone()),
            _ => None,
        })
        .collect()
}

// F17, TN-103, §10.1.2, §10.1.5, §10.1.6, TN-63, §10.2.4, IDI-3, IDI-5, IDP-2, CI-2, §7.6
// OP-150 L2
#[tokio::test]
async fn sign_in_queues_its_claims_and_signals_never_gate() {
    use access_identity_account::app::accounts::{PASSKEY, remove_credential};
    use access_identity_account::domain::claims::{Bind, Content};
    use access_identity_account::ports::{AccountDb, AccountTx};
    use access_kernel::claim::body::{AuthMethod, Body};

    let e = env(0x41, "is-claims").await;
    let alice = e.account("alice@example.com").await;
    let cookie = sign_in(&e, "alice@example.com").await;
    let orders = claim_orders(&e, |o| o.len() >= 3).await;
    let login = orders.iter().find(|o| o.class == "authentication").unwrap();
    assert_eq!(login.subject, alice);
    assert!(matches!(login.bind, Bind::Session(_)));
    assert_eq!(login.assurance.get("aal"), Some(&1));
    assert!(matches!(
        &login.content,
        Content::Body { body: Body::Authentication(a), disclose: true } if a.method == AuthMethod::Password
    ));
    assert_eq!(risk_names(&orders), ["new_device"]);
    assert!(orders.iter().any(|o| o.class == "account_status"));

    let mut key = Authenticator::new(Key::es256());
    let handle = register_passkey(&e, &cookie, &mut key).await;
    let mut other = Authenticator::new(Key::es256());
    other.aaguid = [0x22; 16];
    other.credential_id = vec![0xc2; 32];
    register_passkey(&e, &cookie, &mut other).await;
    let passkey = |o: &&access_identity_account::domain::claims::ClaimOrder| {
        matches!(
            &o.content,
            Content::Body { body: Body::AuthenticatorBinding(b), .. }
                if b.kind == access_kernel::claim::body::AuthenticatorKind::Passkey
        )
    };
    let orders = claim_orders(&e, |o| o.iter().filter(passkey).count() >= 2).await;
    let bindings: Vec<_> = orders.iter().filter(passkey).collect();
    assert_eq!(bindings.len(), 2);
    assert!(
        bindings
            .iter()
            .all(|b| b.bind == Bind::None && b.line.is_some())
    );
    assert!(risk_names(&orders).contains(&String::from("aaguid_change")));

    let flow = start(&e, Some("alice@example.com"), None).await;
    let first = e
        .with(async |a| {
            a.identify(&Identify {
                identifier: Some("alice@example.com"),
                ..Identify::default()
            })
            .await
        })
        .await
        .unwrap();
    drop(flow);
    let f1 = (first.handle.clone(), first.device.clone());
    signed_in(assert_passkey(&e, &f1, &first.options.passkey, &mut key, &handle).await);
    key.counter = 0;
    let again = e
        .with(async |a| {
            a.identify(&Identify {
                identifier: Some("alice@example.com"),
                ..Identify::default()
            })
            .await
        })
        .await
        .unwrap();
    let f2 = (again.handle.clone(), again.device.clone());
    let (_, s) =
        signed_in(assert_passkey(&e, &f2, &again.options.passkey, &mut key, &handle).await);
    assert_eq!(s.result.methods, [MethodClass::Passkey]);
    let orders = claim_orders(&e, |o| {
        risk_names(o).contains(&String::from("sign_count_regression"))
    })
    .await;
    assert!(risk_names(&orders).contains(&String::from("sign_count_regression")));
    let passkey_login = orders
        .iter()
        .rev()
        .find(|o| o.class == "authentication")
        .unwrap();
    assert!(matches!(
        &passkey_login.content,
        Content::Body { body: Body::Authentication(a), .. }
            if a.method == AuthMethod::Webauthn && a.webauthn.is_some_and(|w| w.aaguid == [0x11; 16]) && a.evidence.is_some()
    ));

    let pg = PgAccounts::sealed(e.db.app.clone(), e.vault.clone());
    let mut tx = pg.begin(e.tenant, e.realm).await.unwrap();
    let rows = tx.credentials(alice, PASSKEY).await.unwrap();
    tx.commit().await.unwrap();
    remove_credential(&pg, &e.realm(), alice, rows[0].id, &ADMIN)
        .await
        .unwrap();
    let orders = claim_orders(&e, |o| o.iter().any(|x| x.retract)).await;
    let removal = orders.iter().find(|o| o.retract).unwrap();
    assert_eq!(removal.class, "authenticator_binding");
    assert!(bindings.iter().any(|b| b.line == removal.line));
}

#[path = "signin/sl2.rs"]
mod sl2;
fn stored_signin(methods: &[&str], mfa: bool) -> Vec<u8> {
    use suiss_crypto::dcbor::{self, Limits, Value};
    let list = |l: &[&str]| Value::Array(l.iter().map(|s| Value::text(s)).collect());
    dcbor::encode(
        &Value::Map(vec![
            (Value::text("methods"), list(methods)),
            (Value::text("required_fields"), list(&["email"])),
            (Value::text("mfa_required"), Value::Bool(mfa)),
            (Value::text("domain_allow"), list(&[])),
            (Value::text("domain_deny"), list(&[])),
        ]),
        Limits::CEILING,
    )
    .unwrap()
}

// TN-132, Ek B 3379
#[tokio::test]
async fn a_disabled_sign_in_method_is_neither_offered_nor_accepted() {
    use access_identity_session::app::STEP_NOT_ALLOWED;
    use access_identity_session::domain::realm_policy::RealmSignin;
    let mut e = env(60, "is-policy").await;
    e.policy = RealmSignin::decode(&stored_signin(&["passkey"], false))
        .unwrap()
        .apply(AuthPolicy::DEFAULT);
    e.account("alice@example.com").await;
    let started = e
        .with(async |a| {
            a.identify(&Identify {
                identifier: Some("alice@example.com"),
                ..Identify::default()
            })
            .await
        })
        .await
        .unwrap();
    assert!(!started.options.password && started.options.passkey_offered);
    assert!(!started.options.email_code && !started.options.magic_link);
    let flow = (started.handle, started.device);
    let step = password(&e, &flow, "alice@example.com", PW).await;
    assert!(
        matches!(step, Step::Rejected(Refusal { problem, .. }) if problem == STEP_NOT_ALLOWED),
        "{step:?}"
    );
    e.policy = RealmSignin::decode(&stored_signin(&["email"], false))
        .unwrap()
        .apply(AuthPolicy::DEFAULT);
    let flow = start(&e, Some("alice@example.com"), None).await;
    let r = FlowRef {
        handle: &flow.0,
        device: &flow.1,
    };
    let options = e
        .with(async |a| a.passkey_options(&r, Some("alice@example.com")).await)
        .await
        .unwrap();
    assert!(
        matches!(options, Err(Step::Rejected(Refusal { problem, .. })) if problem == STEP_NOT_ALLOWED)
    );
}

// TN-132, §12.4.2
#[tokio::test]
async fn a_stored_mfa_requirement_cannot_be_skipped() {
    use access_identity_session::domain::realm_policy::RealmSignin;
    let mut e = env(61, "is-policy-mfa").await;
    e.policy = RealmSignin::decode(&stored_signin(&["email", "passkey"], true))
        .unwrap()
        .apply(AuthPolicy::DEFAULT);
    e.account("alice@example.com").await;
    let flow = start(&e, Some("alice@example.com"), None).await;
    let step = password(&e, &flow, "alice@example.com", PW).await;
    assert!(
        matches!(step, Step::Continue { ref needs, .. } if needs == &[Requirement::EnrollSecondFactor])
    );
}

// OP-64 (S-4)
#[test]
fn password_steps_do_not_print_the_password() {
    let step = access_identity_session::app::signin::PasswordStep {
        identifier: "ada@example.com",
        password: "correct horse battery staple",
        ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        correlation: "req-1",
    };
    let printed = format!("{step:?}");
    for secret in ["correct horse", "ada@example.com", "198.51.100.7"] {
        assert!(!printed.contains(secret), "{printed}");
    }
    assert!(printed.contains("req-1"));
}

/// Makes `org_party`'s organization with `owner` as its owner and `member` as a break-glass
/// member (OP-157 m.3 (h)).
async fn breakglass_org(e: &Env, org_party: [u8; 16], owner: [u8; 16], member: [u8; 16]) {
    use access_store::orgs::Source;
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let org = tx
        .insert_org(org_party, "Acme Security", &[4; 32])
        .await
        .unwrap();
    tx.insert_membership(org, owner, Source::Founder, true, None)
        .await
        .unwrap();
    tx.insert_membership(org, member, Source::Invite, false, None)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    access_store::testing::mark_breakglass(&e.db, member)
        .await
        .unwrap();
}

// OP-157 m.3 (h), §10.2.5, §10.2.6, §12.3.8 (4), INV-28, Ek B 5442, 5536
#[tokio::test]
async fn a_breakglass_account_signs_in_only_with_its_hardware_key_and_alarms() {
    use access_identity_session::app::BREAKGLASS_SSO_REFUSED;
    let e = env(61, "is-bg").await;
    let alice = e.account("alice@example.com").await;
    let owner = e.account("owner@example.com").await;
    let cookie = sign_in(&e, "alice@example.com").await;
    let mut key = Authenticator::new(Key::es256());
    let handle = register_passkey(&e, &cookie, &mut key).await;
    breakglass_org(&e, [0x51; 16], owner, alice).await;

    let started = e
        .with(async |a| {
            a.identify(&Identify {
                identifier: Some("alice@example.com"),
                ..Identify::default()
            })
            .await
        })
        .await
        .unwrap();
    let flow = (started.handle.clone(), started.device.clone());
    let step = password(&e, &flow, "alice@example.com", PW).await;
    assert!(matches!(step, Step::Continue { .. }), "{step:?}");
    let step = assert_passkey(&e, &flow, &started.options.passkey, &mut key, &handle).await;
    assert!(
        matches!(step, Step::Rejected(Refusal { problem, .. }) if problem == BREAKGLASS_SSO_REFUSED),
        "{step:?}"
    );

    let before = e.outbox.count();
    let started = e
        .with(async |a| {
            a.identify(&Identify {
                identifier: Some("alice@example.com"),
                ..Identify::default()
            })
            .await
        })
        .await
        .unwrap();
    let flow = (started.handle.clone(), started.device.clone());
    let challenge = b64url_decode(started.options.passkey["challenge"].as_str().unwrap()).unwrap();
    let (cdj, ad, sig) = key.assert(RP_ID, ORIGIN, &challenge);
    let id = key.credential_id.clone();
    let response = AssertionResponse {
        raw_id: &id,
        client_data_json: &cdj,
        authenticator_data: &ad,
        signature: &sig,
        user_handle: None,
    };
    let done = e
        .with(async |a| {
            let f = flow.clone();
            a.passkey(&ref_of(&f), &response, "req").await
        })
        .await
        .unwrap();
    let (_, s) = signed_in(done);
    assert!(s.result.assurance.hardware_bound);
    let sent: Vec<[u8; 16]> = e.outbox.0.lock().unwrap()[before..]
        .iter()
        .map(|(to, _)| *to)
        .collect();
    assert!(sent.contains(&owner), "{sent:?}");

    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let events: Vec<String> = tx
        .audit_page(None, 100)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.event_type)
        .collect();
    tx.commit().await.unwrap();
    assert!(
        events.iter().any(|t| t == "breakglass.signin_refused"),
        "{events:?}"
    );
    assert!(
        events.iter().any(|t| t == "breakglass.account_signin"),
        "{events:?}"
    );
    // INV-28
    assert_eq!(s.result.ct, CtCeiling::Ct3);
}
