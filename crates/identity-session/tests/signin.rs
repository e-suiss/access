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
use access_identity_session::SessionError;
use access_identity_session::adapters::OsRandom;
use access_identity_session::adapters::passkeys::PgPasskeys;
use access_identity_session::app::epochs::Epochs;
use access_identity_session::app::sessions::SessionStatus;
use access_identity_session::app::signin::{Identify, LinkOutcome, LinkPreview, PasswordStep};
use access_identity_session::app::{
    Auth, CODE_NOT_ACCEPTED, FLOW_GONE, FlowRef, Passkeys, Refusal, Step,
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
    tenant: TenantId,
    realm: RealmId,
    kek: SoftKek,
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
        let db = PgAccounts(self.db.app.clone());
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
            passkeys: Passkeys {
                registry: &registry,
                signals: &self.signals,
                decoys: &self.decoys,
                rp: &self.rp,
                policy: &self.wa_policy,
            },
        };
        f(&auth).await
    }

    fn advance(&self, ms: u64) {
        self.clock.0.fetch_add(ms, Ordering::SeqCst);
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
        tenant,
        realm,
        kek: SoftKek::new("realm-kek:1", [seed; 32]),
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
    deactivate(&PgAccounts(e.db.app.clone()), &e.realm(), gone, &ADMIN)
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

// TN-36, CR-38, TN-103, G57, EP-2, §10.1.6
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
        .with(async |a| a.step_up(&cookie, 300_000, Aal::Aal2).await)
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
    let context = e
        .with(async |a| a.auth_context(cookie, ISSUER, None).await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(context.step_up_time, Some(e.clock.now_ms()));
    assert_eq!(context.aal, Aal::Aal3);

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

// OP-149 m.6, m.8: a password session is AAL1: no device Instance; its auth_context has no
// step-up time
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
    let context = e
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
    deactivate(&PgAccounts(e.db.app.clone()), &e.realm(), alice, &ADMIN)
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

// G48, MD-8
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
    assert_eq!(err.problem().status, 503);
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
    let db = PgAccounts(e.db.app.clone());
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
