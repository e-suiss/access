//! Accounts, passwords and login throttling on a real PostgreSQL (TN-49, TN-50, TN-68,
//! TN-82, CR-36, CR-37, SA-30, IDP-3, OP-35, OP-145).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_identity_account::AccountError;
use access_identity_account::adapters::hibp::{LiveRanges, MirrorRanges};
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::SystemEntropy;
use access_identity_account::app::accounts::{
    Deactivated, PASSWORD, PasswordServices, change_status, create, deactivate, remove_credential,
    set_password,
};
use access_identity_account::app::hasher::{Hasher, HasherConfig};
use access_identity_account::app::local::LocalLimiter;
use access_identity_account::app::login::{
    Attempt, LoginGate, LoginServices, clear_account, password_login,
};
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::login::{PasswordLogin, REJECTED};
use access_identity_account::domain::password::{Argon2Params, PasswordRejected};
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::domain::throttle::ThrottlePolicy;
use access_identity_account::ports::{BreachRanges, Clock, RangeUnavailable};
use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};

struct TestClock(AtomicU64);

impl TestClock {
    fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};

const RANGE_21BD1: &str =
    "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n2DC183F740EE76F27B78EB39C8AD972A757:52579\r\n";

/// The corpus with one listed password, "P@ssw0rd"; every other range is empty.
struct Corpus;

impl BreachRanges for Corpus {
    fn range(&self, prefix: &str) -> impl Future<Output = Result<String, RangeUnavailable>> + Send {
        let body = if prefix == "21BD1" { RANGE_21BD1 } else { "" };
        std::future::ready(Ok(body.to_owned()))
    }
}

struct Env {
    db: TestDb,
    tenant: TenantId,
    realm: RealmId,
    kek: SoftKek,
    ids: IdKey,
    clock: TestClock,
    hasher: Hasher,
    gate: LoginGate,
    ranges: Corpus,
}

impl Env {
    fn realm(&self) -> Realm<'_> {
        Realm {
            tenant: self.tenant,
            realm: self.realm,
            kek: &self.kek,
            ids: &self.ids,
        }
    }

    fn pg(&self) -> PgAccounts {
        PgAccounts(self.db.app.clone())
    }

    async fn audit_types(&self) -> Vec<String> {
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let rows = tx.list_audit(10_000).await.unwrap();
        tx.commit().await.unwrap();
        rows.into_iter().map(|r| r.event_type).collect()
    }

    async fn status(&self, subject: [u8; 16]) -> (String, i64) {
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let row = tx.subject(subject, false).await.unwrap().unwrap();
        tx.commit().await.unwrap();
        (row.status, row.session_epoch)
    }

    async fn login(&self, hasher: &Hasher, who: &str, pw: &str, ip: u8) -> PasswordLogin {
        let services = LoginServices {
            gate: &self.gate,
            clock: &self.clock,
            entropy: &SystemEntropy,
            hasher,
        };
        password_login(
            &self.pg(),
            &self.realm(),
            &services,
            &Attempt {
                identifier: who,
                password: pw,
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, ip)),
                correlation: "req_login",
            },
        )
        .await
        .unwrap()
    }

    async fn set_pw(
        &self,
        hasher: &Hasher,
        subject: [u8; 16],
        pw: &str,
    ) -> Result<[u8; 16], AccountError> {
        let services = PasswordServices {
            hasher,
            ranges: &self.ranges,
            entropy: &SystemEntropy,
        };
        set_password(&self.pg(), &self.realm(), &services, subject, pw, &ADMIN).await
    }

    /// An active account named `who` with password `pw`.
    async fn active(&self, who: &str, pw: &str) -> [u8; 16] {
        let id = Identifier::new(IdentifierKind::Email, who).unwrap();
        let s = create(&self.pg(), &self.realm(), &[id], &ADMIN)
            .await
            .unwrap();
        self.set_pw(&self.hasher, s, pw).await.unwrap();
        for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
            change_status(&self.pg(), &self.realm(), s, to, &ADMIN)
                .await
                .unwrap();
        }
        s
    }
}

fn ranges_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "access-hibp-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("21BD1.txt"), RANGE_21BD1).unwrap();
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
    Env {
        db,
        tenant,
        realm,
        kek: SoftKek::new("realm-kek:1", [seed; 32]),
        ids: IdKey::new(Secret::new([seed.wrapping_add(1); 32])),
        clock: TestClock(AtomicU64::new(1_800_000_000_000)),
        hasher: Hasher::new(HasherConfig::sized(Argon2Params::CANONICAL, 4, None)),
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 50),
        ranges: Corpus,
    }
}

// TN-49, CR-36, OP-145, OP-42
#[tokio::test]
async fn an_account_signs_in_with_its_password() {
    let e = env(1, "ia-a").await;
    let s = e.active("alice@example.com", "correct horse battery").await;
    let ok = e
        .login(&e.hasher, " ALICE@example.com", "correct horse battery", 1)
        .await;
    assert_eq!(
        ok,
        PasswordLogin::Accepted {
            subject: s,
            session_epoch: 0,
            rehashed: false,
            prior_failures: 0
        }
    );
    e.clock.advance(60_000);
    let bad = e
        .login(&e.hasher, "alice@example.com", "wrong horse", 1)
        .await;
    assert!(matches!(bad, PasswordLogin::Rejected { .. }));
    let types = e.audit_types().await;
    for t in [
        "account.created",
        "credential.password.set",
        "account.active",
        "login.password.succeeded",
        "login.password.failed",
    ] {
        assert!(types.iter().any(|x| x == t), "{t}");
    }
}

// TN-50, §12.3.1
#[tokio::test]
async fn deactivation_is_one_transaction_and_idempotent() {
    let e = env(2, "ia-b").await;
    let s = e.active("bob@example.com", "correct horse battery").await;
    let first = deactivate(&e.pg(), &e.realm(), s, &ADMIN).await.unwrap();
    assert_eq!(first, Deactivated::Done { session_epoch: 1 });
    assert_eq!(e.status(s).await, ("deactivated".to_owned(), 1));
    let again = deactivate(&e.pg(), &e.realm(), s, &ADMIN).await.unwrap();
    assert_eq!(again, Deactivated::AlreadyDone);
    assert_eq!(e.status(s).await, ("deactivated".to_owned(), 1));
    let n = e
        .audit_types()
        .await
        .iter()
        .filter(|t| *t == "account.deactivated")
        .count();
    assert_eq!(n, 1);
    let r = e
        .login(&e.hasher, "bob@example.com", "correct horse battery", 2)
        .await;
    assert_eq!(r.problem(), Some(REJECTED));
}

// TN-82, CR-40, CR-36, MD-18, SA-11
#[tokio::test]
async fn missing_wrong_suspended_and_deactivated_answer_alike() {
    let e = env(3, "ia-c").await;
    e.active("carol@example.com", "correct horse battery").await;
    let sus = e.active("sus@example.com", "correct horse battery").await;
    change_status(&e.pg(), &e.realm(), sus, AccountStatus::Suspended, &ADMIN)
        .await
        .unwrap();
    let off = e.active("off@example.com", "correct horse battery").await;
    deactivate(&e.pg(), &e.realm(), off, &ADMIN).await.unwrap();

    let cases = [
        ("nobody@example.com", "correct horse battery"),
        ("carol@example.com", "wrong horse battery"),
        ("sus@example.com", "correct horse battery"),
        ("off@example.com", "correct horse battery"),
    ];
    let mut first = Vec::new();
    let mut second = Vec::new();
    for (i, (who, pw)) in cases.iter().enumerate() {
        let ip = u8::try_from(10 + i).unwrap();
        first.push(e.login(&e.hasher, who, pw, ip).await);
        second.push(e.login(&e.hasher, who, pw, ip).await);
    }
    for r in &first {
        assert!(matches!(r, PasswordLogin::Rejected { .. }), "{r:?}");
        assert_eq!(r.problem(), Some(REJECTED));
    }
    for r in &second {
        assert_eq!(*r, PasswordLogin::Throttled { retry_after_s: 1 });
    }
    let failed = e
        .audit_types()
        .await
        .iter()
        .filter(|t| *t == "login.password.failed")
        .count();
    assert_eq!(failed, cases.len());
}

// SA-30, OP-35, TN-59, U46, OP-54-RL8
#[tokio::test]
async fn a_hundred_failures_lock_the_account() {
    let e = env(4, "ia-d").await;
    let s = e.active("dave@example.com", "correct horse battery").await;
    for i in 0..100_u32 {
        e.clock.advance(31_000);
        let ip = u8::try_from(i % 200 + 1).unwrap();
        let r = e
            .login(&e.hasher, "dave@example.com", "wrong horse battery", ip)
            .await;
        assert!(matches!(r, PasswordLogin::Rejected { .. }), "{i}: {r:?}");
    }
    assert_eq!(e.status(s).await.0, "locked");
    assert!(e.audit_types().await.iter().any(|t| t == "account.locked"));
    e.clock.advance(31_000);
    let r = e
        .login(&e.hasher, "dave@example.com", "correct horse battery", 250)
        .await;
    assert_eq!(r.problem(), Some(REJECTED));

    clear_account(&e.pg(), &e.clock, &e.realm(), "dave@example.com", 30)
        .await
        .unwrap();
    change_status(&e.pg(), &e.realm(), s, AccountStatus::Active, &ADMIN)
        .await
        .unwrap();
    e.clock.advance(31_000);
    let r = e
        .login(&e.hasher, "dave@example.com", "correct horse battery", 251)
        .await;
    assert!(matches!(r, PasswordLogin::Accepted { .. }), "{r:?}");
}

// CR-37
#[tokio::test]
async fn weaker_hashes_are_upgraded_on_sign_in() {
    let e = env(5, "ia-e").await;
    let weak = Hasher::new(HasherConfig::sized(
        Argon2Params {
            m_kib: 64,
            t: 1,
            p: 1,
        },
        2,
        None,
    ));
    let id = Identifier::new(IdentifierKind::Username, "erin").unwrap();
    let s = create(&e.pg(), &e.realm(), &[id], &ADMIN).await.unwrap();
    e.set_pw(&weak, s, "correct horse battery").await.unwrap();
    for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
        change_status(&e.pg(), &e.realm(), s, to, &ADMIN)
            .await
            .unwrap();
    }
    let r = e.login(&e.hasher, "erin", "correct horse battery", 1).await;
    assert!(
        matches!(r, PasswordLogin::Accepted { rehashed: true, .. }),
        "{r:?}"
    );
    e.clock.advance(60_000);
    let r = e.login(&e.hasher, "erin", "correct horse battery", 1).await;
    assert!(
        matches!(
            r,
            PasswordLogin::Accepted {
                rehashed: false,
                ..
            }
        ),
        "{r:?}"
    );
}

// CR-37, OP-150 m.3 (f), TI-9
#[tokio::test]
async fn password_hashes_are_always_peppered() {
    use access_identity_account::app::sealing::{open, seal, subject_key};
    let e = env(9, "ia-p").await;
    let s = e.active("pia@example.com", "correct horse battery").await;
    let stored = async || {
        let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
        let row = tx.subject(s, false).await.unwrap().unwrap();
        let creds = tx.credentials(s, PASSWORD).await.unwrap();
        tx.commit().await.unwrap();
        (row, creds.into_iter().next().unwrap())
    };
    let (row, cred) = stored().await;
    assert_eq!(cred.sealed.pepper_version, Some(1));
    let realm = e.realm();
    let dek = subject_key(&realm, &row).unwrap();
    assert!(
        open(&realm, &dek, &s, PASSWORD, &cred.sealed)
            .map_or(true, |p| !p.expose().starts_with("$argon2"))
    );
    let phc = e
        .hasher
        .hash(
            &access_identity_account::domain::password::Password::new("correct horse battery")
                .unwrap(),
            [7; 16],
        )
        .await
        .unwrap();
    let legacy = seal(&realm, &dek, &s, PASSWORD, phc.expose().as_bytes()).unwrap();
    assert_eq!(legacy.pepper_version, None);
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    assert!(
        tx.reseal_credential(cred.id, &cred.algorithm, &legacy)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    let r = e
        .login(&e.hasher, "pia@example.com", "correct horse battery", 1)
        .await;
    assert!(
        matches!(r, PasswordLogin::Accepted { rehashed: true, .. }),
        "{r:?}"
    );
    assert_eq!(stored().await.1.sealed.pepper_version, Some(1));
    e.clock.advance(60_000);
    let r = e
        .login(&e.hasher, "pia@example.com", "correct horse battery", 1)
        .await;
    assert!(
        matches!(
            r,
            PasswordLogin::Accepted {
                rehashed: false,
                ..
            }
        ),
        "{r:?}"
    );
}

// IDP-3, G50, OP-146
#[tokio::test]
async fn breached_or_unchecked_passwords_are_refused() {
    let e = env(6, "ia-f").await;
    let id = Identifier::new(IdentifierKind::Username, "frank").unwrap();
    let s = create(&e.pg(), &e.realm(), &[id], &ADMIN).await.unwrap();
    let err = e.set_pw(&e.hasher, s, "P@ssw0rd").await.unwrap_err();
    assert!(
        matches!(err, AccountError::Password(PasswordRejected::Breached)),
        "{err}"
    );
    let err = e.set_pw(&e.hasher, s, "short").await.unwrap_err();
    assert!(matches!(
        err,
        AccountError::Password(PasswordRejected::TooShort { .. })
    ));
    let mirror = MirrorRanges::new(ranges_dir("ia-f"));
    for (pw, breached) in [("P@ssw0rd", true), ("no range file for this one", false)] {
        let services = PasswordServices {
            hasher: &e.hasher,
            ranges: &mirror,
            entropy: &SystemEntropy,
        };
        let err = set_password(&e.pg(), &e.realm(), &services, s, pw, &ADMIN)
            .await
            .unwrap_err();
        if breached {
            assert!(matches!(
                err,
                AccountError::Password(PasswordRejected::Breached)
            ));
        } else {
            assert!(matches!(err, AccountError::BreachUnavailable), "{err}");
            let p = err.problem();
            assert_eq!((p.status, p.retry_after_s), (503, Some(1)));
        }
    }
    let services = PasswordServices {
        hasher: &e.hasher,
        ranges: &LiveRanges,
        entropy: &SystemEntropy,
    };
    let err = set_password(
        &e.pg(),
        &e.realm(),
        &services,
        s,
        "correct horse battery",
        &ADMIN,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AccountError::BreachUnavailable));
}

// TN-68, §12.3.3
#[tokio::test]
async fn the_last_method_stays() {
    let e = env(7, "ia-g").await;
    let s = e.active("gina@example.com", "correct horse battery").await;
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let creds = tx.credentials(s, PASSWORD).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(creds.len(), 1);
    let err = remove_credential(&e.pg(), &e.realm(), s, creds[0].id, &ADMIN)
        .await
        .unwrap_err();
    assert!(matches!(err, AccountError::LastMethod));
    let replaced = e
        .set_pw(&e.hasher, s, "another horse battery")
        .await
        .unwrap();
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let creds = tx.credentials(s, PASSWORD).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(creds.iter().map(|c| c.id).collect::<Vec<_>>(), [replaced]);
}

// MD-5, TN-2, E27
#[tokio::test]
async fn a_taken_identifier_creates_nothing() {
    let e = env(8, "ia-h").await;
    let a = Identifier::new(IdentifierKind::Email, "Hank@Example.com").unwrap();
    create(&e.pg(), &e.realm(), &[a], &ADMIN).await.unwrap();
    let b = Identifier::new(IdentifierKind::Username, "hank2").unwrap();
    let c = Identifier::new(IdentifierKind::Email, "hank@example.COM").unwrap();
    let err = create(&e.pg(), &e.realm(), &[b, c], &ADMIN)
        .await
        .unwrap_err();
    assert!(matches!(err, AccountError::IdentifierTaken));
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    assert!(tx.subject_by_identifier("hank2").await.unwrap().is_none());
    tx.commit().await.unwrap();
}

// CR-36, OP-33, OP-36, K14, U47
#[tokio::test]
async fn a_full_semaphore_sheds_with_503() {
    let mut config = HasherConfig::sized(Argon2Params::CANONICAL, 1, None);
    config.queue_wait = Duration::from_millis(1);
    let hasher = std::sync::Arc::new(Hasher::new(config));
    assert_eq!(hasher.config().permits, 1);
    let pw = access_identity_account::domain::password::Password::new("correct horse").unwrap();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let h = hasher.clone();
        let p = pw.clone();
        tasks.push(tokio::spawn(async move { h.hash(&p, [1; 16]).await }));
    }
    let mut busy = 0;
    for t in tasks {
        if let Err(e) = t.await.unwrap() {
            assert!(matches!(e, AccountError::Busy));
            assert_eq!(e.problem().status, 503);
            busy += 1;
        }
    }
    assert!(busy > 0);
    assert_eq!(hasher.metrics().shed(), busy);
}

// §10.2.1, CR-36, IDP-3, MD-18, OP-33, SA-31, TN-83
#[tokio::test]
async fn no_dummy_argon2_for_absent_or_inactive_accounts() {
    let e = env(4, "ia-d").await;
    e.active("dora@example.com", "correct horse battery").await;
    let sus = e.active("sus4@example.com", "correct horse battery").await;
    change_status(&e.pg(), &e.realm(), sus, AccountStatus::Suspended, &ADMIN)
        .await
        .unwrap();
    let off = e.active("off4@example.com", "correct horse battery").await;
    deactivate(&e.pg(), &e.realm(), off, &ADMIN).await.unwrap();
    let hasher = Hasher::new(HasherConfig::sized(Argon2Params::CANONICAL, 4, None));
    for (i, who) in ["nobody@example.com", "sus4@example.com", "off4@example.com"]
        .iter()
        .enumerate()
    {
        let ip = u8::try_from(40 + i).unwrap();
        let r = e.login(&hasher, who, "correct horse battery", ip).await;
        assert_eq!(r.problem(), Some(REJECTED), "{who}");
    }
    assert_eq!(hasher.metrics().hashes(), 0);
    let r = e
        .login(&hasher, "dora@example.com", "wrong horse battery", 50)
        .await;
    assert_eq!(r.problem(), Some(REJECTED));
    assert_eq!(hasher.metrics().hashes(), 1);
}
