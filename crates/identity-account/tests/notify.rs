//! The Relay seam, Access side, on a real PostgreSQL (E42, OP-131, OP-146 m.4 (b), OP-73,
//! OP-74, OP-64): messages are queued in the business transaction, sealed under the subject's
//! DEK, delivered at least once in order by the courier, and wait while Relay is down.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::SystemEntropy;
use access_identity_account::app::accounts::{change_status, create};
use access_identity_account::app::{Actor, Realm, SUBJECT_PREFIX};
use access_identity_account::domain::events::OUTBOX_PREFIX as EVENT_PREFIX;
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::notify::NotifyError;
use access_identity_account::notify::courier::{CONSUMER, Courier, Step};
use access_identity_account::notify::delivery::{
    Backoff, CloudEvent, SendFailure, classify, cloud_event,
};
use access_identity_account::notify::envelope::{EventId, Header, parse, seal};
use access_identity_account::notify::http::{HttpRelay, HttpRelayConfig, RelayEndpoint};
use access_identity_account::notify::lease::{CourierLease, TTL, Term};
use access_identity_account::notify::message::{
    Address, AgentNotice, AppPasswordChange, Body, BreakglassAlarm, DegradedDependency, IysChannel,
    IysRecipient, KINDS, LinkPurpose, Message, Notice, NoticeReason, OtpPurpose, Prompt,
    SecurityEvent, SignInMethod, SupportEvent,
};
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_account::notify::pg::PgCourierStore;
use access_identity_account::notify::ports::{
    CourierStore, Notifier, RealmKeys, RelayPort, SubjectKey,
};
use access_identity_account::notify::resend::{ResendError, resend};
use access_identity_account::ports::Clock;
use access_identity_account::testing::relay::{Answer, RelayTwin, check, schema_errors};
use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{Cursor, OutboxEvent, RealmId, TenantId, TenantTx};
use access_store::relay::Undelivered;
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use serde_json::Value;
use suiss_crypto::envelope::{Dek, Kek};

const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};
const START_MS: u64 = 1_800_000_000_000;
const CODE: &str = "Q7R2K9";
const EMAIL: &str = "alice@example.com";

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct Keys(Arc<SoftKek>);

impl RealmKeys for Keys {
    fn kek(
        &self,
        _tenant: TenantId,
        _realm: RealmId,
        kek_id: &str,
    ) -> Option<Arc<dyn Kek + Send + Sync>> {
        (self.0.id() == kek_id).then(|| self.0.clone() as Arc<dyn Kek + Send + Sync>)
    }
}

/// Relay's double: answers from a script (then accepts), deduplicates by id like Relay, and
/// keeps every post it saw.
#[derive(Clone, Default)]
struct FakeRelay {
    script: Arc<Mutex<VecDeque<Result<(), SendFailure>>>>,
    posts: Arc<Mutex<Vec<(String, Value)>>>,
    accepted: Arc<Mutex<Vec<String>>>,
}

impl FakeRelay {
    fn answer(&self, r: Result<(), SendFailure>) {
        self.script.lock().unwrap().push_back(r);
    }

    fn posts(&self) -> Vec<(String, Value)> {
        self.posts.lock().unwrap().clone()
    }

    fn accepted(&self) -> Vec<String> {
        self.accepted.lock().unwrap().clone()
    }
}

impl FakeRelay {
    fn take(&self, event: &CloudEvent) -> Result<(), SendFailure> {
        let v: Value = serde_json::from_slice(event.body()).unwrap();
        let id = event.id.to_string();
        self.posts.lock().unwrap().push((id.clone(), v));
        let r = self.script.lock().unwrap().pop_front().unwrap_or(Ok(()));
        if r.is_ok() {
            let mut a = self.accepted.lock().unwrap();
            if a.contains(&id) {
                return classify(409, None);
            }
            a.push(id);
        }
        r
    }
}

impl RelayPort for FakeRelay {
    fn send(&self, event: &CloudEvent) -> impl Future<Output = Result<(), SendFailure>> + Send {
        std::future::ready(self.take(event))
    }
}

/// The real store, with an acknowledgement that can be made to fail once (a crash between
/// Relay's acceptance and the cursor write).
struct Store {
    pg: PgCourierStore,
    fail_ack: AtomicBool,
}

impl CourierStore for Store {
    async fn lease(
        &self,
        holder: &str,
        ttl: Duration,
    ) -> Result<Option<CourierLease>, NotifyError> {
        self.pg.lease(holder, ttl).await
    }

    async fn release(&self, lease: &CourierLease) -> Result<(), NotifyError> {
        self.pg.release(lease).await
    }

    async fn cursor(&self) -> Result<Cursor, NotifyError> {
        self.pg.cursor().await
    }

    async fn lag_ms(&self) -> Result<Option<u64>, NotifyError> {
        self.pg.lag_ms().await
    }

    async fn poll(&self, after: Cursor, limit: u32) -> Result<Vec<OutboxEvent>, NotifyError> {
        self.pg.poll(after, limit).await
    }

    async fn ack(&self, lease: &CourierLease, at: Cursor) -> Result<(), NotifyError> {
        if self.fail_ack.swap(false, Ordering::SeqCst) {
            return Err(NotifyError::Store(access_store::StoreError::Range));
        }
        self.pg.ack(lease, at).await
    }

    async fn subject_key(
        &self,
        tenant: TenantId,
        realm: RealmId,
        subject: [u8; 16],
    ) -> Result<SubjectKey, NotifyError> {
        self.pg.subject_key(tenant, realm, subject).await
    }

    async fn undelivered(
        &self,
        tenant: TenantId,
        realm: RealmId,
        record: &Undelivered<'_>,
    ) -> Result<(), NotifyError> {
        self.pg.undelivered(tenant, realm, record).await
    }
}

type TestCourier = Courier<Store, FakeRelay, Keys, TestClock>;

struct Env {
    db: TestDb,
    tenant: TenantId,
    realm: RealmId,
    kek: SoftKek,
    vault: access_identity_account::app::vault::Vault,
    ids: IdKey,
    clock: TestClock,
    relay: FakeRelay,
    courier: TestCourier,
    term: Term,
    seed: u8,
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
    let clock = TestClock(Arc::new(AtomicU64::new(START_MS)));
    let relay = FakeRelay::default();
    let courier = Courier::new(
        Store {
            pg: PgCourierStore {
                reader: db.reader.clone(),
                app: db.app.clone(),
            },
            fail_ack: AtomicBool::new(false),
        },
        relay.clone(),
        Keys(Arc::new(SoftKek::new("realm-kek:1", [seed; 32]))),
        clock.clone(),
        IdKey::new(Secret::new([seed.wrapping_add(1); 32])),
        Backoff::default(),
    );
    let term = courier.hold("node-a", TTL).await.unwrap().unwrap();
    Env {
        db,
        tenant,
        realm,
        kek: SoftKek::new("realm-kek:1", [seed; 32]),
        vault: access_identity_account::app::vault::Vault::in_memory(
            std::sync::Arc::new(SoftKek::new("realm-kek:1", [seed; 32])),
            [seed; 32],
        ),
        ids: IdKey::new(Secret::new([seed.wrapping_add(1); 32])),
        clock,
        relay,
        courier,
        term,
        seed,
    }
}

fn otp(subject: [u8; 16], expires_at_ms: u64) -> Message {
    Message {
        subject,
        to: Address::Email(EMAIL.to_owned()),
        locale: Some("tr-TR".to_owned()),
        valid_since_ms: Some(START_MS - 86_400_000),
        body: Body::Otp {
            code: Secret::new(CODE.to_owned()),
            purpose: OtpPurpose::SignIn,
            expires_at_ms,
        },
    }
}

fn notice(subject: [u8; 16], at_ms: u64) -> Message {
    Message {
        subject,
        to: Address::Email(EMAIL.to_owned()),
        locale: None,
        valid_since_ms: Some(START_MS - 86_400_000),
        body: Body::NewSignIn {
            at_ms,
            method: SignInMethod::Passkey,
        },
    }
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

    async fn subject(&self, who: &str) -> [u8; 16] {
        let id = Identifier::new(IdentifierKind::Email, who).unwrap();
        let s = create(
            &PgAccounts::sealed(self.db.app.clone(), self.vault.clone()),
            &self.realm(),
            &[id],
            &ADMIN,
        )
        .await
        .unwrap();
        // OP-151 m.3 (i)
        let deadline = Instant::now() + Duration::from_secs(20);
        while access_store::identity::poll(&self.db.reader, Cursor::default(), 1_000)
            .await
            .unwrap()
            .is_empty()
        {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let term = self.courier.hold("node-a", TTL).await.unwrap().unwrap();
        self.courier.step(&term).await.unwrap();
        s
    }

    /// Queues `m` together with a business change (a session epoch bump) and commits.
    async fn queue(&self, m: &Message) -> EventId {
        let realm = self.realm();
        let notifier = OutboxNotifier::new(&realm, &SystemEntropy, &self.clock);
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        tx.end_sessions(m.subject).await.unwrap();
        let id = notifier.notify(&mut tx, m).await.unwrap();
        tx.commit().await.unwrap();
        id
    }

    async fn epoch(&self, s: [u8; 16]) -> i64 {
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let row = tx.subject(s, false).await.unwrap().unwrap();
        tx.commit().await.unwrap();
        row.session_epoch
    }

    /// The outbox once at least `n` rows are visible past the watermark.
    async fn outbox_rows(&self, n: usize) -> Vec<(String, Vec<u8>)> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let rows: Vec<_> =
                access_store::identity::poll(&self.db.reader, Cursor::default(), 1_000)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|e| (e.kind, e.payload))
                    .filter(|(kind, _)| !kind.starts_with(EVENT_PREFIX))
                    .collect();
            if rows.len() >= n {
                return rows;
            }
            assert!(Instant::now() < deadline, "{} of {n} rows", rows.len());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn undelivered(&self) -> Vec<(String, String, Option<u16>)> {
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let rows = tx.list_relay_undelivered(100).await.unwrap();
        tx.commit().await.unwrap();
        rows.into_iter()
            .map(|r| (r.kind, r.reason, r.relay_status))
            .collect()
    }

    /// Steps until `n` events are handled. The watermark is cluster-wide, so a writing
    /// transaction of another test delays delivery, never loses it.
    async fn settle(&self, n: u32) -> Step {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut total = Step::default();
        loop {
            let term = self.courier.hold("node-a", TTL).await.unwrap().unwrap();
            let s = self.courier.step(&term).await.unwrap();
            total.delivered += s.delivered;
            total.undelivered += s.undelivered;
            total.skipped += s.skipped;
            total.wait_ms = s.wait_ms;
            if s.wait_ms.is_some() || total.delivered + total.undelivered + total.skipped >= n {
                return total;
            }
            assert!(Instant::now() < deadline, "{total:?} of {n} after 20 s");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

// E42, OP-10, OP-131, OP-146 m.4 (b)
#[tokio::test]
async fn a_committed_message_reaches_relay_as_a_cloud_event() {
    let e = env(1, "rn-a").await;
    let s = e.subject(EMAIL).await;
    let id = e.queue(&otp(s, START_MS + 300_000)).await;
    assert_eq!(e.epoch(s).await, 1, "the business change committed with it");

    let step = e.settle(1).await;
    assert_eq!(step.delivered, 1);
    let posts = e.relay.posts();
    assert_eq!(posts.len(), 1);
    let (pid, ce) = &posts[0];
    assert_eq!(pid, &id.to_string());
    assert_eq!(ce["specversion"], "1.0");
    assert_eq!(ce["id"], id.to_string());
    assert_eq!(ce["type"], "relay.message.otp.v1");
    assert_eq!(ce["subject"], e.ids.encode(SUBJECT_PREFIX, s).unwrap());
    assert_eq!(ce["time"], "2027-01-15T08:00:00.000Z");
    assert_eq!(ce["data"]["recipient"]["email"], EMAIL);
    assert_eq!(ce["data"]["code"], CODE);
    assert_eq!(ce["data"]["purpose"], "sign_in");
    assert_eq!(ce["data"]["locale"], "tr-TR");
    assert_eq!(ce["data"]["expires_at"], "2027-01-15T08:05:00.000Z");

    assert_eq!(
        e.settle(0).await,
        Step::default(),
        "the cursor moved past it"
    );
    assert_eq!(e.relay.posts().len(), 1);
}

// OP-10, E42
#[tokio::test]
async fn a_rolled_back_message_is_never_sent() {
    let e = env(2, "rn-b").await;
    let s = e.subject(EMAIL).await;
    let realm = e.realm();
    let notifier = OutboxNotifier::new(&realm, &SystemEntropy, &e.clock);
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    tx.end_sessions(s).await.unwrap();
    notifier
        .notify(&mut tx, &otp(s, START_MS + 300_000))
        .await
        .unwrap();
    tx.rollback().await.unwrap();

    assert_eq!(e.epoch(s).await, 0);
    e.queue(&notice(s, START_MS)).await;
    let step = e.settle(1).await;
    assert_eq!(step.delivered, 1);
    let posts = e.relay.posts();
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].1["type"], "relay.message.new_sign_in.v1");
    assert_eq!(
        e.outbox_rows(1).await.len(),
        1,
        "the rolled-back message is not there"
    );
}

// E42 m.5, OP-131
#[tokio::test]
async fn messages_wait_in_the_outbox_while_relay_is_down() {
    let e = env(3, "rn-c").await;
    let s = e.subject(EMAIL).await;
    e.queue(&notice(s, START_MS)).await;
    let down = Err(SendFailure::Transient {
        retry_after_ms: None,
    });
    for _ in 0..3 {
        e.relay.answer(down);
    }
    let mut waits = Vec::new();
    for _ in 0..3 {
        let step = e.settle(1).await;
        assert_eq!(step.delivered, 0);
        waits.push(step.wait_ms.unwrap());
    }
    assert_eq!(waits, [1_000, 2_000, 4_000]);
    e.relay.answer(Err(SendFailure::Transient {
        retry_after_ms: Some(30_000),
    }));
    assert_eq!(e.settle(1).await.wait_ms, Some(30_000), "Retry-After wins");

    let step = e.settle(1).await;
    assert_eq!(step.delivered, 1);
    let posts = e.relay.posts();
    assert_eq!(posts.len(), 5);
    assert!(
        posts.iter().all(|(id, _)| id == &posts[0].0),
        "one event id on every attempt"
    );
    assert_eq!(e.relay.accepted().len(), 1);
}

// OP-131, OP-63
#[tokio::test]
async fn redelivery_after_a_lost_acknowledgement_carries_the_same_id() {
    let e = env(4, "rn-d").await;
    let s = e.subject(EMAIL).await;
    e.queue(&otp(s, START_MS + 300_000)).await;
    e.fail_ack_once();
    let deadline = Instant::now() + Duration::from_secs(20);
    let term = e.courier.hold("node-a", TTL).await.unwrap().unwrap();
    while e.courier.step(&term).await.is_ok() {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        e.relay.accepted().len(),
        1,
        "Relay took it, the cursor did not move"
    );
    let step = e.settle(1).await;
    assert_eq!(step.delivered, 1);
    let posts = e.relay.posts();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0].0, posts[1].0);
    assert_eq!(posts[0].1, posts[1].1);
    assert_eq!(e.relay.accepted().len(), 1, "Relay took it once");
    assert_eq!(e.settle(0).await, Step::default());
}

impl Env {
    fn fail_ack_once(&self) {
        self.courier.store().fail_ack.store(true, Ordering::SeqCst);
    }
}

// OP-131, E42 m.5
#[tokio::test]
async fn messages_keep_their_commit_order() {
    let e = env(5, "rn-e").await;
    let s = e.subject(EMAIL).await;
    let t = e.subject("bob@example.com").await;
    let mut ids = Vec::new();
    for i in 0..3 {
        ids.push(e.queue(&notice(s, START_MS + i)).await);
        ids.push(e.queue(&notice(t, START_MS + i)).await);
    }
    e.relay.answer(Ok(()));
    e.relay.answer(Err(SendFailure::Transient {
        retry_after_ms: None,
    }));
    let first = e.settle(6).await;
    assert_eq!((first.delivered, first.wait_ms), (1, Some(1_000)));
    let rest = e.settle(5).await;
    assert_eq!(rest.delivered, 5);
    let order: Vec<String> = e.relay.accepted();
    let want: Vec<String> = ids.iter().map(ToString::to_string).collect();
    assert_eq!(order, want);
}

// OP-73, OP-131
#[tokio::test]
async fn a_poison_message_is_recorded_and_passed_without_loss() {
    let e = env(6, "rn-f").await;
    let s = e.subject(EMAIL).await;
    let bad = e.queue(&notice(s, START_MS)).await;
    e.queue(&notice(s, START_MS + 1)).await;
    e.relay.answer(Err(SendFailure::Rejected { status: 422 }));

    let step = e.settle(2).await;
    assert_eq!((step.undelivered, step.delivered), (1, 1));
    assert_eq!(
        e.undelivered().await,
        [(
            "relay.message.new_sign_in.v1".to_owned(),
            "rejected".to_owned(),
            Some(422)
        )]
    );
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    assert_eq!(
        tx.list_relay_undelivered(10).await.unwrap()[0].event_id,
        bad.0
    );
    tx.commit().await.unwrap();
    assert_eq!(e.outbox_rows(2).await.len(), 2, "nothing left the outbox");
}

// E42 m.5
#[tokio::test]
async fn an_expired_code_is_not_sent() {
    let e = env(7, "rn-g").await;
    let s = e.subject(EMAIL).await;
    e.queue(&otp(s, START_MS + 300_000)).await;
    e.clock.0.store(START_MS + 300_000, Ordering::SeqCst);
    let step = e.settle(1).await;
    assert_eq!(step.undelivered, 1);
    assert_eq!(e.relay.posts().len(), 0);
    assert_eq!(e.undelivered().await[0].1, "expired");
}

// OP-73, OP-74 m.6
#[tokio::test]
async fn a_shredded_subject_gets_nothing() {
    let e = env(8, "rn-h").await;
    let s = e.subject(EMAIL).await;
    e.queue(&notice(s, START_MS)).await;
    let pg = PgAccounts::sealed(e.db.app.clone(), e.vault.clone());
    for to in [
        AccountStatus::Deactivated,
        AccountStatus::Tombstone,
        AccountStatus::Purging,
    ] {
        change_status(&pg, &e.realm(), s, to, &ADMIN).await.unwrap();
    }
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    assert!(tx.shred_subject_for_test(s).await.unwrap());
    tx.commit().await.unwrap();

    let step = e.settle(1).await;
    assert_eq!(step.undelivered, 1);
    assert_eq!(e.relay.posts().len(), 0);
    assert_eq!(e.undelivered().await[0].1, "shredded");
}

// OP-131
#[tokio::test]
async fn other_outbox_kinds_are_skipped() {
    let e = env(9, "rn-i").await;
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    tx.outbox("session.revoked", b"x").await.unwrap();
    tx.commit().await.unwrap();
    let step = e.settle(1).await;
    assert_eq!(step.skipped, 1);
    assert_eq!(e.relay.posts().len(), 0);
    let c = access_store::identity::cursor(&e.db.reader, CONSUMER)
        .await
        .unwrap();
    assert_ne!(c, Cursor::default());
}

// OP-12
#[tokio::test]
async fn a_message_needs_a_subject_of_the_realm() {
    let e = env(10, "rn-j").await;
    let realm = e.realm();
    let notifier = OutboxNotifier::new(&realm, &SystemEntropy, &e.clock);
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let r = notifier.notify(&mut tx, &otp([9; 16], START_MS + 1)).await;
    assert!(matches!(r, Err(NotifyError::NoSubject)));
    tx.rollback().await.unwrap();
}

// OP-64, OP-74 m.6, E42
#[tokio::test]
async fn secrets_and_addresses_never_show() {
    let e = env(11, "rn-k").await;
    let s = e.subject(EMAIL).await;
    let m = otp(s, START_MS + 300_000);
    let printed = format!("{m:?}");
    assert!(
        !printed.contains(CODE) && !printed.contains(EMAIL),
        "{printed}"
    );
    assert!(printed.contains("[redacted]"));
    let link = Message {
        subject: s,
        to: Address::Phone("+905551112233".to_owned()),
        locale: None,
        valid_since_ms: None,
        body: Body::MagicLink {
            link: Secret::new("https://id.example/l/abc".to_owned()),
            expires_at_ms: START_MS + 1,
        },
    };
    let printed = format!("{link:?}");
    assert!(
        !printed.contains("abc") && !printed.contains("5551112233"),
        "{printed}"
    );

    e.queue(&m).await;
    let rows = e.outbox_rows(1).await;
    assert_eq!(rows.len(), 1);
    let (kind, payload) = &rows[0];
    assert_eq!(kind, "relay.message.otp.v1");
    let needle = |n: &[u8]| payload.windows(n.len()).any(|w| w == n);
    assert!(!needle(CODE.as_bytes()) && !needle(EMAIL.as_bytes()) && !needle(b"example"));

    let header = Header {
        tenant: [1; 16],
        realm: [2; 16],
        event: EventId::from_random([3; 16]),
        subject: s,
        occurred_ms: START_MS,
    };
    let ce = cloud_event(&header, "usr_x", &m).unwrap();
    let printed = format!("{ce:?}");
    assert!(
        !printed.contains(CODE) && !printed.contains(EMAIL),
        "{printed}"
    );
}

// OP-74 m.6
#[test]
fn the_envelope_is_bound_to_its_header_and_key() {
    let s = [7; 16];
    let header = Header {
        tenant: [1; 16],
        realm: [2; 16],
        event: EventId::from_random([3; 16]),
        subject: s,
        occurred_ms: START_MS,
    };
    let dek = Dek::generate().unwrap();
    let m = otp(s, START_MS + 1);
    let sealed = seal(&header, &dek, &m).unwrap();
    let env = parse(&sealed).unwrap();
    assert_eq!(env.header, header);
    let back = env.open("relay.message.otp.v1", &dek).unwrap();
    assert!(matches!(back.body, Body::Otp { ref code, .. } if code.expose() == CODE));
    assert_eq!(back.to, Address::Email(EMAIL.to_owned()));

    assert!(
        env.open("relay.message.otp.v1", &Dek::generate().unwrap())
            .is_err()
    );
    assert!(env.open("relay.message.magic_link.v1", &dek).is_err());
    for i in [1, 20, 60, sealed.len() - 1] {
        let mut t = sealed.clone();
        t[i] ^= 1;
        let opened = parse(&t).and_then(|p| p.open("relay.message.otp.v1", &dek));
        assert!(opened.is_err(), "byte {i}");
    }
    assert!(parse(&sealed[..40]).is_err());
}

// OP-146 m.4 (b)
#[test]
fn the_contract_validates_its_fields() {
    let mut m = otp([1; 16], 1);
    assert!(m.validate().is_ok());
    m.to = Address::Email("no-at-sign".to_owned());
    assert!(m.validate().is_err());
    m.to = Address::Phone("05551112233".to_owned());
    assert!(m.validate().is_err());
    m.to = Address::Phone("+905551112233".to_owned());
    // OP-153 m.9 (d)
    assert!(m.validate().is_err());
    m.valid_since_ms = None;
    assert!(m.validate().is_ok());
    m.to = Address::Email("a@example.com".to_owned());
    assert!(m.validate().is_err());
    m.to = Address::Phone("+905551112233".to_owned());
    m.locale = Some("tr TR".to_owned());
    assert!(m.validate().is_err());
    m.locale = None;
    m.body = Body::Otp {
        code: Secret::new("12\r\n34".to_owned()),
        purpose: OtpPurpose::Recovery,
        expires_at_ms: 1,
    };
    assert!(m.validate().is_err());
    m.body = Body::MagicLink {
        link: Secret::new("http://id.example/l".to_owned()),
        expires_at_ms: 1,
    };
    assert!(m.validate().is_err());
}

// OP-155 m.3 (l), E42
#[test]
fn a_ciba_invite_carries_a_short_binding_message_and_no_intent() {
    let invite = |binding: Option<&str>| Message {
        subject: [1; 16],
        to: Address::Phone("+905551112233".to_owned()),
        locale: None,
        valid_since_ms: None,
        body: Body::CibaInvite {
            link: Secret::new("https://id.example/a/abc".to_owned()),
            client: "Bank".to_owned(),
            binding_message: binding.map(str::to_owned),
            expires_at_ms: 1,
        },
    };
    assert!(invite(None).validate().is_ok());
    assert!(invite(Some(&"ç".repeat(32))).validate().is_ok());
    assert!(invite(Some(&"x".repeat(33))).validate().is_err());
    assert!(invite(Some("a\u{7}b")).validate().is_err());
    assert!(invite(Some("")).validate().is_err());
    let printed = format!("{:?}", invite(Some("K7-42")));
    assert!(
        !printed.contains("K7-42") && !printed.contains("Bank"),
        "{printed}"
    );
    assert_eq!(invite(None).body.kind(), "relay.message.ciba_invite.v1");
}

fn random_hex<const N: usize>() -> String {
    access_crypto::random::bytes::<N>()
        .unwrap()
        .iter()
        .fold(String::new(), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn sms_code() -> String {
    access_crypto::random::bytes::<6>()
        .unwrap()
        .iter()
        .map(|b| char::from(b'0' + b % 10))
        .collect()
}

fn device() -> Address {
    Address::Device("A".repeat(43))
}

fn stage11_messages(s: [u8; 16]) -> Vec<Message> {
    let email = || Address::Email(EMAIL.to_owned());
    let since = Some(START_MS - 86_400_000);
    vec![
        Message {
            subject: s,
            to: device(),
            locale: None,
            valid_since_ms: None,
            body: Body::PushApproval {
                challenge: Secret::new(random_hex::<32>()),
                application: "Acme Wiki".to_owned(),
                action: "Sign in".to_owned(),
                location: Some("Istanbul, TR".to_owned()),
                expires_at_ms: START_MS + 120_000,
            },
        },
        Message {
            subject: s,
            to: email(),
            locale: None,
            valid_since_ms: since,
            body: Body::SemanticNotice {
                reason: NoticeReason::ApproverNeeded,
                intent: random_hex::<32>(),
                link: Secret::new("https://id.example/a/abc".to_owned()),
                until_ms: Some(START_MS + 1),
            },
        },
        Message {
            subject: s,
            to: email(),
            locale: None,
            valid_since_ms: since,
            body: Body::SecurityAuthorityNotice {
                event: SecurityEvent::SubDelegation,
                name: "Acme Travel".to_owned(),
                review_link: Secret::new("https://id.example/r/abc".to_owned()),
                revoke_link: Some(Secret::new("https://id.example/v/abc".to_owned())),
                at_ms: START_MS,
            },
        },
        Message {
            subject: s,
            to: email(),
            locale: None,
            valid_since_ms: since,
            body: Body::PasskeySetupInvite {
                link: Secret::new("https://id.example/p/abc".to_owned()),
                organization: "Acme".to_owned(),
                expires_at_ms: START_MS + 7 * 86_400_000,
            },
        },
        Message {
            subject: s,
            to: Address::Phone("+905551112233".to_owned()),
            locale: None,
            valid_since_ms: None,
            body: Body::CriticalInterrupt {
                agent: "One".to_owned(),
                grant: random_hex::<16>(),
                summary: "Your flight leaves in 40 minutes".to_owned(),
                at_ms: START_MS,
            },
        },
        Message {
            subject: s,
            to: Address::Phone("+905551112233".to_owned()),
            locale: None,
            valid_since_ms: None,
            body: Body::SmsOtp {
                code: Secret::new(sms_code()),
                purpose: OtpPurpose::SignIn,
                expires_at_ms: START_MS + 300_000,
            },
        },
    ]
}

// OP-156 m.3 (c), (d), (f), E42
#[test]
fn push_goes_to_a_device_and_sms_codes_to_a_phone_only() {
    let mut m = stage11_messages([5; 16]);
    for one in &m {
        assert!(one.validate().is_ok(), "{one:?}");
    }
    m[0].to = Address::Email(EMAIL.to_owned());
    m[0].valid_since_ms = Some(START_MS);
    assert!(m[0].validate().is_err());
    m[5].to = Address::Email(EMAIL.to_owned());
    m[5].valid_since_ms = Some(START_MS);
    assert!(m[5].validate().is_err());
    m[3].to = device();
    m[3].valid_since_ms = None;
    assert!(m[3].validate().is_err());
    let mut short = stage11_messages([5; 16]);
    if let Body::SmsOtp { code, .. } = &mut short[5].body {
        *code = Secret::new(random_hex::<2>());
    }
    assert!(short[5].validate().is_err());
    let printed = format!("{:?}", stage11_messages([5; 16]));
    for hidden in [
        "Acme Wiki",
        "Istanbul",
        "Acme Travel",
        "id.example",
        "flight",
    ] {
        assert!(!printed.contains(hidden), "{printed}");
    }
}

// OP-131, E42 m.5
#[test]
fn relay_answers_are_classified_and_backoff_grows_to_a_ceiling() {
    assert_eq!(classify(202, None), Ok(()));
    assert_eq!(classify(409, None), Ok(()));
    assert_eq!(
        classify(422, None),
        Err(SendFailure::Rejected { status: 422 })
    );
    for s in [401, 403, 404, 408, 429, 500, 503] {
        assert!(
            matches!(classify(s, None), Err(SendFailure::Transient { .. })),
            "{s}"
        );
    }
    let b = Backoff::default();
    assert_eq!(b.wait_ms(1, None), 1_000);
    assert_eq!(b.wait_ms(9, None), 256_000);
    assert_eq!(b.wait_ms(10, None), 300_000);
    assert_eq!(b.wait_ms(u32::MAX, None), 300_000);
    assert_eq!(b.wait_ms(1, Some(10_000_000)), 300_000);
}

// OP-146 m.4 (b)
#[test]
fn every_kind_matches_the_json_schema() {
    let schema: Value =
        serde_json::from_str(include_str!("../contracts/relay-message.v1.schema.json")).unwrap();
    let listed: Vec<&str> = schema["properties"]["type"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    assert_eq!(listed, KINDS);
    let s = [4; 16];
    let to = || Address::Email(EMAIL.to_owned());
    let messages = [
        otp(s, START_MS + 1),
        Message {
            subject: s,
            to: Address::Phone("+905551112233".to_owned()),
            locale: None,
            valid_since_ms: None,
            body: Body::MagicLink {
                link: Secret::new("https://id.example/l/abc".to_owned()),
                expires_at_ms: START_MS + 1,
            },
        },
        Message {
            subject: s,
            to: to(),
            locale: None,
            valid_since_ms: Some(START_MS - 86_400_000),
            body: Body::PasswordChanged { at_ms: START_MS },
        },
        notice(s, START_MS),
        Message {
            subject: s,
            to: to(),
            locale: Some("en".to_owned()),
            valid_since_ms: None,
            body: Body::AccountStatus {
                status: AccountStatus::Suspended,
                at_ms: START_MS,
            },
        },
    ]
    .into_iter()
    .chain(Notice::ALL.into_iter().map(|notice| Message {
        subject: s,
        to: to(),
        locale: None,
        valid_since_ms: Some(START_MS - 86_400_000),
        body: Body::Notice {
            notice,
            at_ms: START_MS,
            until_ms: notice.has_until().then_some(START_MS + 86_400_000),
        },
    }))
    .chain(
        [LinkPurpose::ResetIntent, LinkPurpose::ExportReady].map(|purpose| Message {
            subject: s,
            to: to(),
            locale: None,
            valid_since_ms: Some(START_MS - 86_400_000),
            body: Body::Link {
                purpose,
                link: Secret::new("https://id.example/r/abc".to_owned()),
                expires_at_ms: START_MS + 1,
            },
        }),
    )
    .chain([Message {
        subject: s,
        to: to(),
        locale: Some("tr".to_owned()),
        valid_since_ms: Some(START_MS - 86_400_000),
        body: Body::Invitation {
            link: Secret::new("https://id.example/i/abc".to_owned()),
            organization: "Acme <a href=x>".to_owned(),
            inviter: "Ayşe".to_owned(),
            expires_at_ms: START_MS + 1,
        },
    }])
    .chain(
        [AgentNotice::Suspended, AgentNotice::SponsorNeeded].map(|notice| Message {
            subject: s,
            to: to(),
            locale: None,
            valid_since_ms: Some(START_MS - 86_400_000),
            body: Body::Agent {
                notice,
                agent: "Billing bot".to_owned(),
                at_ms: START_MS,
            },
        }),
    )
    .chain(Prompt::ALL.map(|prompt| Message {
        subject: s,
        to: to(),
        locale: None,
        valid_since_ms: Some(START_MS - 86_400_000),
        body: Body::Prompt {
            prompt,
            link: Secret::new("https://id.example/p/abc".to_owned()),
            name: "Calendar <script>".to_owned(),
            expires_at_ms: START_MS + 1,
        },
    }))
    .chain([
        Message {
            subject: s,
            to: to(),
            locale: None,
            valid_since_ms: Some(START_MS - 86_400_000),
            body: Body::CibaInvite {
                link: Secret::new("https://id.example/a/abc".to_owned()),
                client: "Bank <b>".to_owned(),
                binding_message: Some("K7-42".to_owned()),
                expires_at_ms: START_MS + 1,
            },
        },
        Message {
            subject: s,
            to: to(),
            locale: None,
            valid_since_ms: Some(START_MS - 86_400_000),
            body: Body::UpstreamSubjectConflict {
                upstream: "Acme Entra".to_owned(),
                at_ms: START_MS,
            },
        },
        Message {
            subject: s,
            to: to(),
            locale: None,
            valid_since_ms: Some(START_MS - 86_400_000),
            body: Body::LdapCredentialChanged {
                change: AppPasswordChange::Created,
                application: "Printer".to_owned(),
                at_ms: START_MS,
            },
        },
    ])
    .chain(stage11_messages(s))
    .chain(iys_messages(s))
    .chain(stage12_messages(s))
    .chain(stage13_messages(s))
    .chain(stage14_messages(s))
    .collect::<Vec<_>>();
    assert_eq!(messages.len(), KINDS.len());
    for (m, kind) in messages.iter().zip(KINDS) {
        assert_eq!(m.body.kind(), kind);
        let header = Header {
            tenant: [1; 16],
            realm: [2; 16],
            event: EventId::from_random([3; 16]),
            subject: s,
            occurred_ms: START_MS,
        };
        let ce = cloud_event(&header, "usr_x", m).unwrap();
        let v: Value = serde_json::from_slice(ce.body()).unwrap();
        let errs = check(&schema, &schema, &v, "$");
        assert!(errs.is_empty(), "{kind}: {errs:?}");
        assert_eq!(v["id"], "03030303-0303-4303-8303-030303030303");
        assert_eq!(
            v["source"],
            "urn:suiss:access:realm:02020202-0202-0202-0202-020202020202"
        );
        let mut broken = v.clone();
        broken["data"]["extra"] = Value::Bool(true);
        broken["data"].as_object_mut().unwrap().remove("recipient");
        assert_eq!(check(&schema, &schema, &broken, "$").len(), 2, "{kind}");
    }
}

struct RelayServer {
    endpoint: RelayEndpoint,
    tls: Arc<rustls::ClientConfig>,
    heads: Arc<Mutex<Vec<String>>>,
}

/// An HTTPS Relay double: answers `status` with `extra` headers and keeps request heads.
async fn relay_server(status: &'static str, extra: &'static str) -> RelayServer {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let der: CertificateDer<'static> = cert.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut s = acceptor.accept(tcp).await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0_u8; 4096];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
            }
            seen.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf).into_owned());
            let resp = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\n\r\n");
            s.write_all(resp.as_bytes()).await.unwrap();
            let _ = s.shutdown().await;
        }
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    RelayServer {
        endpoint: RelayEndpoint::parse(&format!("https://localhost:{port}/v1/events")).unwrap(),
        tls: Arc::new(tls),
        heads,
    }
}

fn token_file(tag: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let p = std::env::temp_dir().join(format!(
        "access-relay-token-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&p, "relay-test-token\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

fn sample_event() -> CloudEvent {
    let header = Header {
        tenant: [1; 16],
        realm: [2; 16],
        event: EventId::from_random([3; 16]),
        subject: [4; 16],
        occurred_ms: START_MS,
    };
    cloud_event(&header, "usr_x", &notice([4; 16], START_MS)).unwrap()
}

// E42, OP-146 m.4 (b), CR-35, OP-63
#[tokio::test]
async fn the_https_adapter_posts_and_classifies() {
    for (status, extra, want) in [
        ("202 Accepted", "", Ok(())),
        (
            "503 Service Unavailable",
            "Retry-After: 7\r\n",
            Err(SendFailure::Transient {
                retry_after_ms: Some(7_000),
            }),
        ),
        (
            "422 Unprocessable Content",
            "",
            Err(SendFailure::Rejected { status: 422 }),
        ),
    ] {
        let srv = relay_server(status, extra).await;
        let token = token_file("post");
        let relay = HttpRelay::new(HttpRelayConfig {
            endpoint: srv.endpoint.clone(),
            tls: srv.tls.clone(),
            token_file: token.clone(),
            timeout: Duration::from_secs(5),
        })
        .unwrap();
        let ev = sample_event();
        assert_eq!(relay.send(&ev).await, want, "{status}");
        std::fs::remove_file(&token).unwrap();
        let heads = srv.heads.lock().unwrap().clone();
        assert_eq!(heads.len(), 1);
        let h = &heads[0];
        assert!(h.starts_with("POST /v1/events HTTP/1.1\r\n"), "{h}");
        assert!(h.contains("Authorization: Bearer relay-test-token\r\n"));
        assert!(h.contains(&format!("Idempotency-Key: {}\r\n", ev.id)));
        assert!(h.contains("Content-Type: application/cloudevents+json; charset=utf-8\r\n"));
    }
}

/// An HTTPS Relay double that keeps each connection open and answers every request on it,
/// counting the connections it accepted.
async fn keepalive_server() -> (RelayServer, Arc<std::sync::atomic::AtomicUsize>) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let der: CertificateDer<'static> = cert.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = accepted.clone();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut s = acceptor.accept(tcp).await.unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        continue;
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    while buf.len() < end + 4 + len {
                        let n = s.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    buf.drain(..end + 4 + len);
                    seen.lock().unwrap().push(head);
                    s.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\n\r\nok")
                        .await
                        .unwrap();
                }
            });
        }
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (
        RelayServer {
            endpoint: RelayEndpoint::parse(&format!("https://localhost:{port}/v1/events")).unwrap(),
            tls: Arc::new(tls),
            heads,
        },
        accepted,
    )
}

// OP-158, OP-72, E42
#[tokio::test]
async fn the_courier_reuses_kept_alive_connections() {
    let (srv, accepted) = keepalive_server().await;
    let token = token_file("pool");
    let relay = HttpRelay::new(HttpRelayConfig {
        endpoint: srv.endpoint.clone(),
        tls: srv.tls.clone(),
        token_file: token.clone(),
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    std::fs::remove_file(&token).unwrap();
    for _ in 0..5 {
        assert_eq!(relay.send(&sample_event()).await, Ok(()));
    }
    assert_eq!(relay.connections_opened(), 1);
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(srv.heads.lock().unwrap().len(), 5);
}

// OP-158, E42 m.5
#[tokio::test]
async fn a_closed_kept_alive_connection_is_replaced() {
    let srv = relay_server("202 Accepted", "").await;
    let token = token_file("stale");
    let relay = HttpRelay::new(HttpRelayConfig {
        endpoint: srv.endpoint.clone(),
        tls: srv.tls.clone(),
        token_file: token.clone(),
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    std::fs::remove_file(&token).unwrap();
    for _ in 0..3 {
        assert_eq!(relay.send(&sample_event()).await, Ok(()));
    }
    assert_eq!(srv.heads.lock().unwrap().len(), 3);
    assert_eq!(relay.connections_opened(), 3);
}

// E42 m.5, TI-9
#[tokio::test]
async fn an_unreachable_relay_is_transient() {
    let srv = relay_server("202 Accepted", "").await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let token = token_file("down");
    let relay = HttpRelay::new(HttpRelayConfig {
        endpoint: RelayEndpoint::parse(&format!("https://localhost:{port}/e")).unwrap(),
        tls: srv.tls.clone(),
        token_file: token.clone(),
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    std::fs::remove_file(&token).unwrap();
    assert!(matches!(
        relay.send(&sample_event()).await,
        Err(SendFailure::Transient { .. })
    ));
    assert!(RelayEndpoint::parse("http://relay.internal/e").is_err());
    assert!(RelayEndpoint::parse("https://relay.internal\r\nX: y/e").is_err());
    assert!(RelayEndpoint::parse("https://relay.internal:8443/v1/events").is_ok());
}

/// A second courier over the same database, as another node would run it.
fn node(e: &Env, relay: FakeRelay) -> TestCourier {
    Courier::new(
        Store {
            pg: PgCourierStore {
                reader: e.db.reader.clone(),
                app: e.db.app.clone(),
            },
            fail_ack: AtomicBool::new(false),
        },
        relay,
        Keys(Arc::new(SoftKek::new("realm-kek:1", [e.seed; 32]))),
        e.clock.clone(),
        IdKey::new(Secret::new([e.seed.wrapping_add(1); 32])),
        Backoff::default(),
    )
}

// OP-156 m.3 (c), OP-31
#[tokio::test]
async fn only_the_lease_holder_sends_and_a_lost_lease_cannot_move_the_cursor() {
    let e = env(40, "rn-l1").await;
    let s = e.subject(EMAIL).await;
    let b_relay = FakeRelay::default();
    let b = node(&e, b_relay.clone());
    assert!(
        b.hold("node-b", TTL).await.unwrap().is_none(),
        "a live lease is not shared"
    );
    let renewed = e.courier.hold("node-a", TTL).await.unwrap().unwrap();
    assert_eq!(
        renewed.lease.epoch, e.term.lease.epoch,
        "a renewal keeps the epoch"
    );

    e.queue(&notice(s, START_MS)).await;
    e.courier.store().release(&e.term.lease).await.unwrap();
    let taken = b.hold("node-b", TTL).await.unwrap().unwrap();
    assert!(
        taken.lease.epoch > e.term.lease.epoch,
        "a new holder fences the old"
    );
    let before = access_store::identity::cursor(&e.db.reader, CONSUMER)
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match e.courier.step(&e.term).await {
            Err(NotifyError::LeaseLost) => break,
            Ok(_) => {
                assert!(Instant::now() < deadline);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(other) => panic!("{other}"),
        }
    }
    assert_eq!(
        access_store::identity::cursor(&e.db.reader, CONSUMER)
            .await
            .unwrap(),
        before,
        "the old holder's cursor write was refused"
    );
    let step = loop {
        let step = b.step(&taken).await.unwrap();
        if step.delivered > 0 {
            break step;
        }
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(step.delivered, 1);
    assert_eq!(
        e.relay.posts()[0].0,
        b_relay.posts()[0].0,
        "the new holder sends the same id, which Relay deduplicates"
    );
}

// OP-156 m.3 (c)
#[tokio::test]
async fn a_node_whose_term_ended_sends_nothing_more() {
    let e = env(41, "rn-l2").await;
    let s = e.subject(EMAIL).await;
    e.queue(&notice(s, START_MS)).await;
    let ended = Term {
        lease: e.term.lease.clone(),
        until_ms: START_MS,
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while access_store::identity::poll(&e.db.reader, Cursor::default(), 100)
        .await
        .unwrap()
        .len()
        < 2
    {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let step = e.courier.step(&ended).await.unwrap();
    assert!(step.lapsed);
    assert_eq!(step.delivered, 0);
    assert_eq!(e.relay.posts().len(), 0);
    assert!(e.term.due(START_MS + 6_000, TTL));
    assert!(!e.term.due(START_MS + 1_000, TTL));
}

// OP-156 m.3 (c)
#[tokio::test]
async fn of_two_running_nodes_only_one_sends() {
    let e = env(42, "rn-l3").await;
    let s = e.subject(EMAIL).await;
    e.courier.store().release(&e.term.lease).await.unwrap();
    let (a_relay, b_relay) = (FakeRelay::default(), FakeRelay::default());
    let a = Arc::new(node(&e, a_relay.clone()));
    let b = Arc::new(node(&e, b_relay.clone()));
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let runs = [("node-a", a.clone()), ("node-b", b.clone())].map(|(h, c)| {
        let stopped = stopped.clone();
        tokio::spawn(async move { c.run(h, &stopped).await })
    });
    for at in 0..3 {
        e.queue(&notice(s, START_MS + at)).await;
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while a_relay.accepted().len() + b_relay.accepted().len() < 3 {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop.send(true).unwrap();
    for r in runs {
        r.await.unwrap();
    }
    let (na, nb) = (a_relay.posts().len(), b_relay.posts().len());
    assert!(na == 0 || nb == 0, "both sent: {na} and {nb}");
    assert_eq!(na + nb, 3);
    let next = node(&e, FakeRelay::default());
    assert!(
        next.hold("node-c", TTL).await.unwrap().is_some(),
        "a stopped node gives its lease up"
    );
}

/// A message Relay refused for good, recorded as undeliverable; returns its id.
async fn refused(e: &Env, m: &Message) -> EventId {
    let id = e.queue(m).await;
    e.relay.answer(Err(SendFailure::Rejected { status: 422 }));
    let step = e.settle(1).await;
    assert_eq!(step.undelivered, 1);
    id
}

async fn resend_of(e: &Env, id: EventId) -> Result<EventId, ResendError> {
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let r = resend(&mut tx, &e.realm(), &SystemEntropy, &e.clock, id, &ADMIN).await;
    if r.is_ok() {
        tx.commit().await.unwrap();
    } else {
        tx.rollback().await.unwrap();
    }
    r
}

// OP-156 m.3 (c), OP-73, Ek B 5401
#[tokio::test]
async fn a_resend_writes_a_new_row_and_leaves_the_original() {
    let e = env(43, "rn-r1").await;
    let s = e.subject(EMAIL).await;
    let original = refused(&e, &otp(s, START_MS + 300_000)).await;
    let rows_before = e.outbox_rows(1).await;
    let again = resend_of(&e, original).await.unwrap();
    assert_ne!(again, original, "a new CloudEvents id, so Relay takes it");
    let step = e.settle(1).await;
    assert_eq!(step.delivered, 1);
    let posts = e.relay.posts();
    assert_eq!(posts.last().unwrap().0, again.to_string());
    assert_eq!(posts.last().unwrap().1["data"], posts[0].1["data"]);
    let rows = e.outbox_rows(2).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(
        &rows[..1],
        &rows_before[..],
        "the original row is unchanged"
    );
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    assert_eq!(tx.relay_resends_of(original.0).await.unwrap(), [again.0]);
    assert_eq!(tx.list_relay_undelivered(10).await.unwrap().len(), 1);
    tx.commit().await.unwrap();
    assert!(matches!(
        resend_of(&e, EventId::from_random([7; 16])).await,
        Err(ResendError::NotFound)
    ));
}

// OP-156 m.3 (c), OP-73
#[tokio::test]
async fn shredded_or_expired_content_is_not_resent() {
    let e = env(44, "rn-r2").await;
    let s = e.subject(EMAIL).await;
    let code = refused(&e, &otp(s, START_MS + 300_000)).await;
    let notice_id = refused(&e, &notice(s, START_MS)).await;
    e.clock.0.store(START_MS + 300_000, Ordering::SeqCst);
    assert!(matches!(
        resend_of(&e, code).await,
        Err(ResendError::Expired)
    ));
    let pg = PgAccounts::sealed(e.db.app.clone(), e.vault.clone());
    for to in [
        AccountStatus::Deactivated,
        AccountStatus::Tombstone,
        AccountStatus::Purging,
    ] {
        change_status(&pg, &e.realm(), s, to, &ADMIN).await.unwrap();
    }
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    assert!(tx.shred_subject_for_test(s).await.unwrap());
    tx.commit().await.unwrap();
    assert!(matches!(
        resend_of(&e, notice_id).await,
        Err(ResendError::Shredded)
    ));
}

// OP-156 m.3 (c)
#[tokio::test]
async fn the_lag_is_the_age_of_the_oldest_waiting_message() {
    let e = env(45, "rn-g1").await;
    let s = e.subject(EMAIL).await;
    assert_eq!(e.courier.lag_ms().await.unwrap(), None);
    e.queue(&notice(s, START_MS)).await;
    e.relay.answer(Err(SendFailure::Transient {
        retry_after_ms: None,
    }));
    assert!(e.settle(1).await.wait_ms.is_some());
    assert!(e.courier.lag_ms().await.unwrap().is_some());
    assert_eq!(e.settle(1).await.delivered, 1);
    assert_eq!(e.courier.lag_ms().await.unwrap(), None);
}

fn random_token() -> String {
    use std::fmt::Write as _;
    access_crypto::random::bytes::<16>()
        .unwrap()
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn secret_file(tag: &str, value: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let p = std::env::temp_dir().join(format!(
        "access-relay-twin-{tag}-{}-{}",
        std::process::id(),
        random_token()
    ));
    std::fs::write(&p, value).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

fn twin_relay(twin: &RelayTwin, token: &str, timeout: Duration) -> HttpRelay {
    let file = secret_file("adapter", token);
    let relay = HttpRelay::new(HttpRelayConfig {
        endpoint: RelayEndpoint::parse(&twin.events_url()).unwrap(),
        tls: twin.tls.clone(),
        token_file: file.clone(),
        timeout,
    })
    .unwrap();
    std::fs::remove_file(&file).unwrap();
    relay
}

// OP-156 m.3 (c), OP-146 m.4 (b)
#[tokio::test]
async fn the_relay_twin_validates_and_answers_like_relay() {
    let token = random_token();
    let twin = RelayTwin::start(&token, "https://id.test").await;
    let relay = twin_relay(&twin, &token, Duration::from_secs(5));
    let ev = sample_event();
    twin.script([
        Answer::Status(503, Some(7)),
        Answer::Status(429, None),
        Answer::Delay(Duration::from_millis(50)),
    ]);
    assert_eq!(
        relay.send(&ev).await,
        Err(SendFailure::Transient {
            retry_after_ms: Some(7_000)
        })
    );
    assert!(matches!(
        relay.send(&ev).await,
        Err(SendFailure::Transient { .. })
    ));
    assert_eq!(relay.send(&ev).await, Ok(()));
    assert_eq!(
        relay.send(&ev).await,
        Ok(()),
        "a duplicate id is 409, taken"
    );
    let posts = twin.posts();
    assert_eq!(
        posts.iter().map(|p| p.status).collect::<Vec<_>>(),
        [503, 429, 202, 409]
    );
    assert!(posts.iter().all(|p| p.schema_errors.is_empty()));
    assert_eq!(twin.accepted(), [ev.id.to_string()]);

    let wrong = twin_relay(&twin, &random_token(), Duration::from_secs(5));
    assert!(
        matches!(wrong.send(&ev).await, Err(SendFailure::Transient { .. })),
        "a credential Relay refuses must not cost the message"
    );
    let slow = twin_relay(&twin, &token, Duration::from_millis(50));
    twin.script([Answer::Delay(Duration::from_secs(2))]);
    let other = cloud_event(
        &Header {
            tenant: [1; 16],
            realm: [2; 16],
            event: EventId::from_random([5; 16]),
            subject: [4; 16],
            occurred_ms: START_MS,
        },
        "usr_x",
        &notice([4; 16], START_MS),
    )
    .unwrap();
    assert!(matches!(
        slow.send(&other).await,
        Err(SendFailure::Transient { .. })
    ));
    let mut bad: Value = serde_json::from_slice(ev.body()).unwrap();
    bad["data"]["extra"] = Value::Bool(true);
    assert_ne!(schema_errors(&bad), Vec::<String>::new());
    assert_eq!(twin.discovery()["events_endpoint"], twin.events_url());
}

// OP-156 m.3 (c), E42
#[tokio::test]
async fn the_courier_delivers_to_the_twin() {
    let e = env(46, "rn-t1").await;
    let s = e.subject(EMAIL).await;
    let token = random_token();
    let twin = RelayTwin::start(&token, "https://id.test").await;
    let courier = Courier::new(
        Store {
            pg: PgCourierStore {
                reader: e.db.reader.clone(),
                app: e.db.app.clone(),
            },
            fail_ack: AtomicBool::new(false),
        },
        twin_relay(&twin, &token, Duration::from_secs(5)),
        Keys(Arc::new(SoftKek::new("realm-kek:1", [e.seed; 32]))),
        e.clock.clone(),
        IdKey::new(Secret::new([e.seed.wrapping_add(1); 32])),
        Backoff::default(),
    );
    let id = e.queue(&otp(s, START_MS + 300_000)).await;
    e.queue(&notice(s, START_MS)).await;
    let deadline = Instant::now() + Duration::from_secs(20);
    while twin.accepted().len() < 2 {
        let term = courier.hold("node-a", TTL).await.unwrap().unwrap();
        courier.step(&term).await.unwrap();
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let posts = twin.posts();
    assert_eq!(posts[0].id, id.to_string());
    assert!(
        posts
            .iter()
            .all(|p| p.schema_errors.is_empty() && p.status == 202)
    );
}

fn stage12_messages(s: [u8; 16]) -> Vec<Message> {
    let email = || Address::Email(EMAIL.to_owned());
    let since = Some(START_MS - 86_400_000);
    let with = |to: Address, valid_since_ms: Option<u64>, body: Body| Message {
        subject: s,
        to,
        locale: None,
        valid_since_ms,
        body,
    };
    vec![
        with(
            email(),
            since,
            Body::SupportAccessRequest {
                organization: "Acme Support".to_owned(),
                case: "#4411".to_owned(),
                scope: "View your account settings".to_owned(),
                minutes: 60,
                link: Secret::new("https://id.example/s/abc".to_owned()),
                expires_at_ms: START_MS + 900_000,
            },
        ),
        with(
            email(),
            since,
            Body::SupportAccessNotice {
                event: SupportEvent::Granted,
                operator: "Mehmet Y.".to_owned(),
                organization: "Acme Support".to_owned(),
                case: "#4411".to_owned(),
                at_ms: START_MS,
                until_ms: Some(START_MS + 3_600_000),
            },
        ),
        with(
            email(),
            since,
            Body::BreakglassUsed {
                organization: "Acme Security".to_owned(),
                incident: "INC-7".to_owned(),
                approvals: 2,
                at_ms: START_MS,
                until_ms: START_MS + 4 * 3_600_000,
            },
        ),
        with(
            email(),
            since,
            Body::BreakglassAlarm {
                alarm: BreakglassAlarm::Signin,
                account: "Emergency 1".to_owned(),
                link: Secret::new("https://console.example/bg".to_owned()),
                at_ms: START_MS,
            },
        ),
        with(
            device(),
            None,
            Body::ApprovalInline {
                intent: random_hex::<32>(),
                render: "oWFhYWI".to_owned(),
                render_digest: random_hex::<32>(),
                expires_at_ms: START_MS + 300_000,
            },
        ),
        with(
            email(),
            since,
            Body::ReviewCampaign {
                campaign: "quarterly".to_owned(),
                items: 12,
                link: Secret::new("https://console.example/r/q".to_owned()),
                due_ms: START_MS + 14 * 86_400_000,
            },
        ),
    ]
}

// OP-157 m.3 (z), (f), (h), (m)
#[test]
fn the_stage_12_bodies_keep_their_channels_and_hide_their_names() {
    let mut m = stage12_messages([7; 16]);
    for one in &m {
        assert!(one.validate().is_ok(), "{one:?}");
    }
    m[4].to = Address::Email(EMAIL.to_owned());
    m[4].valid_since_ms = Some(START_MS);
    assert!(
        m[4].validate().is_err(),
        "an inline approval goes to a device only"
    );
    if let Body::BreakglassUsed { approvals, .. } = &mut m[2].body {
        *approvals = 1;
    }
    assert!(m[2].validate().is_err(), "break-glass needs two approvals");
    if let Body::SupportAccessNotice { event, .. } = &mut m[1].body {
        *event = SupportEvent::Revoked;
    }
    assert!(m[1].validate().is_err(), "an ended access has no end time");
    let printed = format!("{:?}", stage12_messages([7; 16]));
    for hidden in [
        "Acme",
        "Mehmet",
        "#4411",
        "INC-7",
        "id.example",
        "quarterly",
    ] {
        assert!(!printed.contains(hidden), "{printed}");
    }
}

fn stage13_messages(s: [u8; 16]) -> Vec<Message> {
    let email = || Address::Email(EMAIL.to_owned());
    let since = Some(START_MS - 86_400_000);
    let with = |body: Body| Message {
        subject: s,
        to: email(),
        locale: None,
        valid_since_ms: since,
        body,
    };
    let link = |l: &str| Secret::new(format!("https://console.example/{l}"));
    vec![
        with(Body::DomainRecovered {
            domain: "Acme Shop".to_owned(),
            position: 4_096,
            lost_after_ms: START_MS - 60_000,
            at_ms: START_MS,
            link: link("h"),
        }),
        with(Body::DomainHandover {
            domain: "Acme Shop".to_owned(),
            provider: "Northwind Cloud".to_owned(),
            position: 4_000,
            at_ms: START_MS,
            link: link("h"),
        }),
        with(Body::DivergenceNotice {
            domain: "Acme Shop".to_owned(),
            items: 2,
            from: 10,
            to: 900,
            at_ms: START_MS,
            link: link("d"),
        }),
        with(Body::EquivocationAlarm {
            domain: "Acme Shop".to_owned(),
            witness: "witness.northwind".to_owned(),
            size: 77,
            at_ms: START_MS,
            link: link("e"),
        }),
        with(Body::DegradedAlarm {
            dependency: DegradedDependency::Witness,
            since_ms: START_MS,
            link: link("s"),
        }),
        with(Body::DecommissionNotice {
            domain: "Acme Shop".to_owned(),
            closes_at_ms: START_MS + 90 * 86_400_000,
            link: link("x"),
        }),
    ]
}

// OP-158 m.3 (bb)
#[test]
fn the_stage_13_bodies_validate_and_hide_their_names() {
    let mut m = stage13_messages([7; 16]);
    for one in &m {
        assert!(one.validate().is_ok(), "{one:?}");
    }
    if let Body::DivergenceNotice { items, .. } = &mut m[2].body {
        *items = 0;
    }
    assert!(
        m[2].validate().is_err(),
        "a divergence names at least one record"
    );
    m[4].to = Address::Device("A".repeat(43));
    m[4].valid_since_ms = None;
    assert!(m[4].validate().is_err(), "an alarm is not a device push");
    let printed = format!("{:?}", stage13_messages([7; 16]));
    for hidden in ["Acme", "Northwind", "console.example"] {
        assert!(!printed.contains(hidden), "{printed}");
    }
}

fn stage14_messages(s: [u8; 16]) -> Vec<Message> {
    vec![Message {
        subject: s,
        to: Address::Email(EMAIL.to_owned()),
        locale: None,
        valid_since_ms: Some(START_MS - 86_400_000),
        body: Body::AlgorithmRetired {
            domain: "Acme Shop".to_owned(),
            algorithm: "EdDSA".to_owned(),
            reanchor_size: 4_096,
            at_ms: START_MS,
            link: Secret::new("https://console.example/signing".to_owned()),
        },
    }]
}

// OP-159 m.3 (f), (oo)
#[test]
fn the_stage_14_body_validates_and_hides_its_names() {
    let mut m = stage14_messages([7; 16]);
    assert!(m[0].validate().is_ok(), "{:?}", m[0]);
    let printed = format!("{m:?}");
    for hidden in ["Acme", "EdDSA", "console.example"] {
        assert!(!printed.contains(hidden), "{printed}");
    }
    if let Body::AlgorithmRetired { algorithm, .. } = &mut m[0].body {
        algorithm.clear();
    }
    assert!(m[0].validate().is_err(), "a retirement names its algorithm");
}

fn iys_messages(s: [u8; 16]) -> [Message; 1] {
    [Message {
        subject: s,
        to: Address::Phone("+905551112233".to_owned()),
        locale: None,
        valid_since_ms: None,
        body: Body::IysConsent {
            channel: IysChannel::Sms,
            recipient_type: IysRecipient::Individual,
            approved: true,
            source: "self_service".to_owned(),
            consent_at_ms: START_MS,
        },
    }]
}

// IDP-37 (4), B23, OP-156 m.3 (c)
#[test]
fn an_iys_record_goes_to_the_address_its_channel_names() {
    let [mut m] = iys_messages([6; 16]);
    assert!(m.validate().is_ok());
    m.to = Address::Email(EMAIL.to_owned());
    m.valid_since_ms = Some(START_MS);
    assert!(m.validate().is_err(), "an sms consent is about a phone");
    if let Body::IysConsent { channel, .. } = &mut m.body {
        *channel = IysChannel::Email;
    }
    assert!(m.validate().is_ok());
    if let Body::IysConsent { source, .. } = &mut m.body {
        *source = "someone".to_owned();
    }
    assert!(m.validate().is_err());
}
