//! TN-136, OP-151 m.3 (i), INV-24, TI-7: webhook registrations bound to their decision, the
//! outbox fan-out and the courier on a real PostgreSQL: signed `CloudEvents`, at least once with
//! the retry schedule, per-delivery isolation, key rotation overlap, no ordering guarantee, and
//! no decision that waits on a delivery.

#![allow(
    unreachable_pub,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use access_crypto::opaque_id::IdKey;
use access_crypto::secret::Secret;
use access_crypto::webhook::WebhookPublicKey;
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::accounts::{change_status, create};
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::events::EventOrder;
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::status::AccountStatus;
use access_identity_events::adapters::{KekSealer, RealmKek};
use access_identity_events::app::webhooks::{WebhookCourier, WebhookFanout, Written};
use access_identity_events::app::{Db, emit};
use access_identity_events::domain::catalog::{IdentityEvent, uuid};
use access_identity_events::domain::webhook::{GIVE_UP_AFTER_MS, WebhookChange, WebhookSpec};
use access_identity_events::ports::{Clock, PostError, Reply, Transport};
use access_identity_hooks::domain::Signing;
use access_identity_oauth::ports::dpop::ClockUnavailable;
use access_kernel::json::b64url_encode;
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::identity::{RealmId, TenantId, TenantTx, poll};
use access_store::idp::{Decision, bind, create_settings};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant, set_issuer};
use access_store::testing::{TestDb, fresh};
use serde_json::Value as Json;
use suiss_crypto::envelope::{Kek, SoftKek};

const ISSUER: &str = "https://id.test/realms/shop";
const T0: u64 = 1_793_750_400_000;
const INTENT: [u8; 32] = [9; 32];
const ACTOR: Actor<'static> = Actor {
    actor: "admin",
    correlation: "c-1",
};

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now(&self) -> Result<u64, ClockUnavailable> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct OneKek(Arc<SoftKek>);

impl RealmKek for OneKek {
    fn kek(&self, _: TenantId, _: RealmId) -> Option<Arc<dyn Kek + Send + Sync>> {
        Some(self.0.clone())
    }
}

fn kek() -> Arc<SoftKek> {
    Arc::new(SoftKek::new("realm-kek-1", [9; 32]))
}

fn vault() -> KekSealer<OneKek> {
    KekSealer(OneKek(kek()))
}

fn ids() -> IdKey {
    IdKey::new(Secret::new([4; 32]))
}

/// One request a receiver got.
#[derive(Clone, Debug)]
struct Got {
    url: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

/// Answers per URL from a script (`None` = unreachable), then 204; records every request.
#[derive(Clone, Default)]
struct Fake {
    got: Arc<Mutex<Vec<Got>>>,
    script: Arc<Mutex<BTreeMap<String, VecDeque<Option<u16>>>>>,
}

impl Fake {
    fn answer(&self, url: &str, answers: &[Option<u16>]) {
        self.script
            .lock()
            .unwrap()
            .entry(String::from(url))
            .or_default()
            .extend(answers.iter().copied());
    }

    fn got(&self) -> Vec<Got> {
        self.got.lock().unwrap().clone()
    }
}

impl Transport for Fake {
    fn post(
        &self,
        url: &str,
        _: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> impl std::future::Future<Output = Result<Reply, PostError>> + Send {
        self.got.lock().unwrap().push(Got {
            url: String::from(url),
            headers: headers
                .iter()
                .map(|(k, v)| (String::from(*k), v.clone()))
                .collect(),
            body: body.to_vec(),
        });
        let next = self
            .script
            .lock()
            .unwrap()
            .get_mut(url)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Some(204));
        std::future::ready(
            next.map(|status| Reply {
                status,
                retry_after_ms: None,
            })
            .ok_or(PostError::Unreachable),
        )
    }
}

struct World {
    db: TestDb,
    tenant: TenantId,
    realm: RealmId,
    domain: DomainId,
    clock: TestClock,
    next_pos: AtomicU64,
}

const URL_A: &str = "https://sync.shop.example/a";
const URL_B: &str = "https://crm.shop.example/b";

impl World {
    async fn new(seed: u8) -> Self {
        let db = fresh().await.unwrap();
        let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
        let domain = DomainId::from_bytes([seed; 32]);
        let genesis = LogRecord {
            pos: 0,
            kind: "genesis",
            recorded_at: 1,
            leaf_hash: [seed; 32],
            envelope: vec![0xa0],
        };
        create_domain(&db.sequencer, &domain, *tenant.as_bytes(), &genesis, &[])
            .await
            .unwrap();
        let (lease, mut head) = acquire_lease(&db.sequencer, &domain, "t", Duration::from_secs(10))
            .await
            .unwrap();
        for i in 1..=8_u8 {
            let pos = head.pos + 1;
            let leaf = [seed.wrapping_add(i); 32];
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
                    intent_digest: INTENT,
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
            commit_batch(&db.sequencer, &domain, *tenant.as_bytes(), &batch)
                .await
                .unwrap();
            head = next;
        }
        let mut t = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
        let realm = create_realm(&mut t, &domain, "shop", "pool-default")
            .await
            .unwrap();
        t.enter_realm(realm).await.unwrap();
        assert!(set_issuer(&mut t, ISSUER).await.unwrap());
        create_settings(&mut t).await.unwrap();
        t.commit().await.unwrap();
        Self {
            db,
            tenant,
            realm,
            domain,
            clock: TestClock(Arc::new(AtomicU64::new(T0))),
            next_pos: AtomicU64::new(1),
        }
    }

    fn pools(&self) -> Db {
        Db {
            app: self.db.app.clone(),
            reader: self.db.reader.clone(),
            ids: Arc::new(ids()),
        }
    }

    fn now(&self) -> u64 {
        self.clock.0.load(Ordering::SeqCst)
    }

    fn advance(&self, ms: u64) {
        self.clock.0.fetch_add(ms, Ordering::SeqCst);
    }

    /// Writes `change` against the next committed ALLOW of its action (EI-25).
    async fn apply(&self, change: &WebhookChange) -> Written {
        let pos = self.next_pos.fetch_add(1, Ordering::SeqCst);
        let nonce = vec![u8::try_from(pos).unwrap(); 16];
        let label = change.action().label();
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let b = bind(
            &mut t,
            &Decision {
                domain: &self.domain,
                position: pos,
                nonce: &nonce,
                intent: INTENT,
                change: [5; 32],
                action: &label,
            },
        )
        .await
        .unwrap()
        .unwrap();
        let w = access_identity_events::app::webhooks::write(
            &mut t,
            &b,
            change,
            &vault(),
            self.now(),
            false,
        )
        .await
        .unwrap();
        t.commit().await.unwrap();
        w
    }

    async fn register(&self, id: u8, url: &str, events: &[&str]) -> WebhookPublicKey {
        let w = self
            .apply(&WebhookChange::Register {
                id: [id; 16],
                spec: WebhookSpec {
                    url: String::from(url),
                    events: events.iter().map(|e| String::from(*e)).collect(),
                    signing: Signing::Ed25519,
                },
            })
            .await;
        let Written::Key(k) = w else {
            panic!("no key shown")
        };
        WebhookPublicKey::parse(k.expose()).unwrap()
    }

    async fn account_created(&self, seed: u8) -> String {
        let id = [seed; 32];
        let e = IdentityEvent::account(&EventOrder::created(
            id,
            self.realm.as_bytes(),
            "usr_0b5yq2mtzk6x4hd1e8fg3wa7rc",
            T0,
        ));
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        emit(&mut t, &e).await.unwrap();
        t.commit().await.unwrap();
        b64url_encode(&id)
    }

    fn fanout(&self) -> WebhookFanout<TestClock> {
        WebhookFanout::new(self.pools(), self.clock.clone())
    }

    fn courier(&self, t: Fake) -> WebhookCourier<Fake, KekSealer<OneKek>, TestClock> {
        WebhookCourier::new(self.pools(), t, vault(), self.clock.clone())
    }

    /// Fans out until `n` deliveries are queued (the outbox watermark is cluster-wide).
    async fn fan_out(&self, n: u32) {
        let f = self.fanout();
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut queued = 0;
        while queued < n {
            queued += f.step().await.unwrap();
            assert!(Instant::now() < deadline, "{queued} of {n} queued");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn attempts(&self, webhook: u8, event: &str) -> Vec<(String, Option<u16>, Option<u32>)> {
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let a = t.webhook_attempts(&[webhook; 16], event).await.unwrap();
        t.commit().await.unwrap();
        a
    }

    async fn state(&self, webhook: u8, event: &str) -> String {
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let d = t
            .webhook_delivery(&[webhook; 16], event)
            .await
            .unwrap()
            .unwrap();
        t.commit().await.unwrap();
        d.state
    }
}

fn verify(pk: &WebhookPublicKey, g: &Got, now_s: u64) -> bool {
    let ts: u64 = g.headers["webhook-timestamp"].parse().unwrap();
    pk.verify(
        &g.headers["webhook-id"],
        ts,
        &g.body,
        &g.headers["webhook-signature"],
        now_s,
    )
}

// TN-136, TI-7, E42
#[tokio::test]
async fn tn_136_events_are_delivered_signed_and_at_least_once() {
    let w = World::new(91).await;
    let pk = w.register(1, URL_A, &["account.created"]).await;
    let event = w.account_created(1).await;
    w.fan_out(1).await;
    let fake = Fake::default();
    fake.answer(URL_A, &[Some(503)]);
    let c = w.courier(fake.clone());

    let s = c.step().await.unwrap();
    assert_eq!((s.delivered, s.retried), (0, 1));
    assert_eq!(
        c.step().await.unwrap().retried,
        0,
        "not due before a minute"
    );
    w.advance(60_000);
    assert_eq!(c.step().await.unwrap().delivered, 1);

    let got = fake.got();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].headers["webhook-id"], event);
    assert_eq!(got[1].headers["webhook-id"], event);
    assert!(verify(&pk, &got[1], (T0 + 60_000) / 1000));
    let ce: Json = serde_json::from_slice(&got[1].body).unwrap();
    support::assert_cloud_event(&ce);
    assert_eq!(ce["id"], event.as_str());
    assert_eq!(ce["type"], "urn:suiss:access:event:account.created");
    assert_eq!(ce["data"]["iss"], ISSUER);
    assert_eq!(ce["data"]["aud"], uuid(&[1; 16]));
    let text = String::from_utf8(got[1].body.clone()).unwrap();
    assert!(!text.contains('@'), "ids only");
    let log = w.attempts(1, &event).await;
    assert_eq!(log.len(), 2);
    assert_eq!((log[0].0.as_str(), log[0].1), ("retry", Some(503)));
    assert_eq!((log[1].0.as_str(), log[1].1), ("delivered", Some(204)));
    assert!(log.iter().all(|(_, _, latency)| latency.is_some()));
    w.fan_out(0).await;
    assert_eq!(
        w.fanout().step().await.unwrap(),
        0,
        "the event id is the dedup key"
    );
}

// TN-136, OP-151 m.3 (i)
#[tokio::test]
async fn tn_136_deliveries_are_isolated_and_unordered() {
    let w = World::new(92).await;
    let pk_a = w.register(1, URL_A, &["account.created"]).await;
    let pk_b = w.register(2, URL_B, &["account.created"]).await;
    let first = w.account_created(1).await;
    w.fan_out(2).await;
    w.advance(1);
    let second = w.account_created(2).await;
    w.fan_out(2).await;
    let fake = Fake::default();
    fake.answer(URL_A, &[None]);
    let c = w.courier(fake.clone());
    let s = c.step().await.unwrap();
    assert_eq!((s.delivered, s.retried), (3, 1));
    assert_eq!(w.state(1, &first).await, "pending");
    assert_eq!(w.state(1, &second).await, "delivered");
    assert_eq!(w.state(2, &first).await, "delivered");
    w.advance(60_000);
    assert_eq!(c.step().await.unwrap().delivered, 1);
    let to_a: Vec<String> = fake
        .got()
        .iter()
        .filter(|g| g.url == URL_A && g.headers.contains_key("webhook-id"))
        .map(|g| g.headers["webhook-id"].clone())
        .collect();
    assert_eq!(to_a.last(), Some(&first), "the earlier event arrived last");
    for g in fake.got() {
        let pk = if g.url == URL_A { &pk_a } else { &pk_b };
        let ts: u64 = g.headers["webhook-timestamp"].parse().unwrap();
        assert!(verify(pk, &g, ts));
    }
}

// TN-136
#[tokio::test]
async fn tn_136_rotation_overlaps_and_retries_end() {
    let w = World::new(93).await;
    let old = w.register(1, URL_A, &["account.created"]).await;
    let Written::Key(k) = w
        .apply(&WebhookChange::Update {
            id: [1; 16],
            url: String::from(URL_A),
            events: vec![String::from("account.created")],
            rotate: true,
        })
        .await
    else {
        panic!("no new key")
    };
    let new = WebhookPublicKey::parse(k.expose()).unwrap();
    let event = w.account_created(1).await;
    w.fan_out(1).await;
    let fake = Fake::default();
    fake.answer(URL_A, &[Some(500); 64]);
    let c = w.courier(fake.clone());
    c.step().await.unwrap();
    let g = &fake.got()[0];
    assert_eq!(g.headers["webhook-signature"].matches("v1a,").count(), 2);
    assert!(verify(&old, g, T0 / 1000) && verify(&new, g, T0 / 1000));

    let mut steps = 0;
    while w.state(1, &event).await == "pending" {
        w.advance(86_400_000);
        c.step().await.unwrap();
        steps += 1;
        assert!(steps < 30);
    }
    assert_eq!(w.state(1, &event).await, "exhausted");
    assert!(w.now() - T0 <= GIVE_UP_AFTER_MS + 86_400_000);
    let late = fake.got().last().unwrap().clone();
    assert!(
        !verify(&old, &late, w.now() / 1000),
        "the old key's overlap ended"
    );
    assert!(verify(&new, &late, w.now() / 1000));

    let pending = w.account_created(2).await;
    w.fan_out(1).await;
    w.apply(&WebhookChange::Retire { id: [1; 16] }).await;
    assert_eq!(c.step().await.unwrap().ended, 1);
    assert_eq!(w.state(1, &pending).await, "failed");
}

// INV-24, TN-136
#[tokio::test]
async fn inv_24_a_lost_delivery_changes_no_decision() {
    let w = World::new(94).await;
    w.register(1, URL_A, &["account.suspended", "session.revoked"])
        .await;
    let kek = kek();
    let id_key = ids();
    let realm = Realm {
        tenant: w.tenant,
        realm: w.realm,
        kek: kek.as_ref(),
        ids: &id_key,
    };
    let db = PgAccounts(w.db.app.clone());
    let ident = Identifier::new(IdentifierKind::Username, "ada").unwrap();
    let s = create(&db, &realm, &[ident], &ACTOR).await.unwrap();
    change_status(&db, &realm, s, AccountStatus::PendingUserAction, &ACTOR)
        .await
        .unwrap();
    change_status(&db, &realm, s, AccountStatus::Active, &ACTOR)
        .await
        .unwrap();
    change_status(&db, &realm, s, AccountStatus::Suspended, &ACTOR)
        .await
        .unwrap();

    let mut t = TenantTx::begin(&w.db.app, w.tenant, w.realm).await.unwrap();
    let row = t.subject(s, false).await.unwrap().unwrap();
    t.commit().await.unwrap();
    assert!(
        !AccountStatus::parse(&row.status)
            .unwrap()
            .can_authenticate()
    );
    assert!(row.session_epoch > 0, "sessions ended without any delivery");

    w.fan_out(2).await;
    let deadline = Instant::now() + Duration::from_secs(20);
    let kinds: Vec<String> = loop {
        let rows = poll(&w.db.reader, access_store::identity::Cursor::default(), 100)
            .await
            .unwrap();
        if rows.iter().filter(|r| r.kind.starts_with("event.")).count() >= 2 {
            break rows.into_iter().map(|r| r.kind).collect();
        }
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(kinds.contains(&String::from("event.account.suspended")));
    assert!(kinds.contains(&String::from("event.session.revoked")));
}
