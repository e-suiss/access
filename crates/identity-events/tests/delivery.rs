//! OP-149 m.4, m.7, OP-63, OP-131: outbox → fan-out → delivery on a real PostgreSQL, to a local
//! receiver: Standard Webhooks signatures, at-least-once with backoff, dedup by id, RFC 8936
//! poll, and the SSRF guard.

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

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_crypto::jose::JwsAlg;
use access_crypto::opaque_id::IdKey;
use access_crypto::secret::Secret;
use access_crypto::webhook::WebhookSecret;
use access_identity_account::notify::delivery::Backoff;
use access_identity_events::adapters::{KekSealer, OutboundTransport, RealmKek};
use access_identity_events::app::courier::{Courier, Step};
use access_identity_events::app::fanout::Fanout;
use access_identity_events::app::streams::{StreamError, Streams};
use access_identity_events::app::{Db, emit};
use access_identity_events::domain::catalog::{ClientChange, IdentityEvent, IdentityKind, urn};
use access_identity_events::domain::stream::parse_stream;
use access_identity_events::ports::{
    Clock, PostError, Reply, TenantIds, TokenSigner, Transport, Unavailable,
};
use access_identity_oauth::adapters::oauth::OsRandom;
use access_identity_oauth::adapters::outbound::{
    DeclaredTargets, Outbound, Target, post_over, post_request,
};
use access_identity_oauth::ports::dpop::ClockUnavailable;
use access_internal_api::events::{
    Detail, Event, Kind, ReasonClass, Source, Subject, compromise_from,
};
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::Id;
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, OutboxRow, acquire_lease, commit_batch, create_domain,
};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::create_settings;
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant, set_issuer};
use access_store::testing::{TestDb, fresh};
use serde_json::Value as Json;
use suiss_crypto::envelope::{Kek, SoftKek};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const ISSUER: &str = "https://id.test/realms/shop";
const T0: u64 = 1_793_750_400_000;

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

/// Signs nothing: the header and payload in the clear and a fixed signature, so the test can
/// read back what would be signed.
struct ClearSigner;

/// A signer whose realm key is unavailable (down, or a realm it cannot open).
struct RefusingSigner;

impl TokenSigner for RefusingSigner {
    fn sign(
        &self,
        _: RealmId,
        _: JwsAlg,
        _: &str,
        _: &[u8],
        _: u64,
    ) -> impl std::future::Future<Output = Result<String, Unavailable>> + Send {
        std::future::ready(Err(Unavailable))
    }

    fn jwks(
        &self,
        _: RealmId,
    ) -> impl std::future::Future<Output = Result<String, Unavailable>> + Send {
        std::future::ready(Err(Unavailable))
    }
}

impl TokenSigner for ClearSigner {
    fn sign(
        &self,
        _: RealmId,
        alg: JwsAlg,
        typ: &str,
        payload: &[u8],
        _: u64,
    ) -> impl std::future::Future<Output = Result<String, Unavailable>> + Send {
        let header = format!(r#"{{"alg":"{}","typ":"{typ}"}}"#, alg.name());
        std::future::ready(Ok(format!(
            "{}.{}.c2ln",
            b64url_encode(header.as_bytes()),
            b64url_encode(payload)
        )))
    }

    fn jwks(
        &self,
        _: RealmId,
    ) -> impl std::future::Future<Output = Result<String, Unavailable>> + Send {
        std::future::ready(Ok(String::from("{}")))
    }
}

fn set_of(token: &str) -> (Json, Json) {
    let mut parts = token.split('.');
    let h = serde_json::from_slice(&b64url_decode(parts.next().unwrap()).unwrap()).unwrap();
    let p = serde_json::from_slice(&b64url_decode(parts.next().unwrap()).unwrap()).unwrap();
    (h, p)
}

/// One request a receiver got.
#[derive(Clone, Debug)]
struct Got {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Got {
    fn header(&self, name: &str) -> &str {
        &self
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .unwrap()
            .1
    }
}

/// A local receiver: answers with the scripted statuses, then 202.
#[derive(Clone, Default)]
struct Receiver {
    got: Arc<Mutex<Vec<Got>>>,
    script: Arc<Mutex<VecDeque<u16>>>,
}

impl Receiver {
    async fn start(&self) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let me = me.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0_u8; 4096];
                    let (head, len) = loop {
                        let n = s.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8(buf[..i].to_vec()).unwrap();
                            let len = head
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length: ")
                                        .map(|v| v.parse::<usize>().unwrap())
                                })
                                .unwrap();
                            break (head, (i + 4, len));
                        }
                    };
                    while buf.len() < len.0 + len.1 {
                        let n = s.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let headers = head
                        .lines()
                        .skip(1)
                        .filter_map(|l| l.split_once(": "))
                        .map(|(n, v)| (n.to_owned(), v.to_owned()))
                        .collect();
                    me.got.lock().unwrap().push(Got {
                        headers,
                        body: buf[len.0..len.0 + len.1].to_vec(),
                    });
                    let status = me.script.lock().unwrap().pop_front().unwrap_or(202);
                    let answer = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    s.write_all(answer.as_bytes()).await.unwrap();
                });
            }
        });
        port
    }
}

/// Sends the request the outbound client would send, but over plain TCP to the local receiver.
struct Local(u16);

impl Transport for Local {
    async fn post(
        &self,
        url: &str,
        content_type: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<Reply, PostError> {
        let target = Target::parse(url).map_err(|_| PostError::Refused)?;
        let request =
            post_request(&target, content_type, headers, body).map_err(|_| PostError::Refused)?;
        let mut s = TcpStream::connect(("127.0.0.1", self.0))
            .await
            .map_err(|_| PostError::Unreachable)?;
        let a = post_over(&mut s, &request)
            .await
            .map_err(|_| PostError::Unreachable)?;
        Ok(Reply {
            status: a.status,
            retry_after_ms: None,
        })
    }
}

struct World {
    db: TestDb,
    tenant: TenantId,
    realm: RealmId,
    domain: DomainId,
    clock: TestClock,
}

impl World {
    async fn new() -> Self {
        let db = fresh().await.unwrap();
        let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
        let domain = DomainId::from_bytes([7; 32]);
        let genesis = LogRecord {
            pos: 0,
            kind: "genesis",
            recorded_at: 1,
            leaf_hash: [7; 32],
            envelope: vec![0xa0],
        };
        create_domain(&db.sequencer, &domain, *tenant.as_bytes(), &genesis, &[])
            .await
            .unwrap();
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
        }
    }

    fn pools(&self) -> Db {
        Db {
            app: self.db.app.clone(),
            reader: self.db.reader.clone(),
            ids: Arc::new(ids()),
        }
    }

    /// The tenant's `tnt_` id (OP-149 m.15 (i)).
    fn tenant_id(&self) -> String {
        ids().external(self.tenant.as_bytes()).unwrap()
    }

    fn streams(&self) -> Streams<KekSealer<OneKek>, OsRandom> {
        Streams::new(self.pools(), sealer(), OsRandom)
    }

    fn fanout(&self) -> Fanout<TestClock> {
        Fanout::new(self.pools(), self.clock.clone())
    }

    fn courier<T: Transport>(&self, t: T) -> Courier<T, ClearSigner, KekSealer<OneKek>, TestClock> {
        self.courier_with(t, ClearSigner)
    }

    fn courier_with<T: Transport, S: TokenSigner>(
        &self,
        t: T,
        signer: S,
    ) -> Courier<T, S, KekSealer<OneKek>, TestClock> {
        Courier::new(
            self.pools(),
            t,
            signer,
            sealer(),
            self.clock.clone(),
            Backoff {
                base_ms: 60_000,
                max_ms: 600_000,
            },
        )
    }

    fn advance(&self, ms: u64) {
        self.clock.0.fetch_add(ms, Ordering::SeqCst);
    }

    async fn api_client_created(&self, client_id: &str) -> String {
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let id = access_crypto::random::bytes::<32>().unwrap();
        let e = IdentityEvent::api_client(
            IdentityKind::ApiClientCreated,
            id,
            &ClientChange {
                tenant: &self.tenant_id(),
                realm: self.realm.as_bytes(),
                client_id,
                exercise: &[3; 32],
                platform_product: None,
                at: T0,
            },
        );
        emit(&mut t, &e).await.unwrap();
        t.commit().await.unwrap();
        b64url_encode(&id)
    }

    /// Commits one record at position 1 with `events` in its outbox, as the sequencer does.
    async fn authority_events(&self, events: &[Event]) {
        let (lease, head) = acquire_lease(
            &self.db.sequencer,
            &self.domain,
            "t",
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        let pos = head.pos + 1;
        let next = HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: [8; 32],
            recorded_at: 2,
            frontier: vec![[8; 32]],
        };
        let batch = CommitBatch {
            epoch: lease.epoch,
            after: head.pos,
            records: vec![LogRecord {
                pos,
                kind: "decision",
                recorded_at: 2,
                leaf_hash: [8; 32],
                envelope: vec![0xa1, 1],
            }],
            head: next,
            nonces: vec![],
            outbox: events
                .iter()
                .enumerate()
                .map(|(i, e)| OutboxRow {
                    pos,
                    idx: u32::try_from(i).unwrap(),
                    event_id: [u8::try_from(i).unwrap() + 40; 32],
                    event: e.to_bytes().unwrap(),
                    trace_parent: None,
                })
                .collect(),
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            effects: vec![],
        };
        commit_batch(
            &self.db.sequencer,
            &self.domain,
            *self.tenant.as_bytes(),
            &batch,
        )
        .await
        .unwrap();
    }

    async fn state(&self, sub: [u8; 16], event_id: &str) -> (String, Option<String>) {
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let d = t
            .delivery(self.realm, sub, event_id)
            .await
            .unwrap()
            .unwrap();
        t.commit().await.unwrap();
        (d.state, d.last_reason)
    }
}

const SETTLE: Duration = Duration::from_secs(20);

/// Steps the identity fan-out until `n` deliveries are queued. The outbox watermark is
/// cluster-wide, so another test's open transaction delays an event, never loses it.
async fn settle_identity(fanout: &Fanout<TestClock>, n: u32) -> u32 {
    let deadline = std::time::Instant::now() + SETTLE;
    let mut total = 0;
    loop {
        total += fanout.identity_step().await.unwrap();
        if total >= n {
            return total;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{total} of {n} after 20 s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// [`settle_identity`] for `domain`'s authority outbox.
async fn settle_domain(fanout: &Fanout<TestClock>, domain: &DomainId, n: u32) -> u32 {
    let deadline = std::time::Instant::now() + SETTLE;
    let mut total = 0;
    loop {
        total += fanout.domain_step(domain).await.unwrap();
        if total >= n {
            return total;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{total} of {n} after 20 s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The cell's id key of these tests.
fn ids() -> IdKey {
    IdKey::new(Secret::new([4; 32]))
}

fn sealer() -> KekSealer<OneKek> {
    KekSealer(OneKek(Arc::new(SoftKek::new("realm-kek-1", [9; 32]))))
}

fn stream_request(method: &str, endpoint: Option<&str>, events: &[&str]) -> Vec<u8> {
    let mut delivery = serde_json::json!({ "method": method });
    if let Some(e) = endpoint {
        delivery["endpoint_url"] = e.into();
    }
    serde_json::to_vec(&serde_json::json!({
        "delivery": delivery,
        "aud": "work",
        "events_requested": events.iter().map(|n| urn(n)).collect::<Vec<_>>(),
    }))
    .unwrap()
}

fn departed(d: &DomainId) -> Event {
    Event {
        kind: Kind::PartyDisabled,
        domain: Digest(*d.as_bytes()),
        source: Source::Exercise(Digest([9; 32])),
        subject: Subject::Party(Id([2; 16])),
        at: T0,
        detail: Detail::Disabled {
            reason: ReasonClass::Departed,
        },
    }
}

fn compromised(d: &DomainId) -> Event {
    Event {
        kind: Kind::PartyCompromised,
        domain: Digest(*d.as_bytes()),
        source: Source::Claim(Id([8; 16])),
        subject: Subject::Party(Id([2; 16])),
        at: T0,
        detail: Detail::Compromised {
            keys: vec![(Id([4; 16]), [5; 32])],
            occurred_at: None,
            window_from: compromise_from(None, T0),
            declared_at: T0,
            evidence: Digest([6; 32]),
        },
    }
}

// OP-149 m.4, m.7, OP-63, OP-131: identity and authority outbox events reach a webhook
// subscriber signed per Standard Webhooks, at least once with backoff, and the same id on a
// redelivery; a repeated fan-out queues nothing twice
// OP-21, §7.9.2.4, MD-7, OP-150 m.2: an admitted party.compromised ends the sessions and grants
// of the Party's subject in the realms its domain governs, through the session epoch
#[tokio::test]
async fn a_party_compromise_raises_its_subjects_session_epoch() {
    // TN-50, CMP-15.2
    let w = World::new().await;
    let mut t = TenantTx::begin(&w.db.app, w.tenant, w.realm).await.unwrap();
    let subject = t
        .insert_subject("active", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &subject, &[2; 16])
            .await
            .unwrap()
    );
    let before = t
        .subject(subject, false)
        .await
        .unwrap()
        .unwrap()
        .session_epoch;
    t.commit().await.unwrap();
    w.authority_events(&[compromised(&w.domain)]).await;
    let fanout = w.fanout();
    let deadline = std::time::Instant::now() + SETTLE;
    loop {
        fanout
            .domain_step_in(&w.domain, Some(&w.db.router))
            .await
            .unwrap();
        let mut t = TenantTx::begin(&w.db.app, w.tenant, w.realm).await.unwrap();
        let now = t
            .subject(subject, false)
            .await
            .unwrap()
            .unwrap()
            .session_epoch;
        t.commit().await.unwrap();
        if now > before {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "epoch not raised");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn webhook_delivery_is_signed_retried_and_deduplicated() {
    let w = World::new().await;
    let receiver = Receiver::default();
    receiver.script.lock().unwrap().push_back(503);
    let port = receiver.start().await;
    let streams = w.streams();
    let hook = streams
        .create(
            w.tenant,
            w.realm,
            &parse_stream(&stream_request(
                "urn:suiss:access:delivery:webhook",
                Some("https://work.example/v1/access/events"),
                &["api_client.created", "party.disabled"],
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    let secret = WebhookSecret::parse(&hook.secret.clone().unwrap()).unwrap();
    assert!(hook.token.is_none());
    support::assert_valid("stream.schema.json", &hook.stream);

    w.api_client_created("cli_shop").await;
    w.authority_events(&[departed(&w.domain)]).await;
    let fanout = w.fanout();
    assert_eq!(settle_identity(&fanout, 1).await, 1);
    assert_eq!(settle_domain(&fanout, &w.domain, 1).await, 1);
    assert_eq!(fanout.identity_step().await.unwrap(), 0);
    assert_eq!(fanout.domain_step(&w.domain).await.unwrap(), 0);

    let courier = w.courier(Local(port));
    let first = courier.step().await.unwrap();
    assert_eq!((first.delivered, first.retried, first.failed), (1, 1, 0));
    assert_eq!(courier.step().await.unwrap(), Step::default());
    w.advance(60_000);
    let second = courier.step().await.unwrap();
    assert_eq!((second.delivered, second.retried), (1, 0));

    let got = receiver.got.lock().unwrap().clone();
    assert_eq!(got.len(), 3);
    let now_s = w.clock.now().unwrap() / 1000;
    let mut ids = Vec::new();
    for g in &got {
        let id = g.header("webhook-id");
        let ts: u64 = g.header("webhook-timestamp").parse().unwrap();
        assert!(
            secret.verify(id, ts, &g.body, g.header("webhook-signature"), now_s),
            "signature"
        );
        assert!(
            g.header("content-type")
                .starts_with("application/cloudevents+json")
        );
        let ce: Json = serde_json::from_slice(&g.body).unwrap();
        support::assert_cloud_event(&ce);
        // OP-149 m.15 (i)
        assert_eq!(ce["accesstenant"], w.tenant_id());
        assert_eq!(ce["id"], id);
        assert_eq!(ce["data"]["iss"], ISSUER);
        assert_eq!(ce["data"]["aud"], "work");
        ids.push(id.to_owned());
    }
    // the first answer was 503: the same id came again, so the receiver deduplicates by it
    let unique: BTreeSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), 2);
    assert_eq!(ids.iter().filter(|i| **i == ids[0]).count(), 2);
    for id in unique {
        assert_eq!(w.state(hook.id, id).await.0, "delivered");
    }
    // OP-149 m.34 (d), RFC 8417 §2.2: the retry carries the time of its own attempt in iat;
    // jti, the event and the CloudEvent's occurrence time are the same
    let (first, retry): (Json, Json) = (
        serde_json::from_slice(&got[0].body).unwrap(),
        serde_json::from_slice(&got[2].body).unwrap(),
    );
    assert_eq!(first["data"]["iat"], T0 / 1000);
    assert_eq!(retry["data"]["iat"], (T0 + 60_000) / 1000);
    assert_eq!(first["data"]["jti"], retry["data"]["jti"]);
    assert_eq!(first["data"]["events"], retry["data"]["events"]);
    assert_eq!(first["time"], retry["time"]);
}

// OP-149 m.34 (d), RFC 8417 §2.2, RFC 8935, Work T-102: an SSF push tried again after the
// receiver's freshness window is signed with iat of that attempt, so the receiver takes it and
// deduplicates by the unchanged jti; the stored payload is not rewritten
#[tokio::test]
async fn a_push_retry_is_stamped_with_the_time_of_its_attempt() {
    let w = World::new().await;
    let receiver = Receiver::default();
    receiver.script.lock().unwrap().push_back(503);
    let port = receiver.start().await;
    let push = w
        .streams()
        .create(
            w.tenant,
            w.realm,
            &parse_stream(&stream_request(
                "urn:ietf:rfc:8935",
                Some("https://work.example/v1/inbound/events"),
                &["api_client.created"],
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    let id = w.api_client_created("cli_late").await;
    let fanout = w.fanout();
    assert_eq!(settle_identity(&fanout, 1).await, 1);

    let courier = w.courier(Local(port));
    let first = courier.step().await.unwrap();
    assert_eq!((first.delivered, first.retried, first.failed), (0, 1, 0));
    assert_eq!(w.state(push.id, &id).await.0, "pending");
    w.advance(6 * 60_000);
    let second = courier.step().await.unwrap();
    assert_eq!((second.delivered, second.retried, second.failed), (1, 0, 0));
    assert_eq!(w.state(push.id, &id).await.0, "delivered");

    let got = receiver.got.lock().unwrap().clone();
    assert_eq!(got.len(), 2);
    let (h1, c1) = set_of(std::str::from_utf8(&got[0].body).unwrap());
    let (h2, c2) = set_of(std::str::from_utf8(&got[1].body).unwrap());
    assert_eq!(
        (h1["typ"].as_str(), h2["typ"].as_str()),
        (Some("secevent+jwt"), Some("secevent+jwt"))
    );
    assert_eq!(c1["iat"], T0 / 1000);
    assert_eq!(c2["iat"], (T0 + 6 * 60_000) / 1000);
    assert_eq!(c1["jti"], id);
    assert_eq!(c2["jti"], id);
    assert_eq!(c1["events"], c2["events"]);
    assert_eq!(c1["aud"], c2["aud"]);
    assert_eq!(c1["sub_id"], c2["sub_id"]);
    // OP-73: the queued payload still says when it was queued
    let mut t = TenantTx::begin(&w.db.app, w.tenant, w.realm).await.unwrap();
    let row = t.delivery(w.realm, push.id, &id).await.unwrap().unwrap();
    t.commit().await.unwrap();
    let stored: Json = serde_json::from_slice(&row.payload).unwrap();
    assert_eq!(stored["iat"], T0 / 1000);
}

// RFC 8936 §2.4, §2.5, OP-149 m.7, SI-9: a poll stream returns its pending SETs signed with
// the realm key, the compromise window as declared, and settles what the receiver acknowledged
#[tokio::test]
async fn poll_returns_and_settles_sets() {
    let w = World::new().await;
    let streams = w.streams();
    let poll = streams
        .create(
            w.tenant,
            w.realm,
            &parse_stream(&stream_request(
                "urn:ietf:rfc:8936",
                None,
                &["party.compromised", "party.disabled"],
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    let token = poll.token.clone().unwrap();
    assert!(poll.secret.is_none());
    w.api_client_created("cli_other").await;
    w.authority_events(&[departed(&w.domain), compromised(&w.domain)])
        .await;
    let fanout = w.fanout();
    assert_eq!(fanout.identity_step().await.unwrap(), 0);
    assert_eq!(settle_domain(&fanout, &w.domain, 2).await, 2);
    // a push courier leaves poll deliveries alone
    assert_eq!(w.courier(Local(1)).step().await.unwrap(), Step::default());

    let answer = streams
        .poll(
            &ClearSigner,
            &w.clock,
            w.tenant,
            w.realm,
            &token,
            br#"{"maxEvents":1}"#,
        )
        .await
        .unwrap();
    support::assert_valid("poll-response.schema.json", &answer);
    assert_eq!(answer["moreAvailable"], true);
    // OP-149 m.34 (d): a SET polled later carries the time it is handed out
    w.advance(6 * 60_000);
    let answer = streams
        .poll(&ClearSigner, &w.clock, w.tenant, w.realm, &token, b"{}")
        .await
        .unwrap();
    assert_eq!(answer["moreAvailable"], false);
    let sets = answer["sets"].as_object().unwrap();
    assert_eq!(sets.len(), 2);
    let mut found = false;
    for (jti, t) in sets {
        let (h, claims) = set_of(t.as_str().unwrap());
        assert_eq!(h["typ"], "secevent+jwt");
        assert_eq!(claims["jti"], jti.as_str());
        assert_eq!(claims["iat"], (T0 + 6 * 60_000) / 1000);
        let urn = support::assert_set(&claims);
        if urn.ends_with("party.compromised") {
            let e = &claims["events"][&urn];
            assert_eq!(e["declared_at"], T0);
            assert_eq!(e["window_from"], T0 - 72 * 3_600_000);
            assert!(e.get("occurred_at").is_none());
            found = true;
        }
    }
    assert!(found);
    let acks: Vec<&String> = sets.keys().collect();
    let body = serde_json::to_vec(&serde_json::json!({ "ack": acks })).unwrap();
    let after = streams
        .poll(&ClearSigner, &w.clock, w.tenant, w.realm, &token, &body)
        .await
        .unwrap();
    assert!(after["sets"].as_object().unwrap().is_empty());
    for jti in sets.keys() {
        assert_eq!(w.state(poll.id, jti).await.0, "acknowledged");
    }
    assert!(matches!(
        streams
            .poll(&ClearSigner, &w.clock, w.tenant, w.realm, "wrong", b"{}")
            .await,
        Err(StreamError::NotFound)
    ));
}

// §14.3, OP-149 m.4, m.23: an endpoint the SSRF guard refuses fails at once, without retry,
// also one declared when the stream was created but not by the delivering client, and a
// disabled stream gets nothing more (OP-73: it stays as a row)
#[tokio::test]
async fn refused_endpoints_and_disabled_streams_get_nothing() {
    let w = World::new().await;
    let streams = w.streams().declaring(DeclaredTargets::new([String::from(
        "https://10.0.0.1:8443/hook",
    )]));
    let mut subs = Vec::new();
    for endpoint in [
        "https://localhost/hook",
        "https://10.0.0.1:8443/hook",
        "https://work.example/h",
    ] {
        subs.push(
            streams
                .create(
                    w.tenant,
                    w.realm,
                    &parse_stream(&stream_request(
                        "urn:suiss:access:delivery:webhook",
                        Some(endpoint),
                        &["api_client.created"],
                    ))
                    .unwrap(),
                )
                .await
                .unwrap(),
        );
    }
    streams
        .disable(w.tenant, w.realm, subs[2].id)
        .await
        .unwrap();
    assert_eq!(
        streams.get(w.tenant, w.realm, subs[2].id).await.unwrap()["status"],
        "disabled"
    );
    let id = w.api_client_created("cli_x").await;
    assert_eq!(settle_identity(&w.fanout(), 2).await, 2);
    let courier = w.courier(OutboundTransport(Outbound::disabled(Duration::from_secs(
        1,
    ))));
    let step = courier.step().await.unwrap();
    assert_eq!((step.delivered, step.retried, step.failed), (0, 0, 2));
    for s in &subs[..2] {
        assert_eq!(
            w.state(s.id, &id).await,
            (String::from("failed"), Some(String::from("refused")))
        );
    }
    w.advance(3_600_000);
    assert_eq!(courier.step().await.unwrap(), Step::default());
    assert!(matches!(
        streams.disable(w.tenant, w.realm, subs[2].id).await,
        Err(StreamError::NotFound)
    ));
}

// OP-149 m.23, §14.3: a stream endpoint on a private address literal or another port than 443
// is accepted only when the operator declared it byte for byte
#[tokio::test]
async fn only_declared_private_endpoints_open_streams() {
    let w = World::new().await;
    let declared = "https://work-server:8443/v1/inbound/events";
    let request = |e: &str| {
        parse_stream(&stream_request(
            "urn:ietf:rfc:8935",
            Some(e),
            &["api_client.created"],
        ))
        .unwrap()
    };
    for refused in [
        declared,
        "https://10.0.0.1/hook",
        "https://[fd00::1]/hook",
        "https://work.example:8443/hook",
    ] {
        assert!(
            matches!(
                w.streams().create(w.tenant, w.realm, &request(refused)).await,
                Err(StreamError::Invalid(i)) if i.0 == "endpoint_url"
            ),
            "{refused}"
        );
    }
    let streams = w
        .streams()
        .declaring(DeclaredTargets::new([String::from(declared)]));
    for near in [
        "https://work-server:8443/v1/inbound/events/",
        "https://work-server:8443/v1/inbound/other",
        "https://work-server:9443/v1/inbound/events",
        "https://Work-Server:8443/v1/inbound/events",
    ] {
        assert!(
            matches!(
                streams.create(w.tenant, w.realm, &request(near)).await,
                Err(StreamError::Invalid(_))
            ),
            "{near}"
        );
    }
    let created = streams
        .create(w.tenant, w.realm, &request(declared))
        .await
        .unwrap();
    assert_eq!(created.stream["delivery"]["endpoint_url"], declared);
}

// SSF 1.0 §8.1.2, §8.1.4, §9.16.2, PI-9: a stream reads and sets its own status by its
// credential; verification queues a SET whose subject is the stream and which echoes the state,
// delivered through the stream like any event; another stream's id is refused
#[tokio::test]
async fn a_stream_verifies_and_sets_its_status() {
    use access_identity_events::domain::control::{VERIFICATION_EVENT, parse_status, parse_verify};
    let w = World::new().await;
    let streams = w.streams();
    let poll = streams
        .create(
            w.tenant,
            w.realm,
            &parse_stream(&stream_request(
                "urn:ietf:rfc:8936",
                None,
                &["party.disabled"],
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    let token = poll.token.clone().unwrap();
    let id = poll.stream["stream_id"].as_str().unwrap().to_owned();
    let own = streams.by_token(w.tenant, w.realm, &token).await.unwrap();
    assert_eq!(streams.status(&own, &id).unwrap()["status"], "enabled");
    assert!(matches!(
        streams.status(&own, "00000000-0000-4000-8000-000000000000"),
        Err(StreamError::NotFound)
    ));
    let paused =
        parse_status(format!(r#"{{"stream_id":"{id}","status":"paused"}}"#).as_bytes()).unwrap();
    streams
        .set_status(w.tenant, w.realm, &own, &paused)
        .await
        .unwrap();
    let own = streams.by_token(w.tenant, w.realm, &token).await.unwrap();
    assert_eq!(streams.status(&own, &id).unwrap()["status"], "paused");

    let verify =
        parse_verify(format!(r#"{{"stream_id":"{id}","state":"s-42"}}"#).as_bytes()).unwrap();
    streams
        .verify(w.tenant, w.realm, &own, &verify, T0)
        .await
        .unwrap();
    let answer = streams
        .poll(&ClearSigner, &w.clock, w.tenant, w.realm, &token, b"{}")
        .await
        .unwrap();
    let sets = answer["sets"].as_object().unwrap();
    assert_eq!(sets.len(), 1);
    let (jti, t) = sets.iter().next().unwrap();
    let (_, claims) = set_of(t.as_str().unwrap());
    assert_eq!(claims["jti"], jti.as_str());
    assert_eq!(claims["sub_id"]["id"], id.as_str());
    assert_eq!(claims["events"][VERIFICATION_EVENT]["state"], "s-42");

    let disabled =
        parse_status(format!(r#"{{"stream_id":"{id}","status":"disabled"}}"#).as_bytes()).unwrap();
    streams
        .set_status(w.tenant, w.realm, &own, &disabled)
        .await
        .unwrap();
    assert!(matches!(
        streams.by_token(w.tenant, w.realm, &token).await,
        Err(StreamError::NotFound)
    ));
}

// OP-149 m.4 at-least-once, m.7, OP-67, Work A24: a push SET that cannot be signed is that
// delivery's transient failure, retried with backoff, and never holds back the other
// deliveries of the step; once the signer is back the delivery goes out
#[tokio::test]
async fn an_unsignable_delivery_is_retried_without_blocking_the_others() {
    let w = World::new().await;
    let receiver = Receiver::default();
    let port = receiver.start().await;
    let streams = w.streams();
    let hook = streams
        .create(
            w.tenant,
            w.realm,
            &parse_stream(&stream_request(
                "urn:suiss:access:delivery:webhook",
                Some("https://work.example/v1/access/events"),
                &["api_client.created"],
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    let push = streams
        .create(
            w.tenant,
            w.realm,
            &parse_stream(&stream_request(
                "urn:ietf:rfc:8935",
                Some("https://work.example/v1/inbound/events"),
                &["api_client.created"],
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    let id = w.api_client_created("cli_push").await;
    let fanout = w.fanout();
    assert_eq!(settle_identity(&fanout, 1).await, 2);

    let down = w.courier_with(Local(port), RefusingSigner);
    let first = down.step().await.unwrap();
    assert_eq!((first.delivered, first.retried, first.failed), (1, 1, 0));
    assert_eq!(w.state(hook.id, &id).await.0, "delivered");
    assert_eq!(w.state(push.id, &id).await.0, "pending");
    assert_eq!(receiver.got.lock().unwrap().len(), 1);
    assert_eq!(down.step().await.unwrap(), Step::default());

    w.advance(60_000);
    let up = w.courier(Local(port));
    let second = up.step().await.unwrap();
    assert_eq!((second.delivered, second.retried, second.failed), (1, 0, 0));
    assert_eq!(w.state(push.id, &id).await.0, "delivered");
    let got = receiver.got.lock().unwrap().clone();
    assert_eq!(got.len(), 2);
    assert!(
        got[1]
            .header("content-type")
            .starts_with("application/secevent+jwt")
    );
}
