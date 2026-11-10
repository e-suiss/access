#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::SystemEntropy;
use access_identity_account::app::accounts::create;
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::notify::delivery::{DiscoveryMismatch, check_discovery};
use access_identity_account::notify::message::{Address, Body, Message, SignInMethod};
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_account::notify::ports::Notifier as _;
use access_identity_account::testing::relay::RelayTwin;
use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use serde_json::{Value, json};
use suiss_crypto::pkcs11::KeyStore;
use tower::ServiceExt as _;

use super::*;
use crate::config::{RelayPlatform, Suiss};
use crate::login::kek_label;
use crate::testing::hsm;

const ISSUER: &str = "https://access.test";
const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};

static STORE: std::sync::OnceLock<Arc<KeyStore>> = std::sync::OnceLock::new();

fn random_hex() -> String {
    access_crypto::random::bytes::<16>()
        .unwrap()
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn file(tag: &str, value: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let p = std::env::temp_dir().join(format!("access-relay-{tag}-{}", random_hex()));
    std::fs::write(&p, value).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

fn config(twin: &RelayTwin, credential: PathBuf) -> Config {
    Config {
        issuer: Some(ISSUER.to_owned()),
        suiss: Some(Suiss {
            region: "local".to_owned(),
            relay: twin.base.clone(),
            management_api: "https://api.access.test".to_owned(),
            products: BTreeMap::new(),
            platform_realm: None,
            relay_platform: RelayPlatform {
                tenant: "access".to_owned(),
                credential_file: credential,
                ca_file: Some(file("ca", &twin.ca_pem)),
            },
        }),
        ..Config::default()
    }
}

struct World {
    db: TestDb,
    tenant: TenantId,
    realm: RealmId,
    domain: DomainId,
    keks: RealmKeks,
    store: Arc<KeyStore>,
}

async fn world() -> World {
    let db = fresh().await.unwrap();
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let domain = DomainId::from_bytes(access_crypto::random::bytes::<32>().unwrap());
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
    assert!(
        access_store::tenancy::set_issuer(&mut t, "https://id.test/realms/shop")
            .await
            .unwrap()
    );
    access_store::idp::create_settings(&mut t).await.unwrap();
    t.commit().await.unwrap();
    let store = STORE
        .get_or_init(|| {
            let (module, label) = hsm("relay");
            let pin = access_crypto::Secret::new(String::from("1234-test-only"));
            Arc::new(KeyStore::open(&module, &label, &pin).unwrap())
        })
        .clone();
    store.generate_kek(&kek_label(realm.as_bytes())).unwrap();
    if store.mac(crate::login::ID_KEY_ROOT).is_err() {
        store.generate_mac(crate::login::ID_KEY_ROOT).unwrap();
    }
    World {
        keks: RealmKeks::new(store.clone()),
        db,
        tenant,
        realm,
        domain,
        store,
    }
}

/// Commits one authority record with `event` in its outbox, as the sequencer does.
async fn authority_event(
    db: &TestDb,
    tenant: TenantId,
    domain: &DomainId,
    event: &access_internal_api::events::Event,
) {
    use access_store::authority::{CommitBatch, HeadRow, OutboxRow, acquire_lease, commit_batch};
    let (lease, head) = acquire_lease(&db.sequencer, domain, "t", Duration::from_secs(10))
        .await
        .unwrap();
    let pos = head.pos + 1;
    let leaf = access_crypto::random::bytes::<32>().unwrap();
    let batch = CommitBatch {
        epoch: lease.epoch,
        after: head.pos,
        records: vec![LogRecord {
            pos,
            kind: "decision",
            recorded_at: 2,
            leaf_hash: leaf,
            envelope: vec![0xa1, 1],
        }],
        head: HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: leaf,
            recorded_at: 2,
            frontier: vec![leaf],
        },
        nonces: vec![],
        outbox: vec![OutboxRow {
            pos,
            idx: 0,
            event_id: access_crypto::random::bytes::<32>().unwrap(),
            event: event.to_bytes().unwrap(),
            trace_parent: None,
        }],
        proofs: vec![],
        reads: vec![],
        writes: vec![],
        draws: vec![],
        single_use: vec![],
        effects: vec![],
    };
    commit_batch(&db.sequencer, domain, *tenant.as_bytes(), &batch)
        .await
        .unwrap();
}

impl World {
    /// A subject of the realm with one sign-in notice queued for it beside a business change.
    async fn queue_notice(&self) -> String {
        self.subject_with_notice().await.1
    }

    async fn subject_with_notice(&self) -> ([u8; 16], String) {
        let kek = self.keks.kek(self.tenant, self.realm).unwrap();
        let ids = IdKey::new(Secret::new(
            crate::login::id_key_bytes(&self.store).unwrap(),
        ));
        let realm = Realm {
            tenant: self.tenant,
            realm: self.realm,
            kek: &*kek,
            ids: &ids,
        };
        let pg = PgAccounts::sealed(self.db.app.clone(), self.keks.vault(self.realm).unwrap());
        let who = format!("{}@example.com", random_hex());
        let id = Identifier::new(IdentifierKind::Email, &who).unwrap();
        let s = create(&pg, &realm, &[id], &ADMIN).await.unwrap();
        let notifier = OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock);
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        tx.end_sessions(s).await.unwrap();
        let message = Message {
            subject: s,
            to: Address::Email(who),
            locale: None,
            valid_since_ms: Some(1_700_000_000_000),
            body: Body::NewSignIn {
                at_ms: 1_800_000_000_000,
                method: SignInMethod::Passkey,
            },
        };
        let id = notifier.notify(&mut tx, &message).await.unwrap();
        tx.commit().await.unwrap();
        (s, id.to_string())
    }

    fn start(&self, prepared: Prepared, flag: &ReadyFlag) -> Running {
        start(
            prepared,
            (
                self.db.reader.clone(),
                self.db.app.clone(),
                self.db.router.clone(),
            ),
            self.keks.clone(),
            crate::login::id_key_bytes(&self.store).unwrap(),
            format!("relay/{}", random_hex()),
            flag,
        )
    }

    async fn status(&self) -> Value {
        let r = routes(self.db.reader.clone(), self.db.app.clone())
            .oneshot(
                axum::http::Request::get(STATUS_PATH)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let b = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        serde_json::from_slice(&b).unwrap()
    }
}

// E42, OP-156 m.3 (c)
#[tokio::test]
async fn the_server_courier_delivers_to_relay_once_relay_is_confirmed() {
    let w = world().await;
    let token = random_hex();
    let twin = RelayTwin::start(&token, ISSUER).await;
    let c = config(&twin, file("credential", &token));
    let prepared = prepare(&c, &[]).unwrap();
    let id = w.queue_notice().await;
    let ready = access_http::internal::Readiness::default();
    let flag = ready.flag("outbox.consumers");
    flag.set(true);
    let running = w.start(prepared, &flag);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !twin.accepted().contains(&id) {
        assert!(Instant::now() < deadline, "not delivered in 30 s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let post = twin.posts().into_iter().find(|p| p.id == id).unwrap();
    assert_eq!(post.schema_errors, Vec::<String>::new());
    assert_eq!(post.event["type"], "relay.message.new_sign_in.v1");
    while w.status().await != json!({ "relay_lag_ms": null, "notifications_delayed": false }) {
        assert!(
            Instant::now() < deadline,
            "the cursor never passed the message"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    running.stop().await;
    assert!(!ready.failing().await.contains(&"outbox.consumers"));
    let lease = access_store::relay::acquire_courier_lease(
        &w.db.reader,
        access_identity_account::notify::courier::CONSUMER,
        "another-node",
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert!(lease.is_some(), "a stopped server gives the lease up");
}

// E42 m.5, INV-24, OP-156 m.3 (c)
#[tokio::test]
async fn an_unconfirmed_relay_gets_nothing_and_messages_wait() {
    let w = world().await;
    let token = random_hex();
    let twin = RelayTwin::start(&token, "https://another-access.test").await;
    let c = config(&twin, file("credential", &token));
    let id = w.queue_notice().await;
    let ready = access_http::internal::Readiness::default();
    let flag = ready.flag("outbox.consumers");
    flag.set(true);
    let running = w.start(prepare(&c, &[]).unwrap(), &flag);
    let deadline = Instant::now() + Duration::from_secs(30);
    while twin.discoveries() == 0 {
        assert!(Instant::now() < deadline, "discovery not read in 30 s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let status = loop {
        let s = w.status().await;
        if s["relay_lag_ms"].is_u64() {
            break s;
        }
        assert!(
            Instant::now() < deadline,
            "the message never showed as waiting"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(status["notifications_delayed"], false);
    running.stop().await;
    assert_eq!(
        twin.posts().len(),
        0,
        "nothing reached a Relay of another Access: {id}"
    );
    assert!(!ready.failing().await.contains(&"outbox.consumers"));
}

// OP-156 m.3 (c)
#[test]
fn the_discovery_document_must_name_this_access_and_relay() {
    let relay = "https://relay.test";
    let good = json!({
        "issuer": relay,
        "access_issuer": ISSUER,
        "capabilities": ["urn:suiss:relay:events:1"],
        "events_endpoint": "https://relay.test/v1/events",
    });
    assert_eq!(
        check_discovery(&good, relay, ISSUER),
        Ok(String::from("https://relay.test/v1/events"))
    );
    let with = |k: &str, v: Value| {
        let mut d = good.clone();
        d[k] = v;
        check_discovery(&d, relay, ISSUER)
    };
    assert_eq!(
        with("issuer", json!("https://relay.test/")),
        Err(DiscoveryMismatch::Issuer)
    );
    assert_eq!(
        with("access_issuer", json!("https://other.test")),
        Err(DiscoveryMismatch::AccessIssuer)
    );
    assert_eq!(
        with("capabilities", json!([])),
        Err(DiscoveryMismatch::NoEvents)
    );
    for elsewhere in [
        "https://relay.test.evil/v1/events",
        "https://evil.test/v1/events",
        "https://relay.test:8443/v1/events",
    ] {
        assert_eq!(
            with("events_endpoint", json!(elsewhere)),
            Err(DiscoveryMismatch::Endpoint),
            "{elsewhere}"
        );
    }
    assert_eq!(
        check_discovery(&json!([]), relay, ISSUER),
        Err(DiscoveryMismatch::Malformed)
    );
}

// TI-9, OP-156 m.3 (c)
#[tokio::test]
async fn the_server_does_not_start_without_the_relay_credential() {
    let twin = RelayTwin::start(&random_hex(), ISSUER).await;
    let c = config(
        &twin,
        std::env::temp_dir().join(format!("absent-{}", random_hex())),
    );
    assert!(prepare(&c, &[]).is_err());
    let open = file("open", "x");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    assert!(prepare(&config(&twin, open), &[]).is_err());
    assert_eq!(body(Some(DELAYED_MS + 1))["notifications_delayed"], true);
    assert_eq!(body(Some(DELAYED_MS))["notifications_delayed"], false);
}

/// The webhook courier's requests, over TLS to the twin on its local port, whatever host the
/// stream names.
#[derive(Clone)]
struct ToTwin(Arc<rustls::ClientConfig>, u16);

impl access_identity_events::ports::Transport for ToTwin {
    async fn post(
        &self,
        url: &str,
        content_type: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<access_identity_events::ports::Reply, access_identity_events::ports::PostError>
    {
        use access_identity_events::ports::{PostError, Reply};
        use access_identity_oauth::adapters::outbound::{Target, post_over, post_request};
        let target = Target::parse(url).map_err(|_| PostError::Refused)?;
        let request =
            post_request(&target, content_type, headers, body).map_err(|_| PostError::Refused)?;
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", self.1))
            .await
            .map_err(|_| PostError::Unreachable)?;
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut s = tokio_rustls::TlsConnector::from(self.0.clone())
            .connect(name, tcp)
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

// TN-136, E42, OP-156 m.3 (c)
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end delivery from a committed authority record"
)]
async fn relay_consumes_authority_events_as_an_ordinary_receiver() {
    use access_crypto::webhook::WebhookSecret;
    use access_identity_events::adapters::KekSealer;
    use access_identity_events::app::streams::Streams;
    use access_identity_events::domain::catalog::urn;
    use access_identity_events::domain::stream::parse_stream;
    use access_identity_oauth::adapters::SignerKeys;
    use access_identity_oauth::adapters::oauth::OsRandom;
    use access_identity_oauth::adapters::outbound::DeclaredTargets;
    use access_internal_api::events::{Event, Kind, Source, Subject};
    use access_kernel::digest::Digest;
    use access_kernel::model::Id;
    use access_store::authority::{CommitBatch, HeadRow, OutboxRow, acquire_lease, commit_batch};

    let db = fresh().await.unwrap();
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let domain = DomainId::from_bytes(access_crypto::random::bytes::<32>().unwrap());
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
    assert!(
        access_store::tenancy::set_issuer(&mut t, "https://id.test/realms/shop")
            .await
            .unwrap()
    );
    access_store::idp::create_settings(&mut t).await.unwrap();
    t.commit().await.unwrap();
    let store = STORE
        .get_or_init(|| {
            let (module, label) = hsm("relay");
            let pin = access_crypto::Secret::new(String::from("1234-test-only"));
            Arc::new(KeyStore::open(&module, &label, &pin).unwrap())
        })
        .clone();
    store.generate_kek(&kek_label(realm.as_bytes())).unwrap();
    if store.mac(crate::login::ID_KEY_ROOT).is_err() {
        store.generate_mac(crate::login::ID_KEY_ROOT).unwrap();
    }
    let keks = RealmKeks::new(store.clone());
    let pools = crate::events::EventPools {
        wake: None,
        app: db.app.clone(),
        reader: db.reader.clone(),
        router: db.router.clone(),
        ids: Arc::new(crate::ids::CellIds::new(store.clone())),
        declared: DeclaredTargets::default(),
        outbound: None,
    };
    let twin = RelayTwin::start(&random_hex(), ISSUER).await;
    let request = json!({
        "delivery": {
            "method": "urn:suiss:access:delivery:webhook",
            "endpoint_url": "https://relay.test/v1/access/events",
        },
        "aud": "relay",
        "events_requested": [urn("authority-revoked")],
    });
    let hook = Streams::new(pools.db(), KekSealer(keks.clone()), OsRandom)
        .create(
            tenant,
            realm,
            &parse_stream(&serde_json::to_vec(&request).unwrap()).unwrap(),
        )
        .await
        .unwrap();
    let secret = WebhookSecret::parse(&hook.secret.clone().unwrap()).unwrap();
    let (lease, head) = acquire_lease(&db.sequencer, &domain, "t", Duration::from_secs(10))
        .await
        .unwrap();
    let pos = head.pos + 1;
    let event = Event {
        kind: Kind::AuthorityRevoked,
        domain: Digest(*domain.as_bytes()),
        source: Source::Exercise(Digest([9; 32])),
        subject: Subject::Grant(Id([2; 16])),
        at: 1_793_750_400_000,
        detail: access_internal_api::events::Detail::None,
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
        head: HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: [8; 32],
            recorded_at: 2,
            frontier: vec![[8; 32]],
        },
        nonces: vec![],
        outbox: vec![OutboxRow {
            pos,
            idx: 0,
            event_id: [42; 32],
            event: event.to_bytes().unwrap(),
            trace_parent: None,
        }],
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

    let ready = access_http::internal::Readiness::default();
    let consumers = ready.flag("outbox.consumers");
    consumers.set(true);
    let delivery = crate::events::Delivery::start(
        &pools,
        ToTwin(
            twin.tls.clone(),
            twin.base.rsplit_once(':').unwrap().1.parse().unwrap(),
        ),
        SignerKeys::new("/nonexistent.sock".into()),
        keks,
        &consumers,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while twin.received().is_empty() {
        assert!(Instant::now() < deadline, "not delivered in 30 s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    delivery.stop().await;
    let got = twin.received().remove(0);
    let h = |n: &str| {
        got.headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    let ts: u64 = h("webhook-timestamp").parse().unwrap();
    assert!(secret.verify(&h("webhook-id"), ts, &got.body, &h("webhook-signature"), ts));
    let ce: Value = serde_json::from_slice(&got.body).unwrap();
    assert_eq!(ce["type"], urn("authority-revoked"));
    assert_eq!(ce["specversion"], "1.0");
}

// OP-156 m.3 (c), INV-24, §8.6
#[tokio::test]
async fn an_ended_instance_reaches_its_person_as_a_security_notice_without_action_required() {
    use access_identity_account::notify::notices::REVIEW_PATH;
    use access_internal_api::events::{Detail, Event, Kind, Source, Subject};
    use access_kernel::digest::Digest;
    use access_kernel::model::Id;
    let w = world().await;
    let (subject, _) = w.subject_with_notice().await;
    let party = access_crypto::random::bytes::<16>().unwrap();
    let mut t = TenantTx::begin(&w.db.app, w.tenant, w.realm).await.unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &subject, &party)
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    for (kind, detail) in [
        (
            Kind::InstanceTerminated,
            Detail::Instance { party: Id(party) },
        ),
        (Kind::AuthorityRevoked, Detail::None),
    ] {
        authority_event(
            &w.db,
            w.tenant,
            &w.domain,
            &Event {
                kind,
                domain: Digest(*w.domain.as_bytes()),
                source: Source::Exercise(Digest([9; 32])),
                subject: Subject::Instance(Id([3; 16])),
                at: 1_800_000_000_000,
                detail,
            },
        )
        .await;
    }
    let pools = NoticePools {
        app: w.db.app.clone(),
        router: w.db.router.clone(),
        reader: w.db.reader.clone(),
    };
    let ids = IdKey::new(Secret::new(crate::login::id_key_bytes(&w.store).unwrap()));
    assert_eq!(notices_step(&pools, &w.keks, &ids).await.unwrap(), 1);
    assert_eq!(
        notices_step(&pools, &w.keks, &ids).await.unwrap(),
        0,
        "the cursor passed it"
    );

    let token = random_hex();
    let twin = RelayTwin::start(&token, ISSUER).await;
    let c = config(&twin, file("credential", &token));
    let ready = access_http::internal::Readiness::default();
    let flag = ready.flag("outbox.consumers");
    flag.set(true);
    let running = w.start(prepare(&c, &[]).unwrap(), &flag);
    let deadline = Instant::now() + Duration::from_secs(30);
    let post = loop {
        if let Some(p) = twin
            .posts()
            .into_iter()
            .find(|p| p.event["type"] == "relay.message.security_authority_notice.v1")
        {
            break p;
        }
        assert!(Instant::now() < deadline, "no notice in 30 s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    running.stop().await;
    assert_eq!(post.schema_errors, Vec::<String>::new());
    assert_eq!(post.event["data"]["event"], "instance_ended");
    assert_eq!(
        post.event["data"]["review_link"],
        format!("https://id.test/realms/shop{REVIEW_PATH}")
    );
    let text = post.event.to_string().to_ascii_lowercase();
    assert!(!text.contains("action required") && !text.contains("action_required"));
}
