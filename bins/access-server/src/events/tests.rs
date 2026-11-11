#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_crypto::secret::Secret;
use access_crypto::webhook::WebhookSecret;
use access_identity_events::app::emit;
use access_identity_events::domain::catalog::{ClientChange, IdentityEvent, IdentityKind, urn};
use access_identity_events::domain::stream::parse_stream;
use access_identity_events::ports::{PostError, Reply};
use access_identity_oauth::adapters::outbound::{DeclaredTargets, Target, post_over, post_request};
use access_internal_api::events::{Detail, Event, Kind, ReasonClass, Source, Subject};
use access_kernel::digest::Digest;
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
use suiss_crypto::pkcs11::KeyStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::login::kek_label;
use crate::testing::hsm;

const ISSUER: &str = "https://id.test/realms/shop";

/// The token stays open for the process: `SoftHSM` does not survive closing it under a test.
static STORE: std::sync::OnceLock<Arc<KeyStore>> = std::sync::OnceLock::new();

/// What a local receiver got: headers and body of each request.
type Got = Arc<Mutex<Vec<(Vec<(String, String)>, Vec<u8>)>>>;

/// A receiver on a local port that answers 202 to everything.
async fn receiver() -> (u16, Got) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let got: Got = Arc::default();
    let into = got.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0_u8; 4096];
            let (head, at, len) = loop {
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
                    break (head, i + 4, len);
                }
            };
            while buf.len() < at + len {
                let n = s.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
            }
            let headers = head
                .lines()
                .skip(1)
                .filter_map(|l| l.split_once(": "))
                .map(|(n, v)| (n.to_ascii_lowercase(), v.to_owned()))
                .collect();
            into.lock()
                .unwrap()
                .push((headers, buf[at..at + len].to_vec()));
            s.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        }
    });
    (port, got)
}

/// The request the outbound client would send, over plain TCP to the local receiver.
#[derive(Clone)]
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

/// A tenant with one realm, its issuer and governing domain.
async fn realm(db: &TestDb) -> (TenantId, RealmId, DomainId) {
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
    assert!(set_issuer(&mut t, ISSUER).await.unwrap());
    create_settings(&mut t).await.unwrap();
    t.commit().await.unwrap();
    (tenant, realm, domain)
}

/// Commits one record with `event` in its outbox, as the sequencer does.
async fn authority_event(db: &TestDb, tenant: TenantId, domain: &DomainId, event: &Event) {
    let (lease, head) = acquire_lease(&db.sequencer, domain, "t", Duration::from_secs(10))
        .await
        .unwrap();
    let pos = head.pos + 1;
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
            event_id: [41; 32],
            event: event.to_bytes().unwrap(),
            trace_parent: None,
        }],
        proofs: vec![],
        reads: vec![],
        writes: vec![],
        draws: vec![],
        single_use: vec![],
        beside: vec![],
        effects: vec![],
    };
    commit_batch(&db.sequencer, domain, *tenant.as_bytes(), &batch)
        .await
        .unwrap();
}

// OP-149 m.17a, m.4, m.7, OP-131
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end delivery with its readiness flag (A-7)"
)]
async fn the_server_delivers_events_to_a_webhook() {
    // OP-149 m.17 (b), OP-42, OP-135
    let db = fresh().await.unwrap();
    let (tenant, realm, domain) = realm(&db).await;
    let store = STORE
        .get_or_init(|| {
            let (module, label) = hsm("events");
            let pin = Secret::new(String::from("1234-test-only"));
            Arc::new(KeyStore::open(&module, &label, &pin).unwrap())
        })
        .clone();
    store.generate_kek(&kek_label(realm.as_bytes())).unwrap();
    if store.mac(crate::login::ID_KEY_ROOT).is_err() {
        store.generate_mac(crate::login::ID_KEY_ROOT).unwrap();
    }
    let keks = RealmKeks::new(store.clone());
    let pools = EventPools {
        app: db.app.clone(),
        reader: db.reader.clone(),
        router: db.router.clone(),
        ids: Arc::new(crate::ids::CellIds::new(store.clone())),
        declared: DeclaredTargets::default(),
        outbound: None,
        wake: None,
    };
    let tenant_id = pools.ids.external(tenant.as_bytes()).unwrap();
    let request = serde_json::json!({
        "delivery": {
            "method": "urn:suiss:access:delivery:webhook",
            "endpoint_url": "https://work.example/v1/access/events",
        },
        "aud": "work",
        "events_requested": [urn("api_client.created"), urn("party.disabled")],
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

    let mut t = TenantTx::begin(&db.app, tenant, realm).await.unwrap();
    let event = IdentityEvent::api_client(
        IdentityKind::ApiClientCreated,
        [1; 32],
        &ClientChange {
            tenant: &tenant_id,
            realm: realm.as_bytes(),
            client_id: "cli_shop",
            exercise: &[3; 32],
            platform_product: None,
            at: 1_793_750_400_000,
        },
    );
    emit(&mut t, &event).await.unwrap();
    t.commit().await.unwrap();
    authority_event(
        &db,
        tenant,
        &domain,
        &Event {
            kind: Kind::PartyDisabled,
            domain: Digest(*domain.as_bytes()),
            source: Source::Exercise(Digest([9; 32])),
            subject: Subject::Party(Id([2; 16])),
            at: 1_793_750_400_000,
            detail: Detail::Disabled {
                reason: ReasonClass::Departed,
            },
        },
    )
    .await;

    let (port, got) = receiver().await;
    // A-7, OP-67 m.3
    let ready = access_http::internal::Readiness::default();
    let consumers = ready.flag("outbox.consumers");
    consumers.set(true);
    let delivery = Delivery::start(
        &pools,
        Local(port),
        SignerKeys::new("/nonexistent.sock".into()),
        keks,
        &consumers,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while got.lock().unwrap().len() < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "not delivered in 30 s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!ready.failing().await.contains(&"outbox.consumers"));
    delivery.stop().await;
    // MD-8
    assert!(ready.failing().await.contains(&"outbox.consumers"));

    let mut types = Vec::new();
    for (headers, body) in got.lock().unwrap().iter() {
        let h = |n: &str| headers.iter().find(|(k, _)| k == n).unwrap().1.clone();
        let ts: u64 = h("webhook-timestamp").parse().unwrap();
        assert!(secret.verify(&h("webhook-id"), ts, body, &h("webhook-signature"), ts));
        let ce: Json = serde_json::from_slice(body).unwrap();
        assert_eq!(ce["data"]["iss"], ISSUER);
        // OP-149 m.15 (i)
        assert_eq!(ce["accesstenant"], tenant_id.as_str());
        types.push(ce["type"].as_str().unwrap().to_owned());
    }
    types.sort();
    assert_eq!(types, [urn("api_client.created"), urn("party.disabled")]);
}
