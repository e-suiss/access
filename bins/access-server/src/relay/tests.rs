#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
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
        store,
    }
}

impl World {
    /// A subject of the realm with one sign-in notice queued for it beside a business change.
    async fn queue_notice(&self) -> String {
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
        id.to_string()
    }

    fn start(&self, prepared: Prepared, flag: &ReadyFlag) -> Running {
        start(
            prepared,
            (self.db.reader.clone(), self.db.app.clone()),
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

// E42, OP-156 m.3 (c), Ek B 5401, 5393: the server's courier takes the outbox to Relay
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
    assert_eq!(
        w.status().await,
        json!({ "relay_lag_ms": null, "notifications_delayed": false })
    );
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

// E42 m.5, INV-24, OP-156 m.3 (c): a Relay that is not this Access's gets nothing; the change
// that queued the message is in force, the message waits and the lag shows it
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

// OP-156 m.3 (c), Relay E-81
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

// TI-9, OP-156 m.3 (c): no credential, no start
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
