//! OP-156 m.3 (i), OP-73, OP-41: the pass over a realm's custom domains on the real store. Both
//! DNS records verify a registration; the twin issues its certificate, whose key is sealed under
//! the realm KEK and served; a removed record lapses it, and a lapsed domain is neither served
//! nor renewed. A DNS outage changes nothing.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use access_identity_domain::adapters::seal::{KeySeal, RealmKek};
use access_identity_domain::app::acme::Client;
use access_identity_domain::app::pass::{self, Acme, Pass};
use access_identity_domain::domain::host::{Base, CustomHost};
use access_identity_domain::testing::{
    AcmeTwin, FakeDns, MemChallenges, NoPause, SoftAccount, TWIN_DIRECTORY, Validation,
};
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::custom_domains::{self as cd, NewDomain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{Decision, bind, create_settings};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use suiss_crypto::envelope::{Kek, SoftKek};

const TTL: Duration = Duration::from_secs(10);
const INTENT: [u8; 32] = [9; 32];
const HOST: &str = "login.acme.example";
const CHALLENGE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn domain(db: &TestDb, t: TenantId, seed: u8) -> DomainId {
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *t.as_bytes(), &g, &[])
        .await
        .unwrap();
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    let pos = head.pos + 1;
    let leaf = [seed.wrapping_add(1); 32];
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
            envelope: vec![0xa1, 1],
        }],
        head: next,
        nonces: vec![NonceRow {
            nonce: vec![1; 16],
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
    commit_batch(&db.sequencer, &d, *t.as_bytes(), &batch)
        .await
        .unwrap();
    d
}

async fn registered(db: &TestDb) -> (TenantId, RealmId) {
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(db, t, 80).await;
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, &d, "acme", "pool-default")
        .await
        .unwrap();
    tx.enter_realm(r).await.unwrap();
    create_settings(&mut tx).await.unwrap();
    let b = bind(
        &mut tx,
        &Decision {
            domain: &d,
            position: 1,
            nonce: &[1; 16],
            intent: INTENT,
            change: [5; 32],
            action: "idp.domain.register",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let host = CustomHost::parse(HOST, &Base::new("suiss.id")).unwrap();
    cd::register(
        &mut tx,
        &b,
        &NewDomain {
            id: [1; 16],
            hostname: host.as_str(),
            challenge: CHALLENGE,
            cname_target: "acme.suiss.id",
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    (t, r)
}

struct OneKek(Arc<SoftKek>);

impl RealmKek for OneKek {
    fn kek(&self, _: TenantId, _: RealmId) -> Option<Arc<dyn Kek + Send + Sync>> {
        Some(self.0.clone())
    }
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

async fn status(db: &TestDb, scope: (TenantId, RealmId)) -> String {
    let mut tx = TenantTx::begin(&db.app, scope.0, scope.1).await.unwrap();
    let s = cd::domains(&mut tx).await.unwrap().remove(0).status;
    tx.commit().await.unwrap();
    s
}

async fn audit_events(db: &TestDb, scope: (TenantId, RealmId)) -> Vec<String> {
    let mut tx = TenantTx::begin(&db.app, scope.0, scope.1).await.unwrap();
    let page = tx.audit_page(None, 100).await.unwrap();
    tx.commit().await.unwrap();
    page.into_iter().map(|r| r.event_type).collect()
}

// OP-156 m.3 (i), OP-73, OP-41
#[tokio::test]
async fn a_verified_domain_gets_its_certificate_and_a_lapsed_one_is_neither_served_nor_renewed() {
    let db = fresh().await.unwrap();
    let scope = registered(&db).await;
    let dns = FakeDns::default();
    let board = Arc::new(MemChallenges::default());
    let twin = AcmeTwin::new(Validation::Board(board.clone()));
    let account = SoftAccount::generate();
    let keys = KeySeal(OneKek(Arc::new(SoftKek::new(
        "kek-1",
        access_crypto::random::bytes::<32>().unwrap(),
    ))));
    let p = Pass {
        app: &db.app,
        dns: &dns,
        acme: Some(Acme {
            client: Client {
                http: &twin,
                key: &account,
                pause: &NoPause,
                directory: TWIN_DIRECTORY,
                contact: None,
            },
        }),
        challenges: &board,
        keys: &keys,
    };
    let t0 = now();

    let out = p.realm(scope, t0).await.unwrap();
    assert_eq!((out.verified, out.issued), (0, 0));
    assert_eq!(status(&db, scope).await, "pending");

    dns.down.store(true, Ordering::SeqCst);
    dns.publish(HOST, CHALLENGE, "acme.suiss.id");
    let out = p.realm(scope, t0 + 600).await.unwrap();
    assert_eq!(out.unavailable, 1);
    assert_eq!(status(&db, scope).await, "pending");
    dns.down.store(false, Ordering::SeqCst);

    let out = p.realm(scope, t0 + 1200).await.unwrap();
    assert_eq!((out.verified, out.issued), (1, 1));
    assert_eq!(status(&db, scope).await, "verified");
    let hosts = cd::served_hosts(&db.router).await.unwrap();
    assert_eq!(hosts, [HOST]);
    let served = pass::served(&db.app, &keys, scope, &hosts, t0 + 1200)
        .await
        .unwrap();
    assert_eq!(served.len(), 1);
    assert_eq!(served[0].host, HOST);
    let leaf = access_identity_domain::x509::read_leaf(&served[0].chain[0]).unwrap();
    assert_eq!(leaf.dns_names, [HOST]);

    let out = p.realm(scope, t0 + 1800).await.unwrap();
    assert_eq!(out.issued, 0);
    assert_eq!(twin.issued(), 1);

    dns.remove_challenge(HOST);
    let later = t0 + 1200 + 86_400;
    let out = p.realm(scope, later).await.unwrap();
    assert_eq!((out.lapsed, out.issued), (1, 0));
    assert_eq!(status(&db, scope).await, "lapsed");
    assert_eq!(
        cd::served_hosts(&db.router).await.unwrap(),
        Vec::<String>::new()
    );
    assert!(
        cd::route_by_custom_host(&db.router, HOST)
            .await
            .unwrap()
            .is_none()
    );
    let renewal_due = later + 61 * 86_400;
    let out = p.realm(scope, renewal_due).await.unwrap();
    assert_eq!(out.issued, 0);
    assert_eq!(twin.issued(), 1);

    let events = audit_events(&db, scope).await;
    for e in [
        "domain.verified",
        "acme.certificate_issued",
        "domain.verification_failed",
    ] {
        assert!(events.iter().any(|x| x == e), "{e}: {events:?}");
    }
}

// OP-156 m.3 (i)
#[tokio::test]
async fn a_failed_order_is_recorded_and_retried_later() {
    let db = fresh().await.unwrap();
    let scope = registered(&db).await;
    let dns = FakeDns::default();
    dns.publish(HOST, CHALLENGE, "acme.suiss.id");
    let board = Arc::new(MemChallenges::default());
    let twin = AcmeTwin::new(Validation::Board(board.clone()));
    twin.refuse_finalize(true);
    let account = SoftAccount::generate();
    let keys = KeySeal(OneKek(Arc::new(SoftKek::new(
        "kek-1",
        access_crypto::random::bytes::<32>().unwrap(),
    ))));
    let p = Pass {
        app: &db.app,
        dns: &dns,
        acme: Some(Acme {
            client: Client {
                http: &twin,
                key: &account,
                pause: &NoPause,
                directory: TWIN_DIRECTORY,
                contact: None,
            },
        }),
        challenges: &board,
        keys: &keys,
    };
    let t0 = now();
    let out = p.realm(scope, t0).await.unwrap();
    assert_eq!((out.verified, out.failed), (1, 1));
    let mut tx = TenantTx::begin(&db.app, scope.0, scope.1).await.unwrap();
    let row = cd::domains(&mut tx).await.unwrap().remove(0);
    tx.commit().await.unwrap();
    assert_eq!(row.acme_failures, 1);
    assert_eq!(row.acme_error.as_deref(), Some("acme-refused"));
    assert!(row.acme_next_at.unwrap() > t0);
    twin.refuse_finalize(false);
    assert_eq!(p.realm(scope, t0 + 1).await.unwrap().issued, 0);
    assert_eq!(
        p.realm(scope, row.acme_next_at.unwrap())
            .await
            .unwrap()
            .issued,
        1
    );
    assert!(
        audit_events(&db, scope)
            .await
            .iter()
            .any(|e| e == "acme.order_failed")
    );
}
