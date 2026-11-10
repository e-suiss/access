//! OP-156 m.3 (i), TN-16, TN-20, EI-25, OP-73: custom domains are registered, retired and bound
//! only under their own committed ALLOWs; one realm holds a host verified; a certificate's key is
//! shredded when it ends; the router reads verified domains and open challenges only.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::Duration;

use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::custom_domains::{
    self as cd, Checked, NewCertificate, NewDomain, active_certificates, domains,
    route_by_custom_host,
};
use access_store::events::SealedKey;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{Bound, Decision, bind, create_settings};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant, set_issuer};
use access_store::testing::{TestDb, fresh};

const TTL: Duration = Duration::from_secs(10);
const INTENT: [u8; 32] = [9; 32];

async fn domain(db: &TestDb, t: TenantId, seed: u8, allows: u8) -> DomainId {
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
    let (lease, mut head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    for i in 1..=allows {
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
        commit_batch(&db.sequencer, &d, *t.as_bytes(), &batch)
            .await
            .unwrap();
        head = next;
    }
    d
}

async fn realm(db: &TestDb, t: TenantId, d: &DomainId, slug: &str) -> RealmId {
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, d, slug, "pool-default")
        .await
        .unwrap();
    tx.enter_realm(r).await.unwrap();
    create_settings(&mut tx).await.unwrap();
    assert!(
        set_issuer(&mut tx, &format!("https://{slug}.suiss.id"))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    r
}

async fn allow(tx: &mut TenantTx, d: &DomainId, pos: u8, action: &str) -> Bound {
    let nonce = [pos; 16];
    bind(
        tx,
        &Decision {
            domain: d,
            position: u64::from(pos),
            nonce: &nonce,
            intent: INTENT,
            change: [5; 32],
            action,
        },
    )
    .await
    .unwrap()
    .unwrap()
}

const CHALLENGE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn new_domain(id: u8) -> NewDomain<'static> {
    NewDomain {
        id: [id; 16],
        hostname: "login.acme.example",
        challenge: CHALLENGE,
        cname_target: "acme.suiss.id",
    }
}

fn checked(id: u8, status: &'static str, now: i64) -> Checked<'static> {
    Checked {
        id: [id; 16],
        status,
        finding: "verified",
        reverify_by: (status == "verified").then_some(now + 90 * 86_400),
        now,
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

fn sealed(seed: u8) -> SealedKey {
    SealedKey {
        kek_id: String::from("kek-1"),
        wrapped_dek: vec![seed; 40],
        nonce: [seed; 12],
        ciphertext: vec![seed; 64],
    }
}

// OP-156 m.3 (i), EI-25, TN-16
#[tokio::test]
async fn registrations_retirement_and_binding_need_their_own_allows() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 40, 4).await;
    let r = realm(&db, t, &d, "acme").await;

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let wrong = allow(&mut tx, &d, 1, "idp.client.register").await;
    assert!(cd::register(&mut tx, &wrong, &new_domain(1)).await.is_err());
    drop(tx);

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = allow(&mut tx, &d, 1, "idp.domain.register").await;
    cd::register(&mut tx, &b, &new_domain(1)).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(
        cd::record_check(&mut tx, &checked(1, "verified", now()))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = allow(&mut tx, &d, 2, "idp.domain.issuer_bind").await;
    assert!(cd::bind(&mut tx, &b, [1; 16], "rp_id").await.unwrap());
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = allow(&mut tx, &d, 3, "idp.domain.issuer_bind").await;
    assert!(!cd::bind(&mut tx, &b, [1; 16], "issuer").await.unwrap());
    let b = allow(&mut tx, &d, 4, "idp.domain.retire").await;
    assert!(!cd::retire(&mut tx, &b, [1; 16]).await.unwrap());
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let row = domains(&mut tx).await.unwrap().remove(0);
    assert_eq!(row.status, "verified");
    assert_eq!(row.bound_as.as_deref(), Some("rp_id"));
    assert_eq!(
        cd::verified_hosts(&mut tx).await.unwrap(),
        ["login.acme.example"]
    );
    tx.commit().await.unwrap();
    assert!(
        sqlx::query(
            "UPDATE access.realm_domains SET bound_as = NULL, bind_pos = NULL, bound_at = NULL"
        )
        .execute(&db.owner)
        .await
        .is_err()
    );
}

// TN-20, §12.3.8
#[tokio::test]
async fn one_realm_serves_a_host_and_the_router_reads_only_verified_domains() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d1 = domain(&db, t, 50, 2).await;
    let d2 = domain(&db, t, 60, 2).await;
    let r1 = realm(&db, t, &d1, "acme").await;
    let r2 = realm(&db, t, &d2, "other").await;
    for (r, d) in [(r1, &d1), (r2, &d2)] {
        let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
        let b = allow(&mut tx, d, 1, "idp.domain.register").await;
        cd::register(&mut tx, &b, &new_domain(1)).await.unwrap();
        tx.commit().await.unwrap();
    }
    assert!(
        route_by_custom_host(&db.router, "login.acme.example")
            .await
            .unwrap()
            .is_none()
    );
    let mut tx = TenantTx::begin(&db.app, t, r1).await.unwrap();
    assert!(
        cd::record_check(&mut tx, &checked(1, "verified", now()))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, t, r2).await.unwrap();
    let e = cd::record_check(&mut tx, &checked(1, "verified", now()))
        .await
        .unwrap_err();
    assert!(e.integrity());
    drop(tx);
    let route = route_by_custom_host(&db.router, "LOGIN.acme.example")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(route.route.realm.as_bytes(), r1.as_bytes());
    assert_eq!(route.route.issuer, "https://acme.suiss.id");
    assert_eq!(
        cd::served_hosts(&db.router).await.unwrap(),
        ["login.acme.example"]
    );

    let mut tx = TenantTx::begin(&db.app, t, r1).await.unwrap();
    cd::open_order(&mut tx, [7; 16], [1; 16], "login.acme.example", &[3; 32])
        .await
        .unwrap();
    assert!(
        cd::open_order(&mut tx, [8; 16], [1; 16], "login.acme.example", &[4; 32])
            .await
            .is_err()
    );
    drop(tx);
    let mut tx = TenantTx::begin(&db.app, t, r1).await.unwrap();
    cd::open_order(&mut tx, [7; 16], [1; 16], "login.acme.example", &[3; 32])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        cd::open_challenges(&db.router).await.unwrap(),
        [(String::from("login.acme.example"), [3; 32])]
    );

    let mut tx = TenantTx::begin(&db.app, t, r1).await.unwrap();
    assert!(
        cd::record_check(&mut tx, &checked(1, "lapsed", now()))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    assert!(
        route_by_custom_host(&db.router, "login.acme.example")
            .await
            .unwrap()
            .is_none()
    );
    let mut tx = TenantTx::begin(&db.app, t, r2).await.unwrap();
    assert!(
        cd::record_check(&mut tx, &checked(1, "verified", now()))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    let route = route_by_custom_host(&db.router, "login.acme.example")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(route.route.realm.as_bytes(), r2.as_bytes());
}

// OP-73, OP-156 m.3 (i)
#[tokio::test]
async fn an_ended_certificate_keeps_its_chain_and_loses_its_key() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 70, 2).await;
    let r = realm(&db, t, &d, "acme").await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = allow(&mut tx, &d, 1, "idp.domain.register").await;
    cd::register(&mut tx, &b, &new_domain(1)).await.unwrap();
    let n = now();
    for seed in [1_u8, 2] {
        cd::put_certificate(
            &mut tx,
            &NewCertificate {
                id: [seed; 16],
                domain: [1; 16],
                hostname: "login.acme.example",
                chain_pem: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
                key: &sealed(seed),
                not_before: n,
                not_after: n + 90 * 86_400,
                renew_after: n + 60 * 86_400,
            },
        )
        .await
        .unwrap();
    }
    let active = active_certificates(&mut tx).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, [2; 16]);
    assert_eq!(active[0].key, sealed(2));
    tx.commit().await.unwrap();
    let shredded: (Option<Vec<u8>>, String) = sqlx::query_as(
        "SELECT key_sealed, status FROM access.domain_certificates WHERE cert_uuid = $1",
    )
    .bind(sqlx::types::Uuid::from_bytes([1; 16]))
    .fetch_one(&db.owner)
    .await
    .unwrap();
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(shredded, (None, String::from("superseded")));
    let b = allow(&mut tx, &d, 2, "idp.domain.retire").await;
    assert!(cd::retire(&mut tx, &b, [1; 16]).await.unwrap());
    assert_eq!(active_certificates(&mut tx).await.unwrap().len(), 0);
    tx.commit().await.unwrap();
    assert!(
        sqlx::query("DELETE FROM access.domain_certificates")
            .execute(&db.owner)
            .await
            .is_err()
    );
}
