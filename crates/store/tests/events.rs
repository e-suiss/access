//! OP-149 m.17 (e), OP-131, TN-1: the outbox reader finds platform products' subscriptions
//! across tenants and nothing else of the subscription table.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::authority::{LogRecord, create_domain};
use access_store::events::{SubscriptionRow, platform_subscriptions};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};

async fn realm(db: &TestDb, seed: u8, slug: &str) -> (TenantId, RealmId) {
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
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
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, &d, slug, "pool-default")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (t, r)
}

fn push(realm: RealmId, id: u8, owner: Option<&str>) -> SubscriptionRow {
    SubscriptionRow {
        realm: *realm.as_bytes(),
        id: [id; 16],
        channel: String::from("ssf_push"),
        endpoint: Some(String::from("https://work.example/ssf")),
        audience: String::from("work"),
        events: vec![String::from("urn:suiss:access:event:tenant.created")],
        description: None,
        secret: None,
        token_digest: None,
        status: String::from("enabled"),
        disabled: false,
        owner_client_id: owner.map(String::from),
        platform_product: owner.map(|_| String::from("work")),
    }
}

// OP-149 m.17 (e), TN-1, OP-131: the reader lists the live platform subscriptions of every
// tenant, never a tenant's own stream, and cannot read the rest of a row
#[tokio::test]
async fn the_reader_sees_only_platform_subscriptions() {
    let db = fresh().await.unwrap();
    let (pt, pr) = realm(&db, 1, "platform").await;
    let (t2, r2) = realm(&db, 2, "acme").await;
    let mut tx = TenantTx::begin(&db.app, pt, pr).await.unwrap();
    tx.insert_subscription(&push(pr, 1, Some("cli_work")))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, t2, r2).await.unwrap();
    tx.insert_subscription(&push(r2, 2, None)).await.unwrap();
    tx.commit().await.unwrap();

    let listed = platform_subscriptions(&db.reader).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].tenant == pt && listed[0].realm == pr);
    assert_eq!(listed[0].id, [1; 16]);

    let denied = sqlx::query("SELECT audience FROM access.event_subscription")
        .fetch_all(&db.reader)
        .await;
    assert!(denied.is_err());
    let mut tx = TenantTx::begin(&db.app, pt, pr).await.unwrap();
    assert!(tx.disable_subscription(pr, [1; 16]).await.unwrap());
    tx.commit().await.unwrap();
    assert!(platform_subscriptions(&db.reader).await.unwrap().is_empty());
}
