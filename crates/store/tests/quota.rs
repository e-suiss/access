//! OP-158 m.3 (v), T27, TN-24, OP-35 layer B: the quota counters on a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::quota::{
    CommitRefusal, Rate, RequestRefusal, set_billing_hold, take_commit, take_request,
};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};

const NOW: u64 = 1_000_000;

async fn domain(db: &TestDb, tenant: TenantId, seed: u8) -> DomainId {
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
    d
}

async fn realm(db: &TestDb, tenant: TenantId, d: &DomainId, slug: &str) -> RealmId {
    let mut tx = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    let r = create_realm(&mut tx, d, slug, "pool-default")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    r
}

const fn rate(per_second: u32, burst: u32) -> Rate {
    Rate { per_second, burst }
}

// T27, TN-24, §12.1.3
#[tokio::test]
async fn a_full_domain_quota_refuses_only_that_domain() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let hot = domain(&db, t, 1).await;
    let quiet = domain(&db, t, 2).await;
    let (tenant, own) = (rate(1_000, 100), rate(10, 3));
    for _ in 0..3 {
        assert_eq!(
            take_commit(&db.app, &hot, NOW, tenant, own).await.unwrap(),
            None
        );
    }
    assert_eq!(
        take_commit(&db.app, &hot, NOW, tenant, own).await.unwrap(),
        Some(CommitRefusal::Domain)
    );
    assert_eq!(
        take_commit(&db.app, &quiet, NOW, tenant, own)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        take_commit(&db.app, &hot, NOW + 100, tenant, own)
            .await
            .unwrap(),
        None
    );
}

// TN-24
#[tokio::test]
async fn the_tenant_quota_spans_its_domains_and_a_refusal_draws_nothing() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let a = domain(&db, t, 3).await;
    let b = domain(&db, t, 4).await;
    let (tenant, own) = (rate(10, 2), rate(10, 2));
    assert_eq!(
        take_commit(&db.app, &a, NOW, tenant, own).await.unwrap(),
        None
    );
    assert_eq!(
        take_commit(&db.app, &b, NOW, tenant, own).await.unwrap(),
        None
    );
    assert_eq!(
        take_commit(&db.app, &b, NOW, tenant, own).await.unwrap(),
        Some(CommitRefusal::Tenant)
    );
    assert_eq!(
        take_commit(&db.app, &b, NOW + 100, tenant, own)
            .await
            .unwrap(),
        None,
        "the refused take left the domain's counter as it was"
    );

    let other = create_tenant(&db.app, "pool-default").await.unwrap();
    let c = domain(&db, other, 5).await;
    assert_eq!(
        take_commit(&db.app, &c, NOW, tenant, own).await.unwrap(),
        None
    );
}

// TN-1, B10, MD-8
#[tokio::test]
async fn a_billing_hold_refuses_widening_commits_until_it_is_lifted() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 6).await;
    let (tenant, own) = (rate(100, 10), rate(100, 10));
    assert!(set_billing_hold(&db.app, t, true).await.unwrap());
    assert_eq!(
        take_commit(&db.app, &d, NOW, tenant, own).await.unwrap(),
        Some(CommitRefusal::Suspended)
    );
    assert!(set_billing_hold(&db.app, t, false).await.unwrap());
    assert_eq!(
        take_commit(&db.app, &d, NOW, tenant, own).await.unwrap(),
        None
    );
}

// OP-35, MD-8
#[tokio::test]
async fn a_malformed_limit_is_an_error_never_an_admission() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 7).await;
    assert!(
        take_commit(&db.app, &d, NOW, rate(0, 1), rate(10, 1))
            .await
            .is_err()
    );
    let unknown = DomainId::from_bytes([0x55; 32]);
    assert!(
        take_commit(&db.app, &unknown, NOW, rate(10, 1), rate(10, 1))
            .await
            .is_err()
    );
}

// OP-35, TN-24
#[tokio::test]
async fn a_realm_request_quota_follows_its_rate_limit() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 8).await;
    let busy = realm(&db, t, &d, "busy").await;
    let calm = realm(&db, t, &d, "calm").await;
    let take = |r| take_request(&db.app, (t, r), NOW, (2, 1_000), 1);
    let first = take(busy).await.unwrap();
    assert_eq!((first.refused, first.used_percent), (None, 50));
    assert_eq!(take(busy).await.unwrap().refused, None);
    let over = take(busy).await.unwrap();
    assert_eq!(
        (over.refused, over.used_percent),
        (Some(RequestRefusal::Realm), 100)
    );
    assert_eq!(take(calm).await.unwrap().refused, None);
    assert_eq!(
        take_request(&db.app, (t, calm), NOW, (100, 1), 1)
            .await
            .unwrap()
            .refused,
        Some(RequestRefusal::Tenant)
    );
}

// MD-8
#[tokio::test]
async fn a_clock_stepped_back_is_refused_for_one_burst_window_only() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 9).await;
    let (tenant, own) = (rate(1_000, 1_000), rate(10, 2));
    let hour = 3_600_000;
    assert_eq!(
        take_commit(&db.app, &d, NOW + hour, tenant, own)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        take_commit(&db.app, &d, NOW, tenant, own).await.unwrap(),
        Some(CommitRefusal::Tenant)
    );
    assert_eq!(
        take_commit(&db.app, &d, NOW + 1_100, tenant, own)
            .await
            .unwrap(),
        None,
        "past the longest burst window (the tenant's second) it admits again"
    );
}
