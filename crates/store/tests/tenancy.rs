//! TN-1, TN-16, TN-19, TN-20, INV-32, OP-132 and the cross-tenant tests of §12.1.3 that need
//! no endpoint: twin-tenant differential (2), covert channel (5), unset scope (6).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{
    HostKind, add_hostname, create_realm, create_tenant, delete_realm, remove_hostname,
    resolve_host,
};
use access_store::testing::{TestDb, fresh};
use sqlx::Row;

async fn domain(db: &TestDb, tenant: TenantId, seed: u8) -> DomainId {
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *tenant.as_bytes(), &g)
        .await
        .unwrap();
    d
}

/// A tenant with one domain, one realm and one hostname.
async fn tenant(db: &TestDb, seed: u8, slug: &str, host: &str) -> (TenantId, RealmId) {
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(db, t, seed).await;
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, &d, slug, "pool-default")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    add_hostname(&mut tx, host, HostKind::Subdomain)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (t, r)
}

async fn visible(db: &TestDb, t: TenantId, r: Option<RealmId>, table: &str) -> Vec<[u8; 16]> {
    let tx = match r {
        Some(r) => TenantTx::begin(&db.app, t, r).await.unwrap(),
        None => TenantTx::begin_tenant(&db.app, t).await.unwrap(),
    };
    let rows = tx
        .raw_rows(&format!("SELECT tenant_id FROM access.{table}"))
        .await
        .unwrap();
    rows.iter()
        .map(|r| *r.get::<sqlx::types::Uuid, _>(0).as_bytes())
        .collect()
}

const TENANT_TABLES: [&str; 3] = ["tenants", "realms", "realm_hostnames"];

// §12.1.3 test 2: identical data in two tenants; neither sees the other's rows
#[tokio::test]
async fn twin_tenants_see_only_themselves() {
    let db = fresh().await.unwrap();
    let (a, ra) = tenant(&db, 1, "acme-a", "a.acme.test").await;
    let (b, rb) = tenant(&db, 2, "acme-b", "b.acme.test").await;
    for table in TENANT_TABLES {
        for (t, r) in [(a, ra), (b, rb)] {
            let rows = visible(&db, t, Some(r), table).await;
            assert!(!rows.is_empty(), "{table}");
            assert!(rows.iter().all(|x| x == t.as_bytes()), "{table}");
        }
    }
}

// §12.1.3 test 6, U59: without a scope, no rows
#[tokio::test]
async fn no_scope_no_rows() {
    let db = fresh().await.unwrap();
    tenant(&db, 3, "acme-c", "c.acme.test").await;
    for table in TENANT_TABLES {
        let n: i64 = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM access.{table}"
        )))
        .fetch_one(&db.app)
        .await
        .unwrap()
        .get(0);
        assert_eq!(n, 0, "{table}");
    }
}

// OP-12: realm-level rows need the realm in scope too
#[tokio::test]
async fn hostnames_need_the_realm_in_scope() {
    let db = fresh().await.unwrap();
    let (t, _) = tenant(&db, 4, "acme-d", "d.acme.test").await;
    assert_eq!(visible(&db, t, None, "realm_hostnames").await.len(), 0);
    assert_eq!(visible(&db, t, None, "realms").await.len(), 1);
}

// §12.1.3 test 5, TNI-10: a taken slug or hostname fails without telling whose it is
#[tokio::test]
async fn global_identifiers_leak_nothing_and_are_never_reused() {
    let db = fresh().await.unwrap();
    let (a, ra) = tenant(&db, 5, "acme-e", "e.acme.test").await;
    let b = create_tenant(&db.app, "pool-default").await.unwrap();
    let db_b = domain(&db, b, 6).await;
    let mut tx = TenantTx::begin_tenant(&db.app, b).await.unwrap();
    let Err(err) = create_realm(&mut tx, &db_b, "acme-e", "pool-default").await else {
        panic!("a taken slug was accepted");
    };
    let err = err.to_string();
    tx.rollback().await.unwrap();
    assert!(!err.contains(&format!("{:x?}", a.as_bytes())), "{err}");
    assert!(
        !err.contains("acme-e") || err.contains("realms_slug"),
        "{err}"
    );
    // INV-32: a deleted realm keeps its slug
    let mut tx = TenantTx::begin_tenant(&db.app, a).await.unwrap();
    assert!(delete_realm(&mut tx, ra).await.unwrap());
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin_tenant(&db.app, b).await.unwrap();
    assert!(
        create_realm(&mut tx, &db_b, "acme-e", "pool-default")
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    // a hostname is a lease: once removed, another realm may take it
    let mut tx = TenantTx::begin_tenant(&db.app, b).await.unwrap();
    let rb = create_realm(&mut tx, &db_b, "acme-f", "pool-default")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, b, rb).await.unwrap();
    assert!(
        add_hostname(&mut tx, "e.acme.test", HostKind::Custom)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, a, ra).await.unwrap();
    assert!(remove_hostname(&mut tx, "e.acme.test").await.unwrap());
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, b, rb).await.unwrap();
    add_hostname(&mut tx, "e.acme.test", HostKind::Custom)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

// MD-5a: a realm is governed by a domain of its own tenant
#[tokio::test]
async fn a_realm_cannot_be_governed_by_another_tenants_domain() {
    let db = fresh().await.unwrap();
    let a = create_tenant(&db.app, "pool-default").await.unwrap();
    let b = create_tenant(&db.app, "pool-default").await.unwrap();
    let foreign = domain(&db, a, 7).await;
    let mut tx = TenantTx::begin_tenant(&db.app, b).await.unwrap();
    assert!(
        create_realm(&mut tx, &foreign, "acme-g", "pool-default")
            .await
            .is_err()
    );
}

// OP-132 m.3: the router resolves live hostnames and reads nothing else
#[tokio::test]
async fn the_router_sees_the_mapping_only() {
    let db = fresh().await.unwrap();
    let (t, r) = tenant(&db, 8, "acme-h", "h.acme.test").await;
    let got = resolve_host(&db.router, "H.ACME.TEST")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (got.0.as_bytes(), got.1.as_bytes()),
        (t.as_bytes(), r.as_bytes())
    );
    assert!(
        resolve_host(&db.router, "nope.acme.test")
            .await
            .unwrap()
            .is_none()
    );
    for stmt in [
        "SELECT governing_domain_id FROM access.realms",
        "SELECT kind FROM access.realm_hostnames",
        "SELECT * FROM access.tenants",
        "UPDATE access.realms SET status = 'active'",
    ] {
        let err = sqlx::query(stmt).execute(&db.router).await.unwrap_err();
        assert!(
            err.to_string().contains("permission denied"),
            "{stmt}: {err}"
        );
    }
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    delete_realm(&mut tx, r).await.unwrap();
    tx.commit().await.unwrap();
    assert!(
        resolve_host(&db.router, "h.acme.test")
            .await
            .unwrap()
            .is_none()
    );
}
