//! OP-132 m.5, OP-18: realm-level rows are visible only in their realm's scope, on a real
//! PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use sqlx::Row as _;

async fn realm(db: &TestDb, t: TenantId, seed: u8, slug: &str) -> RealmId {
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
    r
}

async fn count(tx: TenantTx) -> i64 {
    let rows = tx
        .raw_rows("SELECT count(*) AS n FROM access.identity_outbox WHERE kind = 'test.d3'")
        .await
        .unwrap();
    rows[0].get::<i64, _>("n")
}

// D-3, OP-132 m.5
#[tokio::test]
async fn a_cross_realm_read_in_the_same_tenant_returns_nothing() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let a = realm(&db, t, 0xa1, "scope-a").await;
    let b = realm(&db, t, 0xb1, "scope-b").await;
    let mut tx = TenantTx::begin(&db.app, t, a).await.unwrap();
    tx.outbox("test.d3", b"{}").await.unwrap();
    tx.commit().await.unwrap();

    assert_eq!(
        count(TenantTx::begin(&db.app, t, a).await.unwrap()).await,
        1
    );
    assert_eq!(
        count(TenantTx::begin(&db.app, t, b).await.unwrap()).await,
        0
    );
    assert_eq!(
        count(TenantTx::begin_tenant(&db.app, t).await.unwrap()).await,
        0
    );
    assert_eq!(
        count(TenantTx::begin_tenant_wide(&db.app, t).await.unwrap()).await,
        0
    );
    let forged = format!(
        "INSERT INTO access.identity_outbox (tenant_id, realm_id, kind, payload) \
         VALUES ('{}', '{}', 'test.d3', '\\x7b7d')",
        uuid(t.as_bytes()),
        uuid(a.as_bytes()),
    );
    let tx = TenantTx::begin(&db.app, t, b).await.unwrap();
    assert!(tx.raw_rows(&forged).await.is_err());
    assert_eq!(
        count(TenantTx::begin(&db.app, t, a).await.unwrap()).await,
        1
    );
}

fn uuid(b: &[u8; 16]) -> String {
    let h: String = b.iter().fold(String::new(), |mut s, x| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
        s
    });
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

// D-3, OP-132 m.5
#[tokio::test]
async fn every_realm_keyed_table_has_a_realm_policy() {
    let db = fresh().await.unwrap();
    let unscoped: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'access' AND c.relkind IN ('r', 'p') AND NOT c.relispartition
            AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid
                         AND a.attname = 'realm_id' AND NOT a.attisdropped)
            AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid
                             AND NOT p.polpermissive
                             AND pg_get_expr(p.polqual, p.polrelid) LIKE '%realm_scope%')
          ORDER BY 1",
    )
    .fetch_all(&db.owner)
    .await
    .unwrap();
    assert_eq!(
        unscoped,
        [
            "federation_issuer_state",
            "realm_domain_binding",
            "realms",
            "sandbox_domains"
        ]
    );
}
