//! TN-125, OP-73: bulk job results are kept in the realm's scope, each item recorded once, a job
//! finished once, and an expired job read as absent without being deleted.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::admin_jobs::{self, ItemRow, NewJob};
use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};

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

fn item(index: u32, status: &str) -> ItemRow {
    ItemRow {
        index,
        operation: "suspendAccount".to_owned(),
        key: Some(format!("a{index}")),
        status: status.to_owned(),
        http_status: Some(if status == "committed" { 200 } else { 424 }),
        problem: (status != "committed").then(|| "failed-dependency".to_owned()),
        exercise_id: (status == "committed").then(|| "ZXhlcmNpc2U".to_owned()),
        position: (status == "committed").then_some(7),
    }
}

// TN-125, TN-113, OP-73: one record per item, one end per job, counts on the envelope, hidden
// after its 7 days and in every other realm, never deleted
#[tokio::test]
async fn job_results_are_recorded_once_and_expire_softly() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let r = realm(&db, t, 31, "jobs-a").await;
    let other = realm(&db, t, 32, "jobs-b").await;
    let items = vec![
        ("suspendAccount".to_owned(), Some("a0".to_owned())),
        ("suspendAccount".to_owned(), Some("a1".to_owned())),
    ];
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let id = admin_jobs::create(
        &mut tx,
        &NewJob {
            mode: "sequential",
            actor: [5; 32],
            items: &items,
            created_ms: 1_000,
            expires_ms: 2_000,
        },
    )
    .await
    .unwrap();
    assert!(
        admin_jobs::record(&mut tx, id, &item(0, "committed"))
            .await
            .unwrap()
    );
    assert!(
        !admin_jobs::record(&mut tx, id, &item(0, "rejected"))
            .await
            .unwrap(),
        "an item is recorded once"
    );
    assert!(
        admin_jobs::record(&mut tx, id, &item(1, "failed_dependency"))
            .await
            .unwrap()
    );
    assert!(
        admin_jobs::finish(&mut tx, id, "partial", 1_500)
            .await
            .unwrap()
    );
    assert!(
        !admin_jobs::finish(&mut tx, id, "failed", 1_600)
            .await
            .unwrap()
    );
    let job = admin_jobs::job(&mut tx, id, 1_900).await.unwrap().unwrap();
    assert_eq!(
        (job.status.as_str(), job.items, job.committed, job.failed),
        ("partial", 2, 1, 1)
    );
    let page = admin_jobs::items(&mut tx, id, None, 10).await.unwrap();
    assert_eq!(page[0].exercise_id.as_deref(), Some("ZXhlcmNpc2U"));
    assert_eq!(page[1].status, "failed_dependency");
    assert_eq!(
        admin_jobs::items(&mut tx, id, Some(0), 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(admin_jobs::job(&mut tx, id, 2_000).await.unwrap().is_none());
    tx.commit().await.unwrap();
    let mut elsewhere = TenantTx::begin(&db.app, t, other).await.unwrap();
    assert!(
        admin_jobs::job(&mut elsewhere, id, 1_900)
            .await
            .unwrap()
            .is_none()
    );
    elsewhere.commit().await.unwrap();
    let deleted = sqlx::query("DELETE FROM access.admin_jobs")
        .execute(&db.app)
        .await;
    assert!(deleted.is_err(), "nothing is deleted");
}
