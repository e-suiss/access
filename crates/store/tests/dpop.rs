//! DPoP replay cache (TN-30, MD-8, OP-146 m.5 (f)) on a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::dpop::open_dpop_replay_day;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::testing::{TestDb, fresh};
use sqlx::Executor;

const T: TenantId = TenantId::from_bytes([1; 16]);
const R: RealmId = RealmId::from_bytes([2; 16]);
const DAY: u32 = 20_833;

async fn first_use(db: &TestDb, tenant: TenantId, realm: RealmId, day: u32, key: [u8; 32]) -> bool {
    let mut t = TenantTx::begin(&db.app, tenant, realm).await.unwrap();
    let fresh = t.dpop_first_use(day, &key).await.unwrap();
    t.commit().await.unwrap();
    fresh
}

// TN-30, IDP-11 step 9
#[tokio::test]
async fn a_replayed_key_is_reported_once_seen() {
    let db = fresh().await.unwrap();
    open_dpop_replay_day(&db.archive, DAY).await.unwrap();
    assert!(first_use(&db, T, R, DAY, [7; 32]).await);
    assert!(!first_use(&db, T, R, DAY, [7; 32]).await);
    assert!(first_use(&db, T, R, DAY, [8; 32]).await);
    assert!(first_use(&db, T, RealmId::from_bytes([3; 16]), DAY, [7; 32]).await);
    assert!(first_use(&db, TenantId::from_bytes([4; 16]), R, DAY, [7; 32]).await);
}

// TN-30, IDP-11 step 9
#[tokio::test]
async fn concurrent_replays_have_one_winner() {
    let db = fresh().await.unwrap();
    open_dpop_replay_day(&db.archive, DAY).await.unwrap();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let pool = db.app.clone();
        tasks.push(tokio::spawn(async move {
            let mut t = TenantTx::begin(&pool, T, R).await.unwrap();
            let fresh = t.dpop_first_use(DAY, &[9; 32]).await;
            t.commit().await.map(|()| fresh)
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if let Ok(Ok(true)) = task.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
}

// TN-30, MD-8
#[tokio::test]
async fn an_unopened_day_fails_closed() {
    let db = fresh().await.unwrap();
    let mut t = TenantTx::begin(&db.app, T, R).await.unwrap();
    assert!(t.dpop_first_use(DAY + 10, &[1; 32]).await.is_err());
    let mut t = TenantTx::begin_tenant(&db.app, T).await.unwrap();
    assert!(t.dpop_first_use(DAY, &[1; 32]).await.is_err());
}

// OP-73, OP-146 m.5 (f)
#[tokio::test]
async fn rows_are_append_only_and_opening_is_idempotent() {
    let db = fresh().await.unwrap();
    let name = open_dpop_replay_day(&db.archive, DAY).await.unwrap();
    assert_eq!(name, format!("dpop_replay_d{DAY}"));
    assert_eq!(open_dpop_replay_day(&db.archive, DAY).await.unwrap(), name);
    assert!(open_dpop_replay_day(&db.app, DAY + 1).await.is_err());
    assert!(first_use(&db, T, R, DAY, [5; 32]).await);
    let mut c = db.owner.acquire().await.unwrap();
    for sql in [
        "UPDATE access.dpop_replay SET day = day",
        "DELETE FROM access.dpop_replay",
    ] {
        assert!(c.execute(sql).await.is_err(), "{sql}");
    }
}
