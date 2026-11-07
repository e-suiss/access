//! TN-126: management API Idempotency-Key answers against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::StoreError;
use access_store::api_idempotency::{Begun, begin, finish};
use access_store::testing::fresh;

const LEASE: u64 = 30_000;
const DAY: u64 = 86_400_000;

// TN-126: first run, 409 while running, replay of the kept answer, 422 for another request
#[tokio::test]
async fn a_key_runs_once_and_replays_its_answer() {
    let db = fresh().await.unwrap();
    let (scope, a, b) = ([1; 32], [2; 32], [3; 32]);
    let run = |r, now| begin(&db.app, &scope, r, now, LEASE, DAY);
    assert_eq!(run(&a, 1_000).await.unwrap(), Begun::Run);
    assert_eq!(run(&a, 1_001).await.unwrap(), Begun::Running);
    assert_eq!(run(&b, 1_002).await.unwrap(), Begun::Reused);
    finish(&db.app, &scope, &a, Some(b"answer")).await.unwrap();
    assert_eq!(
        run(&a, 2_000).await.unwrap(),
        Begun::Replay(b"answer".to_vec())
    );
    assert_eq!(run(&b, 2_000).await.unwrap(), Begun::Reused);
    assert!(matches!(
        finish(&db.app, &scope, &a, Some(b"again")).await,
        Err(StoreError::Stale)
    ));
}

// TN-126: a released key (validation failure, 5xx) runs again, also with another request
#[tokio::test]
async fn a_released_key_runs_again() {
    let db = fresh().await.unwrap();
    let (scope, a, b) = ([4; 32], [5; 32], [6; 32]);
    assert_eq!(
        begin(&db.app, &scope, &a, 0, LEASE, DAY).await.unwrap(),
        Begun::Run
    );
    finish(&db.app, &scope, &a, None).await.unwrap();
    assert_eq!(
        begin(&db.app, &scope, &b, 1, LEASE, DAY).await.unwrap(),
        Begun::Run
    );
}

// TN-126, OP-151 m.3 (c), OP-73: kept 24 h, then the scope is reused in place, never deleted;
// a lapsed runner's lease is taken over only by the same request
#[tokio::test]
async fn keys_expire_softly_and_leases_lapse() {
    let db = fresh().await.unwrap();
    let (scope, a, b) = ([7; 32], [8; 32], [9; 32]);
    let run = |r, now| begin(&db.app, &scope, r, now, LEASE, DAY);
    assert_eq!(run(&a, 0).await.unwrap(), Begun::Run);
    assert_eq!(run(&b, LEASE).await.unwrap(), Begun::Reused);
    assert_eq!(run(&a, LEASE).await.unwrap(), Begun::Run);
    finish(&db.app, &scope, &a, Some(b"x")).await.unwrap();
    assert_eq!(run(&b, DAY).await.unwrap(), Begun::Reused);
    assert_eq!(run(&b, LEASE + DAY).await.unwrap(), Begun::Run);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM access_ops.api_idempotency")
        .fetch_one(&db.app)
        .await
        .unwrap();
    assert_eq!(rows, 1);
    let deleted = sqlx::query("DELETE FROM access_ops.api_idempotency")
        .execute(&db.app)
        .await;
    assert!(deleted.is_err());
}
