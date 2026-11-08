//! TN-126: management API Idempotency-Key answers against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::StoreError;
use access_store::api_idempotency::{Begun, begin, finish, release_expired};
use access_store::testing::fresh;

const LEASE: u64 = 30_000;
const DAY: u64 = 86_400_000;

// TN-126
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

// TN-126
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

// TN-126, OP-151 m.3 (c), OP-73
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

// D-4, TN-126, OP-151 m.3 (c), OP-73
#[tokio::test]
async fn expired_answers_are_released_in_place() {
    let db = fresh().await.unwrap();
    let req = [9; 32];
    for (scope, retention) in [([1; 32], 100), ([2; 32], 200), ([3; 32], DAY)] {
        assert_eq!(
            begin(&db.app, &scope, &req, 1_000, LEASE, retention)
                .await
                .unwrap(),
            Begun::Run
        );
        finish(&db.app, &scope, &req, Some(b"answer"))
            .await
            .unwrap();
    }
    assert_eq!(
        begin(&db.app, &[4; 32], &req, 1_000, LEASE, 100)
            .await
            .unwrap(),
        Begun::Run
    );
    assert_eq!(release_expired(&db.app, 5_000, 1).await.unwrap(), 1);
    assert_eq!(release_expired(&db.app, 5_000, 10).await.unwrap(), 1);
    assert_eq!(release_expired(&db.app, 5_000, 10).await.unwrap(), 0);
    let rows: Vec<(Vec<u8>, String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT scope, state, answer FROM access_ops.api_idempotency ORDER BY scope",
    )
    .fetch_all(&db.app)
    .await
    .unwrap();
    let state = |s: &str, a: Option<&[u8]>| (s.to_owned(), a.map(<[u8]>::to_vec));
    let got: Vec<_> = rows.into_iter().map(|(_, s, a)| (s, a)).collect();
    assert_eq!(
        got,
        vec![
            state("released", None),
            state("released", None),
            state("done", Some(b"answer")),
            state("running", None),
        ]
    );
}
