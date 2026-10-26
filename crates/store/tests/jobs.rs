//! OP-129 m.2: the job table against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::Duration;

use access_store::jobs::{claim, complete, schedule};
use access_store::testing::fresh;

const LEASE: Duration = Duration::from_secs(30);

#[tokio::test]
async fn only_due_jobs_are_claimed_and_each_once() {
    let db = fresh().await.unwrap();
    assert!(
        schedule(
            &db.app,
            "invite.expiry_notice",
            "inv_1",
            "inv_1:expiry",
            Duration::ZERO
        )
        .await
        .unwrap()
    );
    assert!(
        !schedule(
            &db.app,
            "invite.expiry_notice",
            "inv_1",
            "inv_1:expiry",
            Duration::ZERO
        )
        .await
        .unwrap()
    );
    schedule(
        &db.app,
        "invite.expiry_notice",
        "inv_2",
        "inv_2:expiry",
        Duration::from_secs(3600),
    )
    .await
    .unwrap();
    let a = claim(&db.app, "w1", 10, LEASE).await.unwrap();
    assert_eq!(
        a.iter().map(|j| j.subject.as_str()).collect::<Vec<_>>(),
        ["inv_1"]
    );
    assert_eq!(claim(&db.app, "w2", 10, LEASE).await.unwrap(), []);
    assert!(
        !complete(&db.app, a[0].id, "w2").await.unwrap(),
        "only the claimant completes"
    );
    assert!(complete(&db.app, a[0].id, "w1").await.unwrap());
    assert!(!complete(&db.app, a[0].id, "w1").await.unwrap());
}

#[tokio::test]
async fn concurrent_workers_take_disjoint_jobs() {
    let db = fresh().await.unwrap();
    for i in 0..40 {
        schedule(
            &db.app,
            "key.rotation_notice",
            &format!("k{i}"),
            &format!("k{i}"),
            Duration::ZERO,
        )
        .await
        .unwrap();
    }
    let (a, b) = tokio::join!(
        claim(&db.app, "w1", 25, LEASE),
        claim(&db.app, "w2", 25, LEASE)
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.len() + b.len(), 40);
    assert!(a.iter().all(|x| b.iter().all(|y| x.id != y.id)));
}

#[tokio::test]
async fn a_lapsed_claim_is_taken_again() {
    let db = fresh().await.unwrap();
    schedule(
        &db.app,
        "domain.reverify_notice",
        "dom_1",
        "dom_1",
        Duration::ZERO,
    )
    .await
    .unwrap();
    let first = claim(&db.app, "w1", 1, Duration::ZERO).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let again = claim(&db.app, "w2", 1, LEASE).await.unwrap();
    assert_eq!(again[0].id, first[0].id);
    assert_eq!(again[0].attempts, 2);
    assert!(!complete(&db.app, first[0].id, "w1").await.unwrap());
    assert!(complete(&db.app, again[0].id, "w2").await.unwrap());
}

#[tokio::test]
async fn subjects_carry_identifiers_only() {
    let db = fresh().await.unwrap();
    assert!(
        schedule(
            &db.app,
            "user.notice",
            "someone@example.com",
            "x",
            Duration::ZERO
        )
        .await
        .is_err()
    );
    assert!(
        schedule(&db.app, "user.notice", "usr_01J", "y", Duration::ZERO)
            .await
            .is_ok()
    );
}
