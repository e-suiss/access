//! TN-128, TN-129, INV-13, OP-73: console BFF sessions against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::console::{
    EndReason, NewConsoleSession, Pending, attach, by_cookie, by_id, end, live_of, open,
    set_pending, take_pending, touch,
};
use access_store::identity::{RealmId, TenantId};
use access_store::testing::fresh;

const T: TenantId = TenantId::from_bytes([1; 16]);
const R: RealmId = RealmId::from_bytes([2; 16]);

fn new(cookie: &[u8; 32], subject: u8) -> NewConsoleSession<'_> {
    NewConsoleSession {
        cookie_digest: cookie,
        tenant: T,
        realm: R,
        subject: [subject; 16],
        login_session: [9; 16],
        session_epoch: 0,
        slug: "acme",
        domain: &[3; 32],
        account: "usr_x",
        binding: &[1, 2, 3],
        auth_time_ms: 900,
        now_ms: 1_000,
    }
}

fn pending(c: u8, until: u64) -> Pending {
    Pending {
        challenge: [c; 32],
        key: vec![c; 77],
        party: [c; 16],
        from_ms: 1_000,
        until_ms: until,
    }
}

// TN-128, TN-129, OP-73: a session is found by its cookie digest only, touched while live,
// ended once and softly; an ended session stays ended
#[tokio::test]
async fn sessions_open_find_and_end_softly() {
    let db = fresh().await.unwrap();
    let id = open(&db.app, &new(&[7; 32], 4)).await.unwrap();
    let s = by_cookie(&db.app, &[7; 32]).await.unwrap().unwrap();
    assert_eq!(s.id, id);
    assert_eq!(
        (s.subject, s.slug.as_str(), s.domain),
        ([4; 16], "acme", [3; 32])
    );
    assert_eq!(s.ended_ms, None);
    assert!(by_cookie(&db.app, &[8; 32]).await.unwrap().is_none());
    assert!(open(&db.app, &new(&[7; 32], 5)).await.is_err());
    assert!(touch(&db.app, &id, 2_000).await.unwrap());
    assert_eq!(
        by_id(&db.app, &id).await.unwrap().unwrap().last_seen_ms,
        2_000
    );
    let other = open(&db.app, &new(&[6; 32], 4)).await.unwrap();
    assert_eq!(live_of(&db.app, T, R, &[4; 16], 10).await.unwrap().len(), 2);
    assert!(
        end(&db.app, &id, 3_000, EndReason::SignedOut)
            .await
            .unwrap()
    );
    assert!(!end(&db.app, &id, 4_000, EndReason::Policy).await.unwrap());
    assert!(!touch(&db.app, &id, 5_000).await.unwrap());
    assert_eq!(
        by_id(&db.app, &id).await.unwrap().unwrap().ended_ms,
        Some(3_000)
    );
    let live = live_of(&db.app, T, R, &[4; 16], 10).await.unwrap();
    assert_eq!(live.iter().map(|s| s.id).collect::<Vec<_>>(), [other]);
    let deleted = sqlx::query("DELETE FROM access_ops.console_sessions")
        .execute(&db.app)
        .await;
    assert!(deleted.is_err(), "OP-73: no physical delete");
}

// INV-13, OP-149 m.6: one pending challenge, taken once and only before it lapses; the device
// Instance is attached once
#[tokio::test]
async fn a_challenge_is_taken_once_and_the_instance_attached_once() {
    let db = fresh().await.unwrap();
    let id = open(&db.app, &new(&[5; 32], 1)).await.unwrap();
    assert!(
        set_pending(&db.app, &id, &pending(1, 10_000))
            .await
            .unwrap()
    );
    assert!(
        set_pending(&db.app, &id, &pending(2, 10_000))
            .await
            .unwrap()
    );
    assert!(
        take_pending(&db.app, &id, &[1; 32], 2_000)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        take_pending(&db.app, &id, &[2; 32], 2_000).await.unwrap(),
        Some(pending(2, 10_000))
    );
    assert!(
        take_pending(&db.app, &id, &[2; 32], 2_000)
            .await
            .unwrap()
            .is_none()
    );
    assert!(set_pending(&db.app, &id, &pending(3, 1_500)).await.unwrap());
    assert!(
        take_pending(&db.app, &id, &[3; 32], 2_000)
            .await
            .unwrap()
            .is_none()
    );
    assert!(attach(&db.app, &id, &[8; 32], &[1, 2]).await.unwrap());
    assert!(!attach(&db.app, &id, &[9; 32], &[3, 4]).await.unwrap());
    assert!(
        !set_pending(&db.app, &id, &pending(4, 10_000))
            .await
            .unwrap()
    );
    let s = by_id(&db.app, &id).await.unwrap().unwrap();
    assert_eq!(s.instance, Some(([8; 32], vec![1, 2])));
    let rewritten = sqlx::query(
        "UPDATE access_ops.console_sessions SET instance_kid = $2 WHERE session_id = $1",
    )
    .bind(sqlx::types::Uuid::from_bytes(id))
    .bind([9u8; 32].as_slice())
    .execute(&db.app)
    .await;
    assert!(rewritten.is_err(), "INV-13: the Instance is fixed");
}
