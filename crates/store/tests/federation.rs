//! Linked sign-ins, social attempts and combinations on a real PostgreSQL (P-ID-9, TN-66,
//! TN-67, OP-73, OP-153 m.3 (l), (m)).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::many_single_char_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::authority::{LogRecord, create_domain};
use access_store::federation::NewAttempt;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};

async fn realm(db: &TestDb) -> (TenantId, RealmId) {
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = DomainId::from_bytes([4; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [4; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *t.as_bytes(), &g, &[])
        .await
        .unwrap();
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, &d, "acme", "pool-default")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (t, r)
}

// P-ID-9, TN-66, OP-73
#[tokio::test]
async fn an_external_identity_links_to_one_account_and_a_link_ends_once() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db).await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(!tx.realm_is_sandbox().await.unwrap());
    let a = tx.insert_subject("active", "k:1", &[1; 40]).await.unwrap();
    let b = tx.insert_subject("active", "k:1", &[1; 40]).await.unwrap();
    assert!(
        tx.link_federated(a, "google", &[7; 32], None, 10)
            .await
            .unwrap()
    );
    assert!(
        tx.link_federated(a, "github", &[8; 32], None, 10)
            .await
            .unwrap()
    );
    assert!(
        !tx.link_federated(b, "google", &[7; 32], None, 11)
            .await
            .unwrap(),
        "one live link per external identity"
    );
    let row = tx.federated_by_key(&[7; 32]).await.unwrap().unwrap();
    assert_eq!((row.subject, row.verified_ms), (a, 10));
    tx.federated_verified(row.link, 20).await.unwrap();
    tx.federated_verified(row.link, 15).await.unwrap();
    assert_eq!(
        tx.federated_by_key(&[7; 32])
            .await
            .unwrap()
            .unwrap()
            .verified_ms,
        20
    );
    assert!(!tx.end_federated(b, row.link, "unlinked", 30).await.unwrap());
    assert!(tx.end_federated(a, row.link, "unlinked", 30).await.unwrap());
    assert!(!tx.end_federated(a, row.link, "unlinked", 31).await.unwrap());
    assert!(tx.federated_by_key(&[7; 32]).await.unwrap().is_none());
    assert!(
        tx.link_federated(b, "google", &[7; 32], None, 40)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let reopened = sqlx::query(
        "UPDATE access.identity_federated SET ended_ms = NULL, end_reason = NULL
          WHERE ended_ms IS NOT NULL",
    )
    .execute(&db.owner)
    .await;
    assert!(reopened.is_err(), "an ended link is never reopened");
    let deleted = sqlx::query("DELETE FROM access.identity_federated")
        .execute(&db.owner)
        .await;
    assert!(deleted.is_err());
}

// TN-68, OP-153 m.15 (g)
#[tokio::test]
async fn the_last_live_link_stays_unless_a_combination_moves_it() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db).await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let a = tx.insert_subject("active", "k:1", &[1; 40]).await.unwrap();
    let b = tx.insert_subject("active", "k:1", &[1; 40]).await.unwrap();
    assert!(
        tx.link_federated(a, "google", &[5; 32], None, 10)
            .await
            .unwrap()
    );
    assert!(
        tx.link_federated(b, "google", &[6; 32], None, 10)
            .await
            .unwrap()
    );
    let la = tx.federated_by_key(&[5; 32]).await.unwrap().unwrap().link;
    let lb = tx.federated_by_key(&[6; 32]).await.unwrap().unwrap().link;
    assert!(!tx.keeps_a_method(a, la).await.unwrap());
    assert!(tx.end_federated(b, lb, "combined", 20).await.unwrap());
    tx.commit().await.unwrap();

    let unlinked = sqlx::query(
        "UPDATE access.identity_federated SET ended_ms = 30, end_reason = 'unlinked'
          WHERE ended_ms IS NULL",
    )
    .execute(&db.owner)
    .await;
    let err = unlinked.unwrap_err();
    let constraint = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
        .map(String::from);
    assert_eq!(constraint.as_deref(), Some("keep_last_method"));
}

// OP-153 m.3 (l), (m)
#[tokio::test]
async fn an_attempt_and_a_ticket_are_used_once_by_their_own_browser() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db).await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let a = tx.insert_subject("active", "k:1", &[1; 40]).await.unwrap();
    let n = "n".repeat(43);
    let v = "v".repeat(43);
    tx.insert_social_attempt(&NewAttempt {
        state_hash: &[1; 32],
        device_hash: &[2; 32],
        provider: "google",
        link_to: None,
        nonce: &n,
        verifier: &v,
        now_ms: 1_000,
        expires_ms: 601_000,
    })
    .await
    .unwrap();
    assert!(
        tx.take_social_attempt(&[1; 32], &[3; 32], "google", 2_000)
            .await
            .unwrap()
            .is_none(),
        "another browser cannot use it"
    );
    assert!(
        tx.take_social_attempt(&[1; 32], &[2; 32], "apple", 2_000)
            .await
            .unwrap()
            .is_none()
    );
    let got = tx
        .take_social_attempt(&[1; 32], &[2; 32], "google", 2_000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((got.nonce.as_str(), got.link_to), (n.as_str(), None));
    assert!(
        tx.take_social_attempt(&[1; 32], &[2; 32], "google", 2_000)
            .await
            .unwrap()
            .is_none()
    );

    tx.insert_combine_ticket(&[5; 32], a, 900, 1_000, 301_000)
        .await
        .unwrap();
    assert!(
        tx.take_combine_ticket(&[5; 32], 301_000)
            .await
            .unwrap()
            .is_none(),
        "expired"
    );
    assert_eq!(
        tx.take_combine_ticket(&[5; 32], 2_000).await.unwrap(),
        Some((a, 900))
    );
    assert!(
        tx.take_combine_ticket(&[5; 32], 2_001)
            .await
            .unwrap()
            .is_none()
    );
    let b = tx.insert_subject("active", "k:1", &[1; 40]).await.unwrap();
    assert!(
        tx.insert_combination(a, b, "{\"survivor\":{}}", &[9; 32], 3_000)
            .await
            .unwrap()
    );
    assert!(
        !tx.insert_combination(a, b, "{}", &[9; 32], 3_001)
            .await
            .unwrap(),
        "an account is absorbed once"
    );
    tx.commit().await.unwrap();
}

// §12.1.3, OP-73, OP-153 m.3 (m)
#[tokio::test]
async fn a_binding_half_is_committed_once_and_never_deleted() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db).await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let a = tx.insert_subject("active", "k:1", &[1; 40]).await.unwrap();
    let half = access_store::federation::NewHalf {
        binding: [3; 16],
        subject: a,
        role: "offer",
        proof: "invite_token",
        secret_hash: &[4; 32],
        peer_evidence: None,
        now_ms: 1_000,
        expires_ms: 601_000,
    };
    assert!(tx.insert_binding_half(&half).await.unwrap());
    assert!(
        !tx.insert_binding_half(&half).await.unwrap(),
        "one half per realm"
    );
    assert!(
        !tx.commit_binding_half([3; 16], a, &[5; 32], 700_000)
            .await
            .unwrap(),
        "lapsed"
    );
    assert!(
        tx.commit_binding_half([3; 16], a, &[5; 32], 2_000)
            .await
            .unwrap()
    );
    assert!(
        !tx.commit_binding_half([3; 16], a, &[6; 32], 3_000)
            .await
            .unwrap()
    );
    let rows = tx.binding_halves_of(a).await.unwrap();
    assert_eq!(
        (rows[0].state.as_str(), rows[0].committed_ms),
        ("committed", Some(2_000))
    );
    tx.commit().await.unwrap();
    let changed = sqlx::query(
        "UPDATE access.identity_binding_halves SET peer_evidence = decode(repeat('07', 32), 'hex')",
    )
    .execute(&db.owner)
    .await;
    assert!(changed.is_err(), "a committed half keeps its evidence");
    let deleted = sqlx::query("DELETE FROM access.identity_binding_halves")
        .execute(&db.owner)
        .await;
    assert!(deleted.is_err());
}
