//! Identity subjects, identifiers, credentials and login counters on a real PostgreSQL
//! (§10.1.7, MD-5, TN-2, TN-49, TN-68, OP-35, OP-73, OP-146 m.5 (f)).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::accounts::{NewCredential, Revoke, SealedSecret};
use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use access_store::throttle::{ThrottleRow, open_day};

async fn realm(db: &TestDb, seed: u8, slug: &str) -> (TenantId, RealmId) {
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
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
    (t, r)
}

async fn second_realm(db: &TestDb, t: TenantId, seed: u8, slug: &str) -> RealmId {
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

fn sealed() -> SealedSecret {
    SealedSecret {
        kek_id: "sub-dek:test".into(),
        wrapped_dek: vec![1; 40],
        nonce: [2; 12],
        ciphertext: vec![3; 48],
        pepper_version: None,
    }
}

async fn subject(tx: &mut TenantTx) -> [u8; 16] {
    tx.insert_subject("staged", "realm-kek:1", &[9; 40])
        .await
        .unwrap()
}

async fn credential(tx: &mut TenantTx, s: [u8; 16], kind: &str) -> [u8; 16] {
    tx.insert_credential(&NewCredential {
        subject: s,
        kind,
        algorithm: "argon2id",
        sealed: &sealed(),
    })
    .await
    .unwrap()
}

// MD-5, OP-12, TN-2, §17.2.2
#[tokio::test]
async fn identifiers_are_case_insensitive_and_realm_scoped() {
    let db = fresh().await.unwrap();
    let (t, r1) = realm(&db, 1, "acct-a").await;
    let r2 = second_realm(&db, t, 2, "acct-b").await;

    let mut tx = TenantTx::begin(&db.app, t, r1).await.unwrap();
    let a = subject(&mut tx).await;
    let b = subject(&mut tx).await;
    assert!(
        tx.add_identifier(a, "email", "Alice@Example.com")
            .await
            .unwrap()
    );
    assert!(
        !tx.add_identifier(b, "email", "alice@example.COM")
            .await
            .unwrap()
    );
    assert_eq!(
        tx.subject_by_identifier("ALICE@example.com").await.unwrap(),
        Some(a)
    );
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r2).await.unwrap();
    assert_eq!(
        tx.subject_by_identifier("alice@example.com").await.unwrap(),
        None
    );
    let c = subject(&mut tx).await;
    assert!(
        tx.add_identifier(c, "email", "alice@example.com")
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r1).await.unwrap();
    assert!(tx.release_identifier(a, "ALICE@example.com").await.unwrap());
    assert!(
        tx.add_identifier(b, "email", "alice@example.com")
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
}

// TN-49
#[tokio::test]
async fn the_status_chain_is_enforced_and_rows_stay() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db, 3, "acct-c").await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let s = subject(&mut tx).await;
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(tx.set_subject_status(s, "staged", "active").await.is_err());
    tx.rollback().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(
        tx.set_subject_status(s, "staged", "pending_user_action")
            .await
            .unwrap()
    );
    assert!(
        !tx.set_subject_status(s, "staged", "pending_user_action")
            .await
            .unwrap()
    );
    assert!(
        tx.set_subject_status(s, "pending_user_action", "active")
            .await
            .unwrap()
    );
    assert_eq!(tx.bump_session_epoch(s).await.unwrap(), Some(1));
    tx.commit().await.unwrap();

    for sql in [
        "DELETE FROM access.identity_subjects",
        "DELETE FROM access.identity_credentials",
        "DELETE FROM access.identity_identifiers",
        "UPDATE access.identity_subjects SET session_epoch = 0",
    ] {
        let tx = TenantTx::begin(&db.app, t, r).await.unwrap();
        assert!(tx.raw_rows(sql).await.is_err(), "{sql}");
    }
}

// TN-68, §12.3.3
#[tokio::test]
async fn the_last_method_cannot_be_removed() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db, 4, "acct-d").await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let s = subject(&mut tx).await;
    let pw = credential(&mut tx, s, "password").await;
    let wa = credential(&mut tx, s, "webauthn").await;
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(tx.revoke_credential(s, pw).await.unwrap(), Revoke::Done);
    assert_eq!(tx.revoke_credential(s, pw).await.unwrap(), Revoke::Missing);
    assert_eq!(
        tx.revoke_credential(s, wa).await.unwrap(),
        Revoke::LastMethod
    );
    tx.commit().await.unwrap();

    let tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let err = tx
        .raw_rows("UPDATE access.identity_credentials SET status = 'revoked', revoked_at = now()")
        .await
        .err()
        .unwrap();
    assert!(err.to_string().contains("TN-68"), "{err}");

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(tx.credentials(s, "webauthn").await.unwrap().len(), 1);
    assert!(tx.credentials(s, "password").await.unwrap().is_empty());
    tx.commit().await.unwrap();
}

// OP-12, §12.1.3 test 2
#[tokio::test]
async fn accounts_are_invisible_outside_their_realm() {
    let db = fresh().await.unwrap();
    let (t, r1) = realm(&db, 5, "acct-e").await;
    let r2 = second_realm(&db, t, 6, "acct-f").await;
    let mut tx = TenantTx::begin(&db.app, t, r1).await.unwrap();
    let s = subject(&mut tx).await;
    credential(&mut tx, s, "password").await;
    tx.add_identifier(s, "username", "bob").await.unwrap();
    tx.commit().await.unwrap();

    for table in [
        "identity_subjects",
        "identity_identifiers",
        "identity_credentials",
    ] {
        let tx = TenantTx::begin(&db.app, t, r2).await.unwrap();
        let rows = tx
            .raw_rows(&format!("SELECT 1 FROM access.{table}"))
            .await
            .unwrap();
        assert!(rows.is_empty(), "{table}");
        let tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
        let rows = tx
            .raw_rows(&format!("SELECT 1 FROM access.{table}"))
            .await
            .unwrap();
        assert!(rows.is_empty(), "{table}");
    }
    let mut tx = TenantTx::begin(&db.app, t, r2).await.unwrap();
    assert!(tx.subject(s, false).await.unwrap().is_none());
    tx.commit().await.unwrap();
}

// OP-35, OP-146
#[tokio::test]
async fn throttle_state_carries_across_days() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db, 7, "acct-g").await;
    let key = [7_u8; 32];
    let day = 20_000;
    open_day(&db.archive, day).await.unwrap();
    open_day(&db.archive, day + 1).await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(
        tx.throttle(&key, day, 30).await.unwrap(),
        ThrottleRow::default()
    );
    let row = ThrottleRow {
        tat_ms: 5,
        failures: 3,
        last_failure_ms: 4,
        blocked_until_ms: 9,
        locked: false,
    };
    tx.put_throttle(&key, day, &row).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(tx.throttle(&key, day + 1, 30).await.unwrap(), row);
    assert_eq!(
        tx.throttle(&key, day + 40, 30).await.unwrap(),
        ThrottleRow::default()
    );
    assert!(
        tx.put_throttle(&[8; 32], day, &row).await.is_err(),
        "a write needs the read"
    );
    tx.rollback().await.unwrap();

    let tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(
        tx.raw_rows("DELETE FROM access.login_throttle")
            .await
            .is_err()
    );
}
