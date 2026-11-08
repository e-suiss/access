//! Identity subjects, identifiers, credentials and login counters on a real PostgreSQL
//! (§10.1.7, MD-5, TN-2, TN-49, TN-68, OP-35, OP-73, OP-146 m.5 (f)).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::accounts::{NewCredential, Revoke, SealedIdentifier, SealedSecret, StoredValue};
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

fn sealed_id(seed: u8) -> SealedIdentifier {
    SealedIdentifier {
        index: [seed; 32],
        class: "contact",
        nonce: [seed; 12],
        ciphertext: vec![seed; 40],
    }
}

// MD-5, OP-12, TN-2, TN-76, §17.2.2, IDI-2, OP-153 m.3 (aa)
#[tokio::test]
async fn identifiers_are_unique_by_blind_index_and_realm_scoped() {
    let db = fresh().await.unwrap();
    let (t, r1) = realm(&db, 1, "acct-a").await;
    let r2 = second_realm(&db, t, 2, "acct-b").await;

    let mut tx = TenantTx::begin(&db.app, t, r1).await.unwrap();
    let a = subject(&mut tx).await;
    let b = subject(&mut tx).await;
    assert!(tx.add_identifier(a, "email", &sealed_id(7)).await.unwrap());
    assert!(!tx.add_identifier(b, "email", &sealed_id(7)).await.unwrap());
    assert_eq!(
        tx.subject_by_identifier(&[7; 32], "unused").await.unwrap(),
        Some(a)
    );
    let rows = tx.identifiers(a).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(matches!(&rows[0].stored, StoredValue::Sealed { class, .. } if class == "contact"));
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r2).await.unwrap();
    assert_eq!(
        tx.subject_by_identifier(&[7; 32], "unused").await.unwrap(),
        None
    );
    let c = subject(&mut tx).await;
    assert!(tx.add_identifier(c, "email", &sealed_id(7)).await.unwrap());
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r1).await.unwrap();
    assert!(tx.release_identifier(a, &[7; 32], "unused").await.unwrap());
    assert!(tx.add_identifier(b, "email", &sealed_id(7)).await.unwrap());
    tx.commit().await.unwrap();
}

// OP-153 m.3 (aa)
#[tokio::test]
async fn no_new_identifier_is_plaintext_and_old_ones_are_sealed_in_place() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db, 11, "acct-legacy").await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let a = subject(&mut tx).await;
    tx.commit().await.unwrap();
    let mut conn = db.owner.acquire().await.unwrap();
    let refused = sqlx::query(
        "INSERT INTO access.identity_identifiers (tenant_id, realm_id, subject_id, kind, value)
         VALUES ($1, $2, $3, 'email', 'old@example.com')",
    )
    .bind(sqlx::types::Uuid::from_bytes(*t.as_bytes()))
    .bind(sqlx::types::Uuid::from_bytes(*r.as_bytes()))
    .bind(sqlx::types::Uuid::from_bytes(a))
    .execute(&mut *conn)
    .await
    .unwrap_err();
    assert!(refused.to_string().contains("sealed"), "{refused}");
    for sql in [
        "ALTER TABLE access.identity_identifiers DISABLE TRIGGER identifier_sealed",
        "INSERT INTO access.identity_identifiers (tenant_id, realm_id, subject_id, kind, value)
         VALUES ($1, $2, $3, 'email', 'Old@Example.com')",
        "ALTER TABLE access.identity_identifiers ENABLE TRIGGER identifier_sealed",
    ] {
        let q = sqlx::query(sql);
        let q = if sql.starts_with("INSERT") {
            q.bind(sqlx::types::Uuid::from_bytes(*t.as_bytes()))
                .bind(sqlx::types::Uuid::from_bytes(*r.as_bytes()))
                .bind(sqlx::types::Uuid::from_bytes(a))
        } else {
            q
        };
        q.execute(&mut *conn).await.unwrap();
    }
    drop(conn);

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(
        tx.subject_by_identifier(&[8; 32], "old@example.com")
            .await
            .unwrap(),
        Some(a)
    );
    let plain = tx.plaintext_identifiers(10).await.unwrap();
    assert_eq!(plain.len(), 1);
    assert_eq!(plain[0].3, "Old@Example.com");
    assert!(tx.seal_identifier(plain[0].0, &sealed_id(8)).await.unwrap());
    assert!(!tx.seal_identifier(plain[0].0, &sealed_id(9)).await.unwrap());
    assert_eq!(tx.plaintext_identifiers(10).await.unwrap().len(), 0);
    assert_eq!(
        tx.subject_by_identifier(&[8; 32], "old@example.com")
            .await
            .unwrap(),
        Some(a)
    );
    tx.commit().await.unwrap();
}

// U58, OP-42, OP-74 m.1
#[tokio::test]
async fn shredding_removes_every_key_and_keeps_the_rows() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db, 12, "acct-shred").await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let a = subject(&mut tx).await;
    assert!(
        tx.insert_subject_key(a, "contact", "realm-kek:1", &[4; 40])
            .await
            .unwrap()
    );
    assert!(
        !tx.insert_subject_key(a, "contact", "realm-kek:1", &[5; 40])
            .await
            .unwrap()
    );
    assert!(
        tx.insert_subject_key(a, "profile", "realm-kek:1", &[6; 40])
            .await
            .unwrap()
    );
    assert!(tx.add_identifier(a, "email", &sealed_id(3)).await.unwrap());
    tx.set_profile_field(a, "name", &[1; 12], &[2; 30])
        .await
        .unwrap();
    tx.set_profile_field(a, "name", &[3; 12], &[4; 30])
        .await
        .unwrap();
    assert_eq!(
        tx.profile_fields(a).await.unwrap(),
        vec![(String::from("name"), [3; 12], vec![4; 30])]
    );
    assert!(
        tx.shred_subject(a).await.unwrap().len() == 2,
        "not purging: own key stays"
    );
    for (from, to) in [
        ("staged", "deactivated"),
        ("deactivated", "tombstone"),
        ("tombstone", "purging"),
    ] {
        assert!(tx.set_subject_status(a, from, to).await.unwrap());
    }
    let gone = tx.shred_subject(a).await.unwrap();
    assert_eq!(gone, vec![(String::from("credential"), vec![9; 40])]);
    assert_eq!(tx.shred_subject(a).await.unwrap(), Vec::new());
    assert!(
        tx.subject_key(a, "contact")
            .await
            .unwrap()
            .unwrap()
            .wrapped_dek
            .is_none()
    );
    assert!(
        tx.subject(a, false)
            .await
            .unwrap()
            .unwrap()
            .wrapped_dek
            .is_none()
    );
    assert_eq!(
        tx.subject_by_identifier(&[3; 32], "x").await.unwrap(),
        Some(a),
        "the blind index outlives the key (TN-76 m.5)"
    );
    assert_eq!(tx.identifiers(a).await.unwrap().len(), 1);
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

// TN-68, OP-153 m.15 (g)
#[tokio::test]
async fn a_live_linked_sign_in_is_a_method() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db, 7, "acct-l").await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let s = subject(&mut tx).await;
    let wa = credential(&mut tx, s, "webauthn").await;
    assert!(
        tx.link_federated(s, "google", &[9; 32], None, 10)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(tx.revoke_credential(s, wa).await.unwrap(), Revoke::Done);
    let link = tx.federated_of(s).await.unwrap()[0].link;
    assert!(!tx.keeps_a_method(s, link).await.unwrap());
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
    tx.add_identifier(s, "username", &sealed_id(1))
        .await
        .unwrap();
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
