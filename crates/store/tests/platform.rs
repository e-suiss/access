//! OP-149 m.4, m.16 (a), OP-73: a platform pairing is recorded once and never deleted, the
//! platform client's Party binding is fixed, and both stay inside their realm.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::platform::PairingRow;
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};

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

fn row(challenge: u8, until: u64) -> PairingRow {
    PairingRow {
        challenge: [challenge; 32],
        client_id: String::from("cli_work"),
        kid: [7; 32],
        party: [3; 16],
        register: true,
        valid_from_ms: 1_000,
        valid_until_ms: until,
        instance: None,
    }
}

// OP-149 m.4, m.16 (a), OP-73
#[tokio::test]
async fn a_pairing_is_recorded_once_and_kept() {
    // L0-META-7, TN-1
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db, 1, "acme").await;
    let (t2, r2) = realm(&db, 2, "beta").await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    tx.insert_pairing(&row(1, 2_000)).await.unwrap();
    tx.insert_pairing(&row(2, 5_000)).await.unwrap();
    assert_eq!(
        tx.current_pairing("cli_work", &[7; 32], 3_000)
            .await
            .unwrap()
            .map(|p| p.challenge),
        Some([2; 32])
    );
    assert!(
        tx.current_pairing("cli_work", &[7; 32], 6_000)
            .await
            .unwrap()
            .is_none()
    );
    assert!(tx.record_pairing(&[1; 32], &[9; 16]).await.unwrap());
    assert!(!tx.record_pairing(&[1; 32], &[8; 16]).await.unwrap());
    let current = tx
        .current_pairing("cli_work", &[7; 32], 6_000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (current.challenge, current.instance),
        ([1; 32], Some([9; 16]))
    );
    assert!(tx.platform_party("cli_work").await.unwrap().is_none());
    assert!(tx.bind_platform_party("cli_work", &[3; 16]).await.unwrap());
    assert!(!tx.bind_platform_party("cli_work", &[4; 16]).await.unwrap());
    assert_eq!(tx.platform_party("cli_work").await.unwrap(), Some([3; 16]));
    tx.commit().await.unwrap();

    let other = TenantTx::begin(&db.app, t2, r2).await.unwrap();
    let seen = other
        .raw_rows("SELECT challenge FROM access.platform_pairing")
        .await
        .unwrap();
    assert!(seen.is_empty(), "another realm's pairings are not visible");

    for sql in [
        "DELETE FROM access.platform_pairing",
        "DELETE FROM access.platform_party",
        "UPDATE access.platform_pairing SET instance_id = NULL, paired_at = NULL",
        "UPDATE access.platform_party SET party_id = party_id",
    ] {
        let tx = TenantTx::begin(&db.app, t, r).await.unwrap();
        assert!(tx.raw_rows(sql).await.is_err(), "{sql}");
    }
}
