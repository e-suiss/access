//! OP-156 m.3 (e)–(h), OP-73: the SMS and SPC settings are written only under their own committed
//! ALLOWs; an SMS code takes three tries and is used once; an approver's PIN declaration is kept
//! beside its answer; SIM change signals are appended and read newest; a mirror version becomes
//! current in one step and the one it replaces is archived, never removed.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::Duration;

use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{Bound, Decision, bind, create_settings};
use access_store::payment::{
    NewSmsCode, SimChange, fail_mirror_version, mirror_versions, promote_mirror_version,
    record_sim_change, sim_changes, stage_mirror_version,
};
use access_store::push::{NewDeviceKey, NewPushChallenge};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant, set_issuer};
use access_store::testing::{TestDb, fresh};

const TTL: Duration = Duration::from_secs(10);
const INTENT: [u8; 32] = [9; 32];

async fn domain(db: &TestDb, t: TenantId, seed: u8, allows: u8) -> DomainId {
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
    let (lease, mut head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    for i in 1..=allows {
        let pos = head.pos + 1;
        let leaf = [seed.wrapping_add(i); 32];
        let next = HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: leaf,
            recorded_at: 2,
            frontier: vec![leaf],
        };
        let batch = CommitBatch {
            epoch: lease.epoch,
            after: head.pos,
            records: vec![LogRecord {
                pos,
                kind: "decision",
                recorded_at: 2,
                leaf_hash: leaf,
                envelope: vec![0xa1, i],
            }],
            head: next.clone(),
            nonces: vec![NonceRow {
                nonce: vec![i; 16],
                actor: vec![1],
                intent_digest: INTENT,
                decision_pos: pos,
                outcome: String::from("allow"),
                render_digest: None,
                tier: None,
            }],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            effects: vec![],
        };
        commit_batch(&db.sequencer, &d, *t.as_bytes(), &batch)
            .await
            .unwrap();
        head = next;
    }
    d
}

async fn realm(db: &TestDb, t: TenantId, d: &DomainId, slug: &str) -> RealmId {
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, d, slug, "pool-default")
        .await
        .unwrap();
    tx.enter_realm(r).await.unwrap();
    create_settings(&mut tx).await.unwrap();
    assert!(
        set_issuer(&mut tx, &format!("https://{slug}.suiss.id"))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    r
}

async fn allow(tx: &mut TenantTx, d: &DomainId, pos: u8, action: &str) -> Bound {
    let nonce = [pos; 16];
    bind(
        tx,
        &Decision {
            domain: d,
            position: u64::from(pos),
            nonce: &nonce,
            intent: INTENT,
            change: [5; 32],
            action,
        },
    )
    .await
    .unwrap()
    .unwrap()
}

async fn subject(db: &TestDb, t: TenantId, r: RealmId) -> [u8; 16] {
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let s = tx
        .insert_subject("active", "kek-1", &[1; 40])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    s
}

// OP-156 m.3 (f), (g), EI-25
#[tokio::test]
async fn sms_and_spc_settings_need_their_own_allows() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 60, 4).await;
    let r = realm(&db, t, &d, "pay").await;

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(!tx.sms_otp_enabled().await.unwrap());
    assert!(!tx.spc_enabled().await.unwrap());
    let wrong = allow(&mut tx, &d, 1, "idp.realm.push").await;
    assert!(tx.put_sms_otp(&wrong, true).await.is_err());
    drop(tx);

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = allow(&mut tx, &d, 1, "idp.realm.sms_otp").await;
    tx.put_sms_otp(&b, true).await.unwrap();
    let b = allow(&mut tx, &d, 2, "idp.realm.spc").await;
    tx.put_spc(&b, true).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(tx.sms_otp_enabled().await.unwrap());
    assert!(tx.spc_enabled().await.unwrap());
    let b = allow(&mut tx, &d, 3, "idp.realm.sms_otp_close").await;
    tx.put_sms_otp(&b, false).await.unwrap();
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(!tx.sms_otp_enabled().await.unwrap());
}

// OP-156 m.3 (f), OP-73
#[tokio::test]
async fn an_sms_code_takes_three_tries_and_is_used_once() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 61, 0).await;
    let r = realm(&db, t, &d, "sms").await;
    let s = subject(&db, t, r).await;
    let code = |binding: &'static [u8; 32]| NewSmsCode {
        subject: s,
        purpose: "sign_in",
        binding,
        code_hash: &[3; 32],
        created_ms: 1_000,
        expires_ms: 301_000,
    };
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    tx.insert_sms_code(&code(&[1; 32])).await.unwrap();
    tx.insert_sms_code(&code(&[2; 32])).await.unwrap();
    let bad = NewSmsCode {
        expires_ms: 999_000,
        ..code(&[1; 32])
    };
    assert!(tx.insert_sms_code(&bad).await.is_err());
    drop(tx);

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    tx.insert_sms_code(&code(&[1; 32])).await.unwrap();
    tx.insert_sms_code(&code(&[2; 32])).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(tx.sms_code(&[1; 32], "activation").await.unwrap().is_none());
    let row = tx.sms_code(&[1; 32], "sign_in").await.unwrap().unwrap();
    assert_eq!((row.attempts, row.used_ms), (0, None));
    for _ in 0..3 {
        assert!(tx.try_sms_code(row.id, None).await.unwrap());
    }
    assert!(!tx.try_sms_code(row.id, Some(5)).await.unwrap());
    let other = tx.sms_code(&[2; 32], "sign_in").await.unwrap().unwrap();
    assert!(tx.try_sms_code(other.id, Some(5)).await.unwrap());
    assert!(!tx.try_sms_code(other.id, None).await.unwrap());
    assert_eq!(tx.sms_codes_since(s, 0).await.unwrap(), 2);
    tx.commit().await.unwrap();

    let refused =
        sqlx::query("UPDATE access.sms_codes SET used_ms = NULL, attempts = attempts + 1")
            .execute(&db.owner)
            .await;
    assert!(refused.is_err());
}

// OP-156 m.3 (e), MD-11
#[tokio::test]
async fn an_approver_key_is_attested_and_its_pin_declarations_are_kept() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 62, 0).await;
    let r = realm(&db, t, &d, "app").await;
    let s = subject(&db, t, r).await;
    let mut key = [4_u8; 65];
    key[0] = 4;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(
        tx.insert_device_key(&NewDeviceKey {
            id: [7; 16],
            subject: s,
            thumbprint: [8; 32],
            public_key: &key,
            name: "phone",
        })
        .await
        .unwrap()
    );
    let plain = tx.app_factor_key([7; 16]).await.unwrap().unwrap();
    assert!(!plain.hardware_attested && !plain.app_pin);
    assert!(!tx.attest_app_factor_key([9; 16], [7; 16]).await.unwrap());
    assert!(tx.attest_app_factor_key(s, [7; 16]).await.unwrap());
    let attested = tx.app_factor_key([7; 16]).await.unwrap().unwrap();
    assert!(attested.hardware_attested && attested.app_pin);
    tx.insert_push_challenge(&NewPushChallenge {
        hash: &[5; 32],
        subject: s,
        flow_hash: &[6; 32],
        number: 42,
        origin_device: None,
        created_ms: 1_000,
        expires_ms: 121_000,
    })
    .await
    .unwrap();
    let c = tx.push_challenge(&[5; 32]).await.unwrap().unwrap();
    assert!(!tx.app_factor_answer(c.id).await.unwrap());
    tx.record_app_factor_answer(c.id, [7; 16], true)
        .await
        .unwrap();
    assert!(tx.app_factor_answer(c.id).await.unwrap());
    assert!(
        tx.record_app_factor_answer(c.id, [7; 16], false)
            .await
            .is_err()
    );
}

// OP-156 m.3 (f), IDP-9, OP-73
#[tokio::test]
async fn sim_change_signals_are_appended_and_read_by_their_newest_check() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 63, 2).await;
    assert_eq!(sim_changes(&db.app, &d, &[1; 16]).await.unwrap(), None);
    let signal = |claim: u8, pos: u64, last: u64, checked: u64| SimChange {
        subject: [1; 16],
        claim: [claim; 16],
        issuer: [2; 16],
        pos,
        last_change_ms: last,
        checked_ms: checked,
    };
    record_sim_change(&db.sequencer, &d, &signal(1, 1, 100, 200))
        .await
        .unwrap();
    record_sim_change(&db.sequencer, &d, &signal(2, 2, 50, 900))
        .await
        .unwrap();
    record_sim_change(&db.sequencer, &d, &signal(2, 2, 1, 1))
        .await
        .unwrap();
    assert_eq!(
        sim_changes(&db.app, &d, &[1; 16]).await.unwrap(),
        Some((100, 900))
    );
    assert!(
        record_sim_change(&db.sequencer, &d, &signal(3, 2, 900, 100))
            .await
            .is_err()
    );
    assert!(
        record_sim_change(&db.app, &d, &signal(4, 2, 1, 2))
            .await
            .is_err()
    );
}

// OP-156 m.3 (h), OP-73
#[tokio::test]
async fn a_mirror_version_becomes_current_and_the_old_one_is_archived() {
    let db = fresh().await.unwrap();
    let dir = "/var/lib/access/hibp-q6-test";
    let first = stage_mirror_version(&db.app, dir, "ranges.example")
        .await
        .unwrap();
    assert!(
        promote_mirror_version(&db.app, first, 3, &[1; 32])
            .await
            .unwrap()
    );
    assert!(
        !promote_mirror_version(&db.app, first, 3, &[1; 32])
            .await
            .unwrap()
    );
    let broken = stage_mirror_version(&db.app, dir, "ranges.example")
        .await
        .unwrap();
    fail_mirror_version(&db.app, broken).await.unwrap();
    assert!(
        !promote_mirror_version(&db.app, broken, 3, &[1; 32])
            .await
            .unwrap()
    );
    let second = stage_mirror_version(&db.app, dir, "ranges.example")
        .await
        .unwrap();
    assert!(
        promote_mirror_version(&db.app, second, 4, &[2; 32])
            .await
            .unwrap()
    );
    let v = mirror_versions(&db.app, dir).await.unwrap();
    let status: Vec<(&[u8; 16], &str)> = v.iter().map(|m| (&m.id, m.status.as_str())).collect();
    assert_eq!(
        status,
        [
            (&second, "current"),
            (&broken, "failed"),
            (&first, "archived")
        ]
    );
    assert!(
        sqlx::query("DELETE FROM access.hibp_mirror_versions")
            .execute(&db.owner)
            .await
            .is_err()
    );
}
