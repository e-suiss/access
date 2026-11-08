//! Tenant analytics on a real PostgreSQL (IDP-36, OP-151 m.3 (n), TI-18, OP-47): the daily
//! counters derived from the day's flows and audit rows, the failed-login surge and the
//! realm-scoped read.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_identity_risk::app::analytics::{aggregate, read};
use access_store::audit::AuditEvent;
use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::sessions::{FlowUpdate, NewFlow};
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};

fn today() -> u32 {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    u32::try_from(ms / 86_400_000).unwrap()
}

async fn realms(db: &TestDb) -> (TenantId, RealmId, RealmId) {
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = DomainId::from_bytes([0x5a; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [0x5a; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *tenant.as_bytes(), &g, &[])
        .await
        .unwrap();
    let mut tx = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    let a = create_realm(&mut tx, &d, "an-alpha", "pool-default")
        .await
        .unwrap();
    let b = create_realm(&mut tx, &d, "an-beta", "pool-default")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (tenant, a, b)
}

async fn flow(tx: &mut TenantTx, day: u32, n: u8, state: &str, done: bool) {
    let day = i32::try_from(day).unwrap();
    let hash = [n; 32];
    tx.insert_flow(&NewFlow {
        day,
        flow_hash: &hash,
        device_hash: &[0; 32],
        resume_hash: None,
        expires_ms: i64::MAX / 2,
        state: state.as_bytes(),
    })
    .await
    .unwrap();
    if done {
        assert!(
            tx.update_flow(&FlowUpdate {
                day,
                flow_hash: &hash,
                version: 0,
                status: "done",
                state: state.as_bytes(),
                resume_hash: None,
            })
            .await
            .unwrap()
        );
    }
}

// IDP-36, OP-151 m.3 (n)
#[tokio::test]
async fn daily_counters_surge_and_viewer_scope() {
    let db = fresh().await.unwrap();
    let (tenant, a, b) = realms(&db).await;
    let day = today();
    let mut tx = TenantTx::begin(&db.app, tenant, a).await.unwrap();
    let pw = r#"{"purpose":"login","identifier":[1,2],"factors":[{"method":"password"}]}"#;
    let pw_totp = r#"{"purpose":"login","identifier":[1,2],"factors":[{"method":"password"},{"method":"totp"}],"risk":{"step_up":true}}"#;
    let typed = r#"{"purpose":"login","identifier":[1,2],"factors":[]}"#;
    let passkey = r#"{"purpose":"login","identifier":null,"factors":[{"method":"passkey"}]}"#;
    let enroll = r#"{"purpose":{"enroll_totp":{"session":[1]}},"factors":[]}"#;
    flow(&mut tx, day, 1, pw, true).await;
    flow(&mut tx, day, 2, pw_totp, true).await;
    flow(&mut tx, day, 3, typed, false).await;
    flow(&mut tx, day, 4, passkey, true).await;
    flow(&mut tx, day, 5, enroll, true).await;
    flow(&mut tx, day, 6, enroll, false).await;
    for _ in 0..120 {
        tx.audit(&AuditEvent {
            event_type: "login.password.failed",
            actor: "anonymous",
            target: "unknown",
            correlation: "req",
        })
        .await
        .unwrap();
    }
    let first = aggregate(&mut tx, day).await.unwrap();
    let again = aggregate(&mut tx, day).await.unwrap();
    tx.commit().await.unwrap();
    let d = first.day;
    assert_eq!(d.flows_started, 4);
    assert_eq!(d.identifier_entered, 3);
    assert_eq!(d.first_factor_passed, 3);
    assert_eq!(d.second_factor_passed, 1);
    assert_eq!(d.sessions_created, 3);
    assert_eq!((d.method_password, d.method_passkey), (2, 1));
    assert_eq!((d.mfa_setup_started, d.mfa_setup_completed), (2, 1));
    assert_eq!(d.failed_logins, 120);
    assert_eq!(d.risk_step_ups, 1);
    let surge = first.surge.unwrap();
    assert_eq!((surge.observed, surge.baseline), (120, 0));
    assert_eq!(again.surge, None);
    assert_eq!(again.day, d);

    let mut tx = TenantTx::begin(&db.app, tenant, a).await.unwrap();
    let mine = read(&mut tx, day, day).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(mine.days, [d]);
    assert_eq!(mine.surges.len(), 1);
    let mut tx = TenantTx::begin(&db.app, tenant, b).await.unwrap();
    let theirs = read(&mut tx, 0, day).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(theirs.days.len(), 0);
    assert_eq!(theirs.surges.len(), 0);
    let mut tx = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    assert!(read(&mut tx, 0, day).await.is_err());
}
