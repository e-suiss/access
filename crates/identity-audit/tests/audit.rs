//! OP-10, OP-37, OP-38, OPI-6, OP-134: the audit log and its checkpoints on a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::{Duration, Instant};

use access_identity_audit::adapters::PgAudit;
use access_identity_audit::app::step;
use access_identity_audit::domain::leaf;
use access_store::audit::{AuditEvent, append_checkpoint, last_checkpoint, open_month, pending};
use access_store::identity::{Cursor, RealmId, TenantId, TenantTx};
use access_store::testing::{TestDb, fresh};
use suiss_ledger::merkle::Frontier;

const T: TenantId = TenantId::from_bytes([1; 16]);
const R: RealmId = RealmId::from_bytes([2; 16]);

fn event(n: usize) -> (String, String) {
    (format!("usr_{n}"), format!("req_{n}"))
}

async fn audit(db: &TestDb, n: usize) {
    let (target, corr) = event(n);
    let mut t = TenantTx::begin(&db.app, T, R).await.unwrap();
    t.audit(&AuditEvent {
        event_type: "session.revoked",
        actor: "adm_1",
        target: &target,
        correlation: &corr,
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
}

/// Steps until the tree holds `n` rows; the watermark is cluster-wide (OP-131 m.4).
async fn integrate(db: &TestDb, n: u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        step(&PgAudit(db.checkpointer.clone())).await.unwrap();
        let size = last_checkpoint(&db.checkpointer)
            .await
            .unwrap()
            .map_or(0, |c| c.size);
        if size >= n {
            return size;
        }
        assert!(Instant::now() < deadline, "{size} of {n} rows after 20 s");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// OPI-6: the audit row commits or rolls back with the change it records
#[tokio::test]
async fn the_row_shares_the_business_transaction() {
    let db = fresh().await.unwrap();
    let mut t = TenantTx::begin(&db.app, T, R).await.unwrap();
    t.audit(&AuditEvent {
        event_type: "mfa.removed",
        actor: "adm_1",
        target: "usr_1",
        correlation: "req_1",
    })
    .await
    .unwrap();
    t.rollback().await.unwrap();
    audit(&db, 2).await;
    assert_eq!(integrate(&db, 1).await, 1);
    let rows = pending(&db.checkpointer, Cursor::default(), 10)
        .await
        .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.target.as_str()).collect::<Vec<_>>(),
        ["usr_2"]
    );
}

// OP-37, OP-38: checkpoints extend one tree; steps in pieces give the same root as one step
#[tokio::test]
async fn checkpoints_extend_one_tree() {
    let db = fresh().await.unwrap();
    for n in 0..5 {
        audit(&db, n).await;
    }
    let first = integrate(&db, 5).await;
    for n in 5..12 {
        audit(&db, n).await;
    }
    assert_eq!(integrate(&db, 12).await, 12);
    assert_eq!(first, 5);
    let rows = pending(&db.checkpointer, Cursor::default(), 100)
        .await
        .unwrap();
    let mut f = Frontier::default();
    for r in &rows {
        f.push(leaf(r).unwrap()).unwrap();
    }
    let last = last_checkpoint(&db.checkpointer).await.unwrap().unwrap();
    assert_eq!(last.root, f.root());
    assert_eq!(
        last.cursor,
        Cursor {
            xid: rows[11].xid,
            id: rows[11].id
        }
    );
    // OP-38: nothing new, no checkpoint
    assert!(
        step(&PgAudit(db.checkpointer.clone()))
            .await
            .unwrap()
            .is_none()
    );
}

// OQ-MD3 scenario 1 for the audit log: a running transaction is waited for, not skipped
#[tokio::test]
async fn a_running_transaction_is_not_skipped() {
    let db = fresh().await.unwrap();
    let mut early = TenantTx::begin(&db.app, T, R).await.unwrap();
    early
        .audit(&AuditEvent {
            event_type: "role.granted",
            actor: "adm_1",
            target: "usr_0",
            correlation: "req_0",
        })
        .await
        .unwrap();
    audit(&db, 1).await;
    step(&PgAudit(db.checkpointer.clone())).await.unwrap();
    assert!(last_checkpoint(&db.checkpointer).await.unwrap().is_none());
    early.commit().await.unwrap();
    assert_eq!(integrate(&db, 2).await, 2);
    let rows = pending(&db.checkpointer, Cursor::default(), 10)
        .await
        .unwrap();
    assert_eq!(rows[0].target, "usr_0");
}

// OP-17, OP-38: checkpoints are append-only and one size is written once
#[tokio::test]
async fn checkpoints_cannot_fork_or_change() {
    let db = fresh().await.unwrap();
    audit(&db, 1).await;
    integrate(&db, 1).await;
    let mut c = last_checkpoint(&db.checkpointer).await.unwrap().unwrap();
    c.root = [0; 32];
    assert!(append_checkpoint(&db.checkpointer, &c).await.is_err());
}

// OP-12: tenants and realms see only their own rows; the checkpointer reads all of them
#[tokio::test]
async fn audit_rows_are_scoped() {
    let db = fresh().await.unwrap();
    audit(&db, 1).await;
    let other = TenantId::from_bytes([9; 16]);
    let mut t = TenantTx::begin(&db.app, other, R).await.unwrap();
    t.audit(&AuditEvent {
        event_type: "login.failed",
        actor: "anon",
        target: "usr_9",
        correlation: "req_9",
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    assert_eq!(integrate(&db, 2).await, 2);
    let mut tx = TenantTx::begin(&db.app, T, R).await.unwrap();
    assert_eq!(tx.list_audit(10).await.unwrap().len(), 1);
    let mut tx = TenantTx::begin_tenant(&db.app, T).await.unwrap();
    assert_eq!(tx.list_audit(10).await.unwrap().len(), 0);
}

// OP-13b: the archive role opens monthly partitions; rows land in them
#[tokio::test]
async fn monthly_partitions() {
    let db = fresh().await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let days = i64::try_from(now / 86_400).unwrap();
    // civil date of today (Howard Hinnant's algorithm), to open the current month
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let name = open_month(
        &db.archive,
        i32::try_from(year).unwrap(),
        u32::try_from(month).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        open_month(
            &db.archive,
            i32::try_from(year).unwrap(),
            u32::try_from(month).unwrap()
        )
        .await
        .unwrap(),
        name
    );
    audit(&db, 1).await;
    assert_eq!(integrate(&db, 1).await, 1);
    assert!(
        open_month(&db.app, 2030, 1).await.is_err(),
        "only the archive role opens partitions"
    );
}
