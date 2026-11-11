//! OP-158 m.3 (e), (f), (g), TI-13, AP-14: export runs, replica acknowledgements and the
//! checkpoints a mirror stream carries, against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::authority::{LogRecord, create_domain};
use access_store::authority_checkpoint::{AuthorityCheckpoint, append};
use access_store::mirror::{
    ExportRun, ReplicaAckRow, RunKind, ack, acked, checkpoint_exists, checkpoints, run, start_run,
};
use access_store::scope::DomainId;
use access_store::testing::{TestDb, fresh};

const TENANT: [u8; 16] = [0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 3];

async fn domain(db: &TestDb, seed: u8) -> DomainId {
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1_000,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, TENANT, &g, &[])
        .await
        .unwrap();
    d
}

fn cp(issued_at: u64, size: u64, seed: u8) -> AuthorityCheckpoint {
    AuthorityCheckpoint {
        issued_at,
        size,
        root: [seed; 32],
        note: format!("note {size}"),
        excerpt: vec![seed],
    }
}

// G28, SI-15, OP-73
#[tokio::test]
async fn an_export_run_is_kept_once_and_never_changed() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 0x31).await;
    let r = ExportRun {
        export: [7; 32],
        kind: RunKind::Mirror,
        party: [1; 16],
        instance: [2; 16],
        pep: String::from("replica-pep"),
        from: 0,
        to: None,
        full: true,
        started_at: 5_000,
    };
    assert!(start_run(&db.app, &d, &r).await.unwrap());
    assert!(!start_run(&db.app, &d, &r).await.unwrap());
    assert_eq!(run(&db.app, &d, &[7; 32]).await.unwrap(), Some(r));
    assert_eq!(run(&db.app, &d, &[8; 32]).await.unwrap(), None);
    let other = domain(&db, 0x32).await;
    assert_eq!(run(&db.app, &other, &[7; 32]).await.unwrap(), None);
    let package = ExportRun {
        export: [9; 32],
        kind: RunKind::Package,
        party: [1; 16],
        instance: [2; 16],
        pep: String::from("p"),
        from: 2,
        to: None,
        full: false,
        started_at: 5_000,
    };
    assert!(start_run(&db.app, &d, &package).await.is_err());
    let mut tx = db.owner.begin().await.unwrap();
    sqlx::query("SELECT set_config('app.domain_id', $1, true)")
        .bind("31".repeat(32))
        .execute(&mut *tx)
        .await
        .unwrap();
    let changed = sqlx::query("UPDATE access.export_runs SET pep = 'x'")
        .execute(&mut *tx)
        .await;
    assert!(changed.is_err());
}

// TI-13, SEC23
#[tokio::test]
async fn replica_acks_are_kept_per_size_and_read_as_the_largest() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 0x33).await;
    let row = |size: u64| ReplicaAckRow {
        replica: String::from("acme-replica"),
        size,
        root: [size as u8; 32],
        acked_at: 10 * size,
        signature: [size as u8; 64],
    };
    assert!(ack(&db.sequencer, &d, &row(3)).await.unwrap());
    assert!(!ack(&db.sequencer, &d, &row(3)).await.unwrap());
    assert!(ack(&db.sequencer, &d, &row(5)).await.unwrap());
    let names = [String::from("acme-replica"), String::from("other")];
    assert_eq!(
        acked(&db.app, &d, &names).await.unwrap(),
        vec![(names[0].clone(), 5), (names[1].clone(), 0)]
    );
    assert!(ack(&db.app, &d, &row(6)).await.is_err());
}

// T21, OP-158 m.3 (f)
#[tokio::test]
async fn a_stream_reads_the_checkpoints_of_a_size_range() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 0x34).await;
    for c in [cp(100, 1, 1), cp(200, 3, 3), cp(300, 3, 3), cp(400, 6, 6)] {
        append(&db.sequencer, &d, &c).await.unwrap();
    }
    let got = checkpoints(&db.app, &d, 1, 6).await.unwrap();
    assert_eq!(
        got.iter()
            .map(|c| (c.size, c.issued_at))
            .collect::<Vec<_>>(),
        [(3, 300), (6, 400)]
    );
    assert!(checkpoint_exists(&db.app, &d, 3, &[3; 32]).await.unwrap());
    assert!(!checkpoint_exists(&db.app, &d, 3, &[4; 32]).await.unwrap());
}
