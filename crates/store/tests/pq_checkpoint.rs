//! CR-45 RA-2, RA-3, OP-159 m.3 (g), OP-73: post-quantum re-anchor checkpoints and their cosigns
//! against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::authority::{LogRecord, create_domain};
use access_store::pq_checkpoint::{PqCheckpoint, PqCosignRow, Reason, append, list};
use access_store::scope::DomainId;
use access_store::testing::fresh;

const TENANT: [u8; 16] = [0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 4];

fn cp(issued_at: u64, size: u64, cosigns: Vec<PqCosignRow>) -> PqCheckpoint {
    PqCheckpoint {
        issued_at,
        size,
        root: [7; 32],
        body: format!("body {size}"),
        sign1: vec![0xd2, 1],
        excerpt: vec![2],
        reason: Reason::Cadence,
        cosigns,
    }
}

// CR-45 RA-2, RA-3, OP-73
#[tokio::test]
async fn re_anchor_checkpoints_are_appended_once_and_read_newest_first() {
    let db = fresh().await.unwrap();
    let d = DomainId::from_bytes([0x5a; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1_000,
        leaf_hash: [0x5a; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, TENANT, &g, &[])
        .await
        .unwrap();
    let w = PqCosignRow {
        witness: String::from("w-pq"),
        cosigned_at: 3,
        sign1: vec![0xd2, 9],
    };
    assert!(append(&db.sequencer, &d, &cp(10, 2, vec![w.clone()])).await.unwrap());
    assert!(!append(&db.sequencer, &d, &cp(10, 2, vec![])).await.unwrap());
    let mut later = cp(20, 5, vec![]);
    later.reason = Reason::Retirement;
    assert!(append(&db.sequencer, &d, &later).await.unwrap());
    let all = list(&db.app, &d, None, 10).await.unwrap();
    assert_eq!(all.iter().map(|c| c.size).collect::<Vec<_>>(), [5, 2]);
    assert_eq!(all[0].reason, Reason::Retirement);
    assert_eq!(all[1].cosigns, vec![w]);
    assert_eq!(list(&db.app, &d, Some(2), 10).await.unwrap().len(), 1);
    // OP-73
    assert!(
        sqlx::query("DELETE FROM access.pq_checkpoints")
            .execute(&db.sequencer)
            .await
            .is_err()
    );
    assert!(append(&db.app, &d, &cp(30, 6, vec![])).await.is_err());
}
