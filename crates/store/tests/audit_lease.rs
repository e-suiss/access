//! OP-152 m.5 (k): one writer per cell audit chain, against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::Duration;

use access_store::StoreError;
use access_store::audit::{CheckpointRow, last_checkpoint};
use access_store::audit_lease::{AuditChain, acquire_audit_lease, append_held_checkpoint};
use access_store::identity::Cursor;
use access_store::operational::last_operational_checkpoint;
use access_store::testing::fresh;

fn row(size: u64) -> CheckpointRow {
    CheckpointRow {
        size,
        root: [7; 32],
        frontier: vec![[7; 32]],
        cursor: Cursor { xid: 1, id: 1 },
        note: Some(String::from("note")),
    }
}

// OP-152 m.5 (k): only the replica holding a chain's lease appends its checkpoints
#[tokio::test]
async fn only_the_lease_holder_appends_a_chain_checkpoint() {
    let db = fresh().await.unwrap();
    let ttl = Duration::from_secs(30);
    for chain in [AuditChain::Identity, AuditChain::Operational] {
        assert!(
            acquire_audit_lease(&db.checkpointer, chain, "a", ttl)
                .await
                .unwrap()
        );
        assert!(
            !acquire_audit_lease(&db.checkpointer, chain, "b", ttl)
                .await
                .unwrap()
        );
        assert!(matches!(
            append_held_checkpoint(&db.checkpointer, chain, "b", &row(1)).await,
            Err(StoreError::LeaseLost)
        ));
        append_held_checkpoint(&db.checkpointer, chain, "a", &row(1))
            .await
            .unwrap();
        assert!(
            acquire_audit_lease(&db.checkpointer, chain, "a", ttl)
                .await
                .unwrap()
        );
    }
    assert_eq!(
        last_checkpoint(&db.checkpointer)
            .await
            .unwrap()
            .unwrap()
            .size,
        1
    );
    assert_eq!(
        last_operational_checkpoint(&db.checkpointer)
            .await
            .unwrap()
            .unwrap()
            .size,
        1
    );
}

// OP-152 m.5 (k): an expired lease passes to another replica and fences the old holder out
#[tokio::test]
async fn an_expired_lease_moves_and_fences_the_old_holder() {
    let db = fresh().await.unwrap();
    let chain = AuditChain::Identity;
    assert!(
        acquire_audit_lease(&db.checkpointer, chain, "a", Duration::ZERO)
            .await
            .unwrap()
    );
    assert!(matches!(
        append_held_checkpoint(&db.checkpointer, chain, "a", &row(1)).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(
        acquire_audit_lease(&db.checkpointer, chain, "b", Duration::from_secs(30))
            .await
            .unwrap()
    );
    assert!(matches!(
        append_held_checkpoint(&db.checkpointer, chain, "a", &row(1)).await,
        Err(StoreError::LeaseLost)
    ));
    append_held_checkpoint(&db.checkpointer, chain, "b", &row(1))
        .await
        .unwrap();
    let epoch: i64 = sqlx::query_scalar(
        "SELECT epoch FROM access_ops.audit_checkpoint_lease WHERE chain = 'identity-audit'",
    )
    .fetch_one(&db.checkpointer)
    .await
    .unwrap();
    assert_eq!(epoch, 2);
}
