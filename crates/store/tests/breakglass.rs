//! OP-157 m.3 (h), §12.3.8 (4), OP-73: break-glass uses and their reviews on real Postgres. A
//! use is recorded once, falls overdue past its window, is reviewed only by another Party under a
//! committed ALLOW, and every change is a new row version.

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
use access_store::breakglass::{BreakglassUse, Review, ReviewState};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{Decision, bind, create_settings};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
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
            beside: vec![],
            effects: vec![],
        };
        commit_batch(&db.sequencer, &d, *t.as_bytes(), &batch)
            .await
            .unwrap();
        head = next;
    }
    d
}

async fn realm(db: &TestDb, t: TenantId, d: &DomainId) -> RealmId {
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, d, "acme", "pool-default")
        .await
        .unwrap();
    tx.enter_realm(r).await.unwrap();
    create_settings(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    r
}

fn decision<'a>(d: &'a DomainId, position: u64, nonce: &'a [u8], action: &'a str) -> Decision<'a> {
    Decision {
        domain: d,
        position,
        nonce,
        intent: INTENT,
        change: [5; 32],
        action,
    }
}

fn used(seed: u8, drill: bool, used_at_ms: u64) -> BreakglassUse {
    BreakglassUse {
        exercise: [seed; 32],
        drill,
        grant: [3; 16],
        actor: [4; 16],
        subject: Some([5; 16]),
        used_at_ms,
        due_at_ms: used_at_ms + 72 * 3_600_000,
    }
}

// OP-157 m.3 (h), §12.3.8 (4), (5), OP-73, Ek B 5537
#[tokio::test]
async fn a_use_is_reviewed_once_by_another_party_or_falls_overdue() {
    let db = fresh().await.unwrap();
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, tenant, 41, 2).await;
    let r = realm(&db, tenant, &d).await;
    let mut tx = TenantTx::begin(&db.app, tenant, r).await.unwrap();
    assert!(
        tx.record_breakglass_use(&used(1, false, 1_000))
            .await
            .unwrap()
    );
    assert!(
        !tx.record_breakglass_use(&used(1, false, 1_000))
            .await
            .unwrap()
    );
    assert!(
        tx.record_breakglass_use(&used(2, true, 2_000))
            .await
            .unwrap()
    );
    assert_eq!(tx.last_breakglass_drill().await.unwrap(), Some(2_000));
    let all = tx.breakglass_reviews().await.unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|r| r.state == ReviewState::Pending));

    let late = 2_000 + 72 * 3_600_000 + 1;
    let overdue = tx.mark_breakglass_overdue(late).await.unwrap();
    assert_eq!(overdue.len(), 2);
    assert_eq!(tx.mark_breakglass_overdue(late).await.unwrap(), Vec::new());

    let review = bind(
        &mut tx,
        &decision(&d, 1, &[1; 16], "idp.org.breakglass_review"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        tx.review_breakglass(&review, &[1; 32], "emergency", &[4; 16])
            .await
            .unwrap(),
        Review::OwnUse
    );
    assert_eq!(
        tx.review_breakglass(&review, &[9; 32], "emergency", &[6; 16])
            .await
            .unwrap(),
        Review::Unknown
    );
    let Review::Done(done) = tx
        .review_breakglass(&review, &[1; 32], "emergency", &[6; 16])
        .await
        .unwrap()
    else {
        panic!("reviewed");
    };
    assert_eq!(done.version, 3);
    assert_eq!(
        tx.review_breakglass(&review, &[1; 32], "misuse", &[6; 16])
            .await
            .unwrap(),
        Review::Already
    );
    let all = tx.breakglass_reviews().await.unwrap();
    let first = all.iter().find(|r| r.used.exercise == [1; 32]).unwrap();
    assert_eq!(first.state, ReviewState::Reviewed);
    assert_eq!(first.classification.as_deref(), Some("emergency"));
    assert_eq!(first.reviewer, Some([6; 16]));
    assert_eq!(first.position, Some(1));
    tx.commit().await.unwrap();

    // OP-73
    for sql in [
        "UPDATE access.breakglass_reviews SET state = 'pending'",
        "DELETE FROM access.breakglass_reviews",
    ] {
        assert!(sqlx::query(sql).execute(&db.owner).await.is_err(), "{sql}");
    }
}
