//! OP-158 m.3 (l), §16.6 HO-1, HO-6, HO-8, §16.6.1 RB-6, U11, OP-73: the freeze, the batch that
//! closes a run by writing the provider binding, the database fence after an outgoing handover,
//! a re-anchor's thaw and the incoming provider's adoption, against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::StoreError;
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, commit_batch, create_domain, read_head, read_log,
};
use access_store::handover::{
    AdoptedNonce, Adoption, Role, adopt, freeze, frozen_at, refused_frozen, steps, thaw,
};
use access_store::scope::DomainId;
use access_store::testing::{TestDb, fresh};

const TENANT: [u8; 16] = [0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 4];

fn binding_key() -> Vec<u8> {
    let mut k = vec![0x81, 0x70];
    k.extend_from_slice(b"provider_binding");
    k
}

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

/// One record after the head, setting `effects`.
async fn push(
    db: &TestDb,
    d: &DomainId,
    effects: Vec<(Vec<u8>, u64, Option<Vec<u8>>)>,
) -> Result<u64, StoreError> {
    let head = read_head(&db.sequencer, d).await.unwrap();
    let pos = head.pos + 1;
    let leaf = [u8::try_from(pos % 251).unwrap(); 32];
    let mut frontier = head.frontier.clone();
    frontier.push(leaf);
    let effects = effects.into_iter().map(|(k, _, v)| (k, pos, v)).collect();
    commit_batch(
        &db.sequencer,
        d,
        TENANT,
        &CommitBatch {
            epoch: head.epoch,
            after: head.pos,
            records: vec![LogRecord {
                pos,
                kind: "decision",
                recorded_at: 2_000 + pos,
                leaf_hash: leaf,
                envelope: vec![0xa1, 1],
            }],
            head: HeadRow {
                pos,
                epoch: head.epoch,
                leaf_hash: leaf,
                recorded_at: 2_000 + pos,
                frontier,
            },
            nonces: vec![],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            effects,
        },
    )
    .await
    .map(|()| pos)
}

// HO-1, HO-6, U11, OP-73
#[tokio::test]
async fn an_outgoing_handover_moves_the_head_once_for_its_batch_and_never_again() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 0x41).await;
    push(&db, &d, vec![]).await.unwrap();
    let k = freeze(&db.sequencer, &d, [1; 16], Role::Outgoing, 7_000)
        .await
        .unwrap();
    assert_eq!(k, 2);
    assert_eq!(frozen_at(&db.app, &d).await.unwrap(), Some(7_000));
    assert!(matches!(
        freeze(&db.sequencer, &d, [2; 16], Role::Outgoing, 7_001).await,
        Err(StoreError::HeadMoved)
    ));
    // the batch: statements, then the decision that writes the binding
    push(&db, &d, vec![]).await.unwrap();
    let h = push(&db, &d, vec![(binding_key(), 0, Some(vec![0xa0]))])
        .await
        .unwrap();
    let s = steps(&db.app, &d).await.unwrap();
    assert!(
        s.iter()
            .any(|x| x.step == "committed" && x.h == Some(h) && x.k == k)
    );
    let after = push(&db, &d, vec![]).await.unwrap_err();
    assert!(refused_frozen(&after), "{after:?}");
    assert_eq!(read_head(&db.app, &d).await.unwrap().pos, h);
    assert!(matches!(
        thaw(&db.sequencer, &d, [1; 16]).await,
        Err(StoreError::HeadMoved)
    ));
    // the freeze itself is kept
    let mut tx = db.sequencer.begin().await.unwrap();
    sqlx::query("SELECT set_config('app.domain_id', $1, true)")
        .bind("41".repeat(32))
        .execute(&mut *tx)
        .await
        .unwrap();
    let cleared = sqlx::query("UPDATE access.domain_head SET frozen_at = NULL")
        .execute(&mut *tx)
        .await;
    assert!(cleared.is_err());
}

// RB-6, HO-1
#[tokio::test]
async fn a_re_anchor_thaws_after_its_batch_and_an_abandoned_run_gives_the_domain_back() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 0x42).await;
    freeze(&db.sequencer, &d, [3; 16], Role::Reanchor, 7_000)
        .await
        .unwrap();
    assert!(matches!(
        thaw(&db.sequencer, &d, [9; 16]).await,
        Err(StoreError::HeadMoved)
    ));
    push(&db, &d, vec![(binding_key(), 0, Some(vec![0xa0]))])
        .await
        .unwrap();
    thaw(&db.sequencer, &d, [3; 16]).await.unwrap();
    assert_eq!(frozen_at(&db.app, &d).await.unwrap(), None);
    push(&db, &d, vec![]).await.unwrap();

    let e = domain(&db, 0x43).await;
    freeze(&db.sequencer, &e, [4; 16], Role::Outgoing, 7_000)
        .await
        .unwrap();
    thaw(&db.sequencer, &e, [4; 16]).await.unwrap();
    push(&db, &e, vec![]).await.unwrap();
    assert!(matches!(
        freeze(&db.sequencer, &e, [5; 16], Role::Incoming, 7_000).await,
        Err(StoreError::Range)
    ));
}

// HO-8, TI-2
#[tokio::test]
async fn the_incoming_provider_adopts_the_log_state_nonces_and_head() {
    let db = fresh().await.unwrap();
    let d = DomainId::from_bytes([0x44; 32]);
    let records: Vec<LogRecord> = (0..3_u64)
        .map(|pos| LogRecord {
            pos,
            kind: if pos == 0 { "genesis" } else { "decision" },
            recorded_at: 1_000 + pos,
            leaf_hash: [u8::try_from(pos + 1).unwrap(); 32],
            envelope: vec![0xa1, u8::try_from(pos).unwrap()],
        })
        .collect();
    let a = Adoption {
        run: [6; 16],
        k: 1,
        cited_root: [7; 32],
        records: records.clone(),
        head: HeadRow {
            pos: 2,
            epoch: 0,
            leaf_hash: [3; 32],
            recorded_at: 1_002,
            frontier: vec![[8; 32], [3; 32]],
        },
        state: vec![
            (binding_key(), Some(vec![0xa0]), 2),
            (vec![0x81, 0x61, 0x78], None, 1),
        ],
        nonces: vec![AdoptedNonce {
            nonce: vec![1; 16],
            actor: vec![2; 16],
            intent_digest: [3; 32],
            decision_pos: 2,
            outcome: String::from("allow"),
        }],
        counters: vec![(vec![9], 4)],
        single_use: vec![(vec![10], 2)],
    };
    adopt(&db.sequencer, &d, TENANT, &a).await.unwrap();
    assert_eq!(read_head(&db.app, &d).await.unwrap().pos, 2);
    assert_eq!(
        read_log(&db.app, &d, 0, 2).await.unwrap().len(),
        records.len()
    );
    assert!(
        access_store::authority::find_nonce(&db.app, &d, &[1; 16])
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        steps(&db.app, &d)
            .await
            .unwrap()
            .iter()
            .any(|s| s.step == "adopted" && s.role == Role::Incoming && s.h == Some(2))
    );
    assert!(adopt(&db.sequencer, &d, TENANT, &a).await.is_err());
    let mut short = a.clone();
    short.records.truncate(2);
    assert!(matches!(
        adopt(
            &db.sequencer,
            &DomainId::from_bytes([0x45; 32]),
            TENANT,
            &short
        )
        .await,
        Err(StoreError::Range)
    ));
}
