//! The leader gate and cell moves on the real store (OP-31, OP-56, G64, TI-2, EI-20, FA-13,
//! §17.4.1, §17.4.10, §17.10.2, OP-158 m.3 (n), (q)): which process may lead a domain, the
//! graceful step-down, the semantic version gate after an activation record, and the seal and
//! acceptance that move a domain between cells without a second writer.

use access_authority_sequencer::cell::{self, Fence, MoveError, Point, Witnessed};
use access_kernel::verify::key_scope::SpecVersions;

use super::*;

fn v(core: u64) -> SpecVersions {
    SpecVersions {
        core,
        meta_schema: 1,
        ..SpecVersions::default()
    }
}

fn read(d: Digest, nonce: u8) -> Incoming {
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    incoming(
        shop_request(d, nonce, Mode::Commit, ExerciseBasis::Anchor(shop)),
        ROOT_KEY,
    )
}

/// ROOT and its Instance, registered through `p`.
async fn onboard(p: &Domains<Listed, Bound, Counter, Fixed>, d: Digest) {
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    for (nonce, payload) in [
        (
            2,
            Payload::PartyRegister {
                party: ROOT,
                root: Root::Sole(ROOT),
                actor_kind: ActorKind::Human,
            },
        ),
        (
            3,
            Payload::InstanceCreate {
                party: ROOT,
                key: public(ROOT_KEY),
                mandate: None,
            },
        ),
    ] {
        let inc = incoming(meta_request(d, nonce, public_basis, payload), ROOT_KEY);
        allowed(&p.exercise(&inc).await.unwrap());
    }
}

// OP-56, G64, OP-158 m.3 (q), Ek B 6036, 6037, 6120
#[tokio::test]
async fn g64_after_the_activation_record_only_nodes_of_the_new_semantics_lead() {
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let old = process(&db, "old", vec![d]);
    let new = process(&db, "new", vec![d]).with_semantics(v(2));
    onboard(&old, d).await;
    allowed(&old.exercise(&read(d, 10)).await.unwrap());
    old.release().await;
    allowed(&new.exercise(&read(d, 11)).await.unwrap());
    let meta = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    let activate = incoming(
        meta_request(d, 12, meta, Payload::VersionActivate { versions: v(2) }),
        ROOT_KEY,
    );
    allowed(&new.exercise(&activate).await.unwrap());
    assert_eq!(
        access_authority_sequencer::gate::activated(&db.app, &DomainId::from_bytes(d.0))
            .await
            .unwrap(),
        Some(v(2))
    );
    new.release().await;
    assert_eq!(
        unavailable(old.exercise(&read(d, 13)).await),
        "version-gate"
    );
    allowed(&new.exercise(&read(d, 14)).await.unwrap());
    new.release().await;
    assert_eq!(
        unavailable(old.exercise(&read(d, 15)).await),
        "version-gate"
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// OP-31, §17.4.10, FA-7, Ek B 5995
#[tokio::test]
async fn op_31_a_graceful_step_down_hands_the_domain_over_without_waiting_for_the_lease() {
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let a = process(&db, "a", vec![d]);
    let b = process(&db, "b", vec![d]);
    onboard(&a, d).await;
    allowed(&a.exercise(&read(d, 10)).await.unwrap());
    assert_eq!(unavailable(b.exercise(&read(d, 11)).await), "lease-held");
    let started = std::time::Instant::now();
    a.step_down().await;
    allowed(&b.exercise(&read(d, 12)).await.unwrap());
    assert!(
        started.elapsed() < TTL,
        "the next leader waited for the lease"
    );
    b.release().await;
    assert_eq!(unavailable(a.exercise(&read(d, 13)).await), "stepping-down");
    fold_check(&db.sequencer, d).await.unwrap();
}

async fn count_of(db: &TestDb, event: &str) -> i64 {
    access_store::testing::authority_events(db, event, None)
        .await
        .unwrap()
}

// TI-2, EI-20, U33, §17.4.1 item 1, T28, Ek B 5720, 5767, 5992, 6090
#[tokio::test]
async fn ti_2_a_sealed_cell_appends_nothing_and_the_target_continues_at_the_next_epoch() {
    let source = fresh().await.unwrap();
    let target = fresh().await.unwrap();
    let d = create_genesis(&source.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let a = process(&source, "cell-a", vec![d]);
    onboard(&a, d).await;
    allowed(&a.exercise(&read(d, 10)).await.unwrap());
    assert!(matches!(
        cell::seal(&source.sequencer, &source.app, d, "mover").await,
        Err(MoveError::Sequencer(SequencerError::Store(
            access_store::StoreError::LeaseHeld
        )))
    ));
    a.release().await;
    let (sealed_at, epoch) = cell::seal(&source.sequencer, &source.app, d, "mover")
        .await
        .unwrap();
    // U33, EI-20
    assert_eq!(unavailable(a.exercise(&read(d, 11)).await), "sealed");
    let b_source = process(&source, "other", vec![d]);
    assert_eq!(unavailable(b_source.exercise(&read(d, 12)).await), "sealed");
    assert!(
        cell::accept(
            &source.sequencer,
            &target.sequencer,
            &target.app,
            Digest([0x55; 32])
        )
        .await
        .is_err()
    );
    let accepted = cell::accept(&source.sequencer, &target.sequencer, &target.app, d)
        .await
        .unwrap();
    assert_eq!(accepted, epoch + 1);
    let id = DomainId::from_bytes(d.0);
    let head = access_store::cells::cell_head(&target.sequencer, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (head.head.pos, head.accepted_epoch),
        (sealed_at, Some(epoch + 1))
    );
    fold_check(&target.sequencer, d).await.unwrap();
    assert!(
        cell::accept(&source.sequencer, &target.sequencer, &target.app, d)
            .await
            .is_err()
    );
    let b = process(&target, "cell-b", vec![d]);
    let replay = b.exercise(&read(d, 10)).await.unwrap();
    assert!(
        replay.replayed,
        "the nonce committed on the source is known on the target"
    );
    let next = b.exercise(&read(d, 16)).await.unwrap();
    allowed(&next);
    let at = next.record.unwrap();
    assert!(at > sealed_at, "no position is reused");
    access_authority_sequencer::adapters::verify_chain(&target.sequencer, d, 0, at)
        .await
        .unwrap();
    assert_eq!(
        access_store::authority::read_head(&source.sequencer, &id)
            .await
            .unwrap()
            .pos,
        sealed_at
    );
    fold_check(&target.sequencer, d).await.unwrap();
    assert_eq!(count_of(&source, "domain.sealed").await, 1);
    assert_eq!(count_of(&target, "domain.accepted").await, 1);
}

// FA-13, OP-54-RL12, §17.4.1 item 2, T28, Ek B 5993, 6091, 6092
#[tokio::test]
async fn op_54_rl12_an_unplanned_continuation_needs_a_fence_proof_and_the_lost_head() {
    let gone = fresh().await.unwrap();
    let target = fresh().await.unwrap();
    let d = create_genesis(&gone.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let a = process(&gone, "lost", vec![d]);
    onboard(&a, d).await;
    allowed(&a.exercise(&read(d, 10)).await.unwrap());
    a.release().await;
    let id = DomainId::from_bytes(d.0);
    let copy = access_store::cells::image(&gone.sequencer, &id)
        .await
        .unwrap();
    allowed(&a.exercise(&read(d, 11)).await.unwrap());
    a.release().await;
    let lost_head = access_store::authority::read_head(&gone.sequencer, &id)
        .await
        .unwrap();
    let last = Point {
        pos: lost_head.pos,
        leaf: lost_head.leaf_hash,
    };
    assert!(matches!(
        cell::accept_unplanned(&target.sequencer, &target.app, d, &copy, None, None).await,
        Err(MoveError::Unfenced)
    ));
    let fence = Fence {
        evidence: String::from("stonith: cell-a primary powered off by the cloud API"),
        last,
    };
    assert!(matches!(
        cell::accept_unplanned(&target.sequencer, &target.app, d, &copy, Some(&fence), None).await,
        Err(MoveError::Uncovered(_))
    ));
    let full = access_store::cells::image(&gone.sequencer, &id)
        .await
        .unwrap();
    let wrong = Witnessed {
        size: 2,
        root: [9; 32],
    };
    assert!(matches!(
        cell::accept_unplanned(
            &target.sequencer,
            &target.app,
            d,
            &full,
            Some(&fence),
            Some(wrong)
        )
        .await,
        Err(MoveError::Uncovered(_))
    ));
    assert_eq!(count_of(&target, "failover.unfenced_attempt").await, 3);
    assert!(
        access_store::cells::cell_head(&target.sequencer, &id)
            .await
            .unwrap()
            .is_none()
    );
    let empty = Fence {
        evidence: String::from("  "),
        last,
    };
    assert!(matches!(
        cell::accept_unplanned(&target.sequencer, &target.app, d, &full, Some(&empty), None).await,
        Err(MoveError::Unfenced)
    ));
    let witnessed = cell::replay(d, &full, None).unwrap();
    let epoch = cell::accept_unplanned(
        &target.sequencer,
        &target.app,
        d,
        &full,
        Some(&fence),
        Some(Witnessed {
            size: last.pos + 1,
            root: witnessed.root,
        }),
    )
    .await
    .unwrap();
    assert_eq!(epoch, full.head.head.epoch + 1);
    assert_eq!(count_of(&target, "failover.promoted").await, 1);
    let b = process(&target, "cell-b", vec![d]);
    let next = b.exercise(&read(d, 12)).await.unwrap();
    allowed(&next);
    let at = next.record.unwrap();
    assert!(at > last.pos);
    access_authority_sequencer::adapters::verify_chain(&target.sequencer, d, 0, at)
        .await
        .unwrap();
    fold_check(&target.sequencer, d).await.unwrap();
}
