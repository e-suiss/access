//! A Mandate's own limits on the real store (C14, C27, INV-5, L0-EVAL-16b, OP-157 m.19 (a)):
//! its window, its while-conditions and its budget bound the Instance at the decision time,
//! and an explanation rebuilds the decision at the time its record carries.

use access_authority_core::app::Scope;
use access_kernel::combinator::{BlockerClass, Position};
use access_kernel::meta::MandateEnvelope;
use access_kernel::model::{BudgetDimension, BudgetTerm, BudgetWindow, WhileCondition};

use super::*;

/// ALICE's holding of a `shop:read` Grant on the meta-anchor.
async fn held(core: &mut Core, d: Digest) -> ExerciseBasis {
    let meta_anchor = meta::meta_anchor(&d);
    let issued = send(
        core,
        meta_request(
            d,
            10,
            ExerciseBasis::Anchor(meta_anchor),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(meta_anchor),
                holder: SubjectSelector::Party(ALICE),
                authority: authority(vec![action("shop", "read")], selector("shop")),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&issued);
    ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
        holder: ALICE,
        since: issued.record.unwrap(),
    })
}

/// ALICE binds her Instance to `shop:read` within `constraints`.
async fn bind(core: &mut Core, d: Digest, nonce: u8, constraints: ConstraintSet) {
    let bound = send(
        core,
        meta_request(
            d,
            nonce,
            self_anchor(d, 3),
            Payload::MandateBind {
                instance: alice_instance(d),
                envelope: MandateEnvelope {
                    authority: authority(vec![action("shop", "read")], selector("shop")).authority,
                    constraints,
                    requirements: BTreeSet::new(),
                    pin: None,
                    origins: access_kernel::combinator::Origins::default(),
                },
            },
        ),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&bound);
}

fn within(from: u64, until: u64) -> ConstraintSet {
    ConstraintSet {
        validity: Window { from, until },
        conditions: BTreeSet::new(),
        budget: BTreeSet::new(),
    }
}

fn at_instance(r: &Response, class: BlockerClass, subcode: Option<&str>) -> bool {
    r.decision.outcome == Outcome::Deny
        && r.decision.blockers.iter().any(|b| {
            b.class == class && b.subcode.as_deref() == subcode && b.position == Position::Instance
        })
}

// INV-5, C14, L0-EVAL-16b, OP-157 m.19 (a), Ek B 5577
#[tokio::test]
async fn an_expired_mandate_denies_and_is_explained_at_its_record_time() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let holding = held(&mut core, d).await;
    bind(&mut core, d, 11, within(NOW - 1_000, NOW + 5_000)).await;
    let read = |nonce| shop_request(d, nonce, Mode::Commit, holding);

    let inside = send(&mut core, read(20), ALICE_KEY).await.unwrap();
    allowed(&inside);
    let later = NOW + 10_000;
    let mut late = read(21);
    late.intent.validity = Window {
        from: NOW,
        until: later + 60_000,
    };
    let outside = send_at(&mut core, late.clone(), ALICE_KEY, later)
        .await
        .unwrap();
    assert!(
        at_instance(&outside, BlockerClass::Ended, Some("ended/expired")),
        "{outside:?}"
    );

    // X25, L1-ADP-15
    let again = core
        .explain_recorded(
            &incoming(read(20), ALICE_KEY),
            inside.record.unwrap(),
            Scope::Requester,
            later,
        )
        .await
        .unwrap();
    assert_eq!(again.decision.outcome, Outcome::Allow);
    fold_check(&db.sequencer, d).await.unwrap();
}

// C27, L0-EVAL-4, L0-EVAL-16b, OP-157 m.19 (a)
#[tokio::test]
async fn a_mandate_budget_draws_and_its_conditions_bound_the_instance() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let holding = held(&mut core, d).await;
    let mut once = within(0, NOW + 3_600_000);
    once.budget = BTreeSet::from([BudgetTerm {
        dimension: BudgetDimension::Count,
        capacity: 1,
        window: BudgetWindow::Total,
    }]);
    bind(&mut core, d, 11, once).await;
    let read = |nonce| shop_request(d, nonce, Mode::Commit, holding);
    allowed(&send(&mut core, read(20), ALICE_KEY).await.unwrap());
    let spent = send(&mut core, read(21), ALICE_KEY).await.unwrap();
    assert!(
        at_instance(&spent, BlockerClass::BudgetExhausted, None),
        "the first read drew the only one: {spent:?}"
    );

    let mut gone = within(0, NOW + 3_600_000);
    gone.conditions = BTreeSet::from([WhileCondition::InstanceAlive(Id([0x77; 16]))]);
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let holding = held(&mut core, d).await;
    bind(&mut core, d, 11, gone).await;
    let lapsed = send(
        &mut core,
        shop_request(d, 20, Mode::Commit, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert!(
        at_instance(&lapsed, BlockerClass::Ended, Some("ended/lapsed")),
        "{lapsed:?}"
    );
}
