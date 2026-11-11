//! A distinct-surface term counts approvals by the surface path they came through, recorded
//! with each contribution (§13.7.3, OP-157 m.8 (l), m.14 (o), OP-158 m.3 (b)).

use super::*;

/// ALICE's approval `nonce` of `target` shown on `profile` at `origin`.
fn approved_on(
    d: Digest,
    nonce: u8,
    (target, render): (Digest, Digest),
    surface: (&str, Option<&str>),
) -> Request {
    let mut act = approval_act(d, nonce, target, render, NOW - 1_000, NOW + 60_000);
    surface.0.clone_into(&mut act.surface_profile);
    act.surface_origin = surface.1.map(str::to_owned);
    let h = access_kernel::aas::digest(&act).unwrap();
    with_proofs(
        contribute(d, nonce, target),
        vec![
            ProofRef::Aas(act.to_bytes().unwrap()),
            ProofRef::Claim(approval_claim(d, h, &PASSKEY_UV, NOW - 5_000)),
        ],
    )
}

// §13.7.3, §13.2, OP-157 m.14 (o), OP-158 m.3 (b), Ek B 5475, 5476, 5498
#[tokio::test]
async fn a_distinct_surface_term_counts_each_surface_path_once() {
    let db = fresh().await.unwrap();
    let mut two = term(
        ProofKind::Contribution,
        "approve",
        ProofBinding::IntentDigest,
    );
    two.count = 2;
    two.independence = Independence::DistinctSurface;
    let (mut core, d) = setup_with(&db, gated_with(&[two], 8)).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let target = shop_request(d, 9, Mode::Commit, shop);
    let shown = (
        access_kernel::intent::intent_digest(&target.intent).unwrap(),
        render_of(&target),
    );
    let asked = send(&mut core, target.clone(), ROOT_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction);

    let mut give = async |nonce, surface| {
        let r = send(&mut core, approved_on(d, nonce, shown, surface), ALICE_KEY)
            .await
            .unwrap();
        allowed(&r);
        ProofRef::Contribution(r.exercise.unwrap())
    };
    let hosted = give(20, ("suiss-approval-surface", Some("https://id.example"))).await;
    let hosted_again = give(21, ("suiss-approval-surface", Some("https://id.example"))).await;
    let unnamed = give(22, ("suiss-approver-sdk", None)).await;
    let device = give(23, ("suiss-approver-sdk", Some("app:approver"))).await;

    let state = state_of(
        &db,
        d,
        &meta::exercise_key(
            kind::CONTRIBUTION,
            &match &hosted {
                ProofRef::Contribution(e) => *e,
                _ => panic!("a contribution"),
            },
        ),
    )
    .await
    .map(|b| {
        meta::ContributionState::from_value(&dcbor::decode(&b, Limits::CEILING).unwrap()).unwrap()
    })
    .unwrap();
    assert_eq!(
        state.surface_path,
        Some(
            access_kernel::aas::surface_path("suiss-approval-surface", "https://id.example")
                .unwrap()
        )
    );

    for proofs in [
        vec![hosted.clone(), hosted_again],
        vec![hosted.clone(), unnamed],
    ] {
        let one = send(&mut core, with_proofs(target.clone(), proofs), ROOT_KEY)
            .await
            .unwrap();
        assert_eq!(one.decision.outcome, Outcome::RequireAction, "{one:?}");
    }
    let done = send(
        &mut core,
        with_proofs(target, vec![hosted, device]),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&done);
    fold_check(&db.sequencer, d).await.unwrap();
}
