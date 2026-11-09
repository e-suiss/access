//! The approval ceiling by surface and who may approve an agent's request, on the real store
//! (E49, AGI-8, OP-154 m.3 (x)).

use access_kernel::aas::{EvidenceLevel, SurfaceClass};

use super::*;

/// ALICE's approval of `target` from a surface of `surface` reaching `evidence`, with the
/// statement's digest.
fn approved_on(
    d: Digest,
    nonce: u8,
    (target, render): (Digest, Digest),
    surface: Option<SurfaceClass>,
    evidence: Option<EvidenceLevel>,
) -> (Request, Digest) {
    let mut act = approval_act(d, nonce, target, render, NOW - 1_000, NOW + 60_000);
    act.surface_class = surface;
    act.evidence = evidence;
    let h = access_kernel::aas::digest(&act).unwrap();
    let r = with_proofs(
        contribute(d, nonce, target),
        vec![
            ProofRef::Aas(act.to_bytes().unwrap()),
            ProofRef::Claim(approval_claim(d, h, &PASSKEY_UV, NOW - 5_000)),
        ],
    );
    (r, h)
}

fn approve() -> RequirementTerm {
    term(
        ProofKind::Contribution,
        "approve",
        ProofBinding::IntentDigest,
    )
}

// E49, E47, OP-154 m.3 (x), Ek B 4370
#[tokio::test]
async fn a_voice_approval_of_an_irreversible_action_stays_a_required_action() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, gated(&[approve()])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let target = shop_request(d, 9, Mode::Commit, shop);
    let digest = access_kernel::intent::intent_digest(&target.intent).unwrap();
    let render = render_of(&target);
    let asked = send(&mut core, target.clone(), ROOT_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction);
    let floors = &asked.decision.unmet[0].term.assurance;
    assert_eq!(floors.get("surface"), Some(&2));
    assert_eq!(floors.get("phishing_resistant"), Some(&1));
    for (nonce, surface, evidence) in [
        (20, Some(SurfaceClass::Voice), Some(EvidenceLevel::Presence)),
        (
            21,
            Some(SurfaceClass::Watch),
            Some(EvidenceLevel::PhishingResistant),
        ),
        (
            22,
            Some(SurfaceClass::Phone),
            Some(EvidenceLevel::UserVerified),
        ),
        (23, None, None),
    ] {
        let (r, _) = approved_on(d, nonce, (digest, render), surface, evidence);
        let given = send(&mut core, r, ALICE_KEY).await.unwrap();
        allowed(&given);
        let again = send(
            &mut core,
            with_proofs(
                target.clone(),
                vec![ProofRef::Contribution(given.exercise.unwrap())],
            ),
            ROOT_KEY,
        )
        .await
        .unwrap();
        assert_eq!(
            again.decision.outcome,
            Outcome::RequireAction,
            "{surface:?} {evidence:?}"
        );
    }
    let (r, _) = approved_on(
        d,
        24,
        (digest, render),
        Some(SurfaceClass::Phone),
        Some(EvidenceLevel::PhishingResistant),
    );
    let given = send(&mut core, r, ALICE_KEY).await.unwrap();
    allowed(&given);
    let done = send(
        &mut core,
        with_proofs(
            target,
            vec![ProofRef::Contribution(given.exercise.unwrap())],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&done);
}

// E49 (4), OP-154 m.3 (x), Ek B 4371
#[tokio::test]
async fn the_first_valid_answer_on_a_nonce_wins() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, gated(&[approve()])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let target = shop_request(d, 9, Mode::Commit, shop);
    let digest = access_kernel::intent::intent_digest(&target.intent).unwrap();
    let render = render_of(&target);
    let asked = send(&mut core, target, ROOT_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction);
    let (phone, first) = approved_on(
        d,
        20,
        (digest, render),
        Some(SurfaceClass::Phone),
        Some(EvidenceLevel::PhishingResistant),
    );
    let (desktop, second) = approved_on(
        d,
        20,
        (digest, render),
        Some(SurfaceClass::Desktop),
        Some(EvidenceLevel::PhishingResistant),
    );
    assert_ne!(first, second);
    let won = send(&mut core, phone, ALICE_KEY).await.unwrap();
    allowed(&won);
    let exercise = won.exercise.unwrap();
    match send(&mut core, desktop, ALICE_KEY).await {
        Err(CoreError::Nonce) => {}
        Ok(r) => {
            assert!(r.replayed, "{r:?}");
            assert_eq!(r.exercise, Some(exercise));
        }
        Err(e) => panic!("{e:?}"),
    }
    let state = state_of(&db, d, &meta::exercise_key(kind::CONTRIBUTION, &exercise))
        .await
        .map(|b| {
            meta::ContributionState::from_value(&dcbor::decode(&b, Limits::CEILING).unwrap())
                .unwrap()
        })
        .unwrap();
    assert_eq!(state.statement, Some(first));
    assert_eq!(state.assurance.get("surface"), Some(&2));
}

// AGI-8, A-5, EI-18, OP-154 m.3 (x), Ek B 4550
#[tokio::test]
async fn an_agents_request_takes_no_contribution_from_an_agent() {
    for (contributor, outcome) in [
        (ActorKind::Human, Outcome::Allow),
        (ActorKind::Agent, Outcome::RequireAction),
    ] {
        let db = fresh().await.unwrap();
        let (mut core, d) = setup_with(&db, gated(&[approve()])).await;
        onboard_as(&mut core, d, (ROOT, ActorKind::Agent), ROOT_KEY, (1, 2)).await;
        onboard_as(&mut core, d, (ALICE, contributor), ALICE_KEY, (3, 4)).await;
        let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
        let target = shop_request(d, 9, Mode::Commit, shop);
        let digest = access_kernel::intent::intent_digest(&target.intent).unwrap();
        let render = render_of(&target);
        let asked = send(&mut core, target.clone(), ROOT_KEY).await.unwrap();
        assert_eq!(asked.decision.outcome, Outcome::RequireAction);
        let (r, _) = approved_on(
            d,
            20,
            (digest, render),
            Some(SurfaceClass::Phone),
            Some(EvidenceLevel::PhishingResistant),
        );
        let given = send(&mut core, r, ALICE_KEY).await.unwrap();
        allowed(&given);
        let again = send(
            &mut core,
            with_proofs(
                target,
                vec![ProofRef::Contribution(given.exercise.unwrap())],
            ),
            ROOT_KEY,
        )
        .await
        .unwrap();
        assert_eq!(again.decision.outcome, outcome, "{contributor:?}");
    }
}
