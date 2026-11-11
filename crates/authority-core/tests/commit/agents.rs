//! The approval ceiling by surface and who may approve an agent's request, on the real store
//! (E49, AGI-8, OP-154 m.3 (x)).

use access_authority_core::restrict::patterns::{self, Pattern};
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

fn set_pattern(d: Digest, nonce: u8, p: &Pattern) -> Request {
    meta_request(
        d,
        nonce,
        ExerciseBasis::Anchor(meta::meta_anchor(&d)),
        Payload::PolicySet {
            defaults: None,
            policy: None,
            content: patterns::content(p).unwrap(),
        },
    )
}

fn with_amount(mut r: Request, provenance: Option<access_kernel::intent::Provenance>) -> Request {
    r.intent.params.insert(
        "amount".to_owned(),
        access_kernel::intent::ParamValue::Amount {
            value: 4200,
            unit: "eur_cent".to_owned(),
        },
    );
    if let Some(p) = provenance {
        r.intent.provenance.insert("amount".to_owned(), p);
    }
    r
}

// E54 (1), §13.7.6, OP-142, Ek B 4641
#[tokio::test]
async fn an_untrusted_amount_needs_an_approval_once_the_domain_opts_in() {
    use access_kernel::intent::Provenance;
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, gated(&[])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let before = send(
        &mut core,
        with_amount(shop_request(d, 9, Mode::Commit, shop), None),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&before);
    let p = Pattern::Untrusted {
        params: BTreeSet::from(["amount".to_owned(), "recipient".to_owned()]),
        approval: patterns::contribution("approve", None),
    };
    allowed(
        &send(&mut core, set_pattern(d, 10, &p), ROOT_KEY)
            .await
            .unwrap(),
    );
    for (nonce, label) in [(11, None), (12, Some(Provenance::UntrustedExternal))] {
        let asked = send(
            &mut core,
            with_amount(shop_request(d, nonce, Mode::Commit, shop), label),
            ROOT_KEY,
        )
        .await
        .unwrap();
        assert_eq!(asked.decision.outcome, Outcome::RequireAction, "{label:?}");
        assert_eq!(asked.decision.unmet[0].term.class, "approve");
        assert_eq!(
            asked.decision.unmet[0].term.assurance.get("surface"),
            Some(&2)
        );
    }
    for (nonce, label) in [(13, Provenance::User), (14, Provenance::Trusted)] {
        let typed = send(
            &mut core,
            with_amount(shop_request(d, nonce, Mode::Commit, shop), Some(label)),
            ROOT_KEY,
        )
        .await
        .unwrap();
        allowed(&typed);
    }
    let plain = send(&mut core, shop_request(d, 15, Mode::Commit, shop), ROOT_KEY)
        .await
        .unwrap();
    allowed(&plain);
}

// §11.19 row, Ek B 4464
#[tokio::test]
async fn an_enterprise_agents_high_consequence_action_waits_for_an_administrator() {
    for (kind, outcome) in [
        (ActorKind::Human, Outcome::Allow),
        (ActorKind::Agent, Outcome::RequireAction),
    ] {
        let db = fresh().await.unwrap();
        let (mut core, d) = setup_with(&db, gated(&[])).await;
        onboard_as(&mut core, d, (ROOT, kind), ROOT_KEY, (1, 2)).await;
        onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
        let admins = SubjectSelector::Party(ALICE);
        let p = Pattern::AdminApproval {
            min_tier: 1,
            approvers: admins.clone(),
        };
        let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
        let low = Pattern::AdminApproval {
            min_tier: 2,
            approvers: admins.clone(),
        };
        allowed(
            &send(&mut core, set_pattern(d, 10, &low), ROOT_KEY)
                .await
                .unwrap(),
        );
        allowed(
            &send(&mut core, shop_request(d, 11, Mode::Commit, shop), ROOT_KEY)
                .await
                .unwrap(),
        );
        allowed(
            &send(&mut core, set_pattern(d, 12, &p), ROOT_KEY)
                .await
                .unwrap(),
        );
        let target = shop_request(d, 13, Mode::Commit, shop);
        let asked = send(&mut core, target.clone(), ROOT_KEY).await.unwrap();
        assert_eq!(asked.decision.outcome, outcome, "{kind:?}");
        if outcome == Outcome::Allow {
            continue;
        }
        let term = &asked.decision.unmet[0].term;
        assert_eq!(term.class, "approve");
        assert_eq!(term.source, Some(admins));
        let digest = access_kernel::intent::intent_digest(&target.intent).unwrap();
        let (r, _) = approved_on(
            d,
            20,
            (digest, render_of(&target)),
            Some(SurfaceClass::Desktop),
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
}

// F11, SEC30, §7.9.10.3, Ek B 4642
#[tokio::test]
async fn disclosure_needs_the_data_owners_contribution_and_declassify_is_ct3() {
    use access_kernel::tier::Tier;
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, gated(&[])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let owner = SubjectSelector::Party(ALICE);
    let p = Pattern::Disclosure {
        actions: BTreeSet::from(["shop:read".to_owned()]),
        owner: owner.clone(),
        declassify: false,
    };
    allowed(
        &send(&mut core, set_pattern(d, 10, &p), ROOT_KEY)
            .await
            .unwrap(),
    );
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let asked = send(&mut core, shop_request(d, 11, Mode::Commit, shop), ROOT_KEY)
        .await
        .unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction);
    let term = &asked.decision.unmet[0].term;
    assert_eq!(term.class, access_kernel::contribution::DISCLOSE);
    assert_eq!(term.source, Some(owner));
    let target = access_kernel::digest::Digest([7; 32]);
    let tier = |class: &str| {
        let payload = Payload::Contribute {
            target,
            class: class.to_owned(),
        };
        access_authority_core::requirements::tier_of(
            &contribute(d, 30, target).intent,
            Some(&payload),
            false,
            None,
        )
    };
    assert_eq!(tier(access_kernel::contribution::DISCLOSE), Tier::Ct2);
    assert_eq!(tier(access_kernel::contribution::DECLASSIFY), Tier::Ct3);
    assert!(tier(access_kernel::contribution::APPROVE) < Tier::Ct2);
}
