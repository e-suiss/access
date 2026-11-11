//! Separation of duties on the real store (§2.4, §5.9, §13.7.3, SEC10, OP-157 m.3 (u)): where a
//! domain declares SoD, the requester's own contribution does not count; where it does not, the
//! actor's own suffices.

use access_authority_core::app::delegated;
use access_authority_core::app::templates::sod;

use super::*;

/// Genesis where acting on `shop` needs `term`, and ROOT and ALICE both hold the Grant to
/// contribute `approve`; also returns the Grant index of each.
fn genesis_with(term: RequirementTerm) -> (BTreeMap<String, Opened>, u64, u64) {
    let mut g = gated(&[term]);
    let Some(Value::Array(mut grants)) = g.get("grants").map(|o| o.value.clone()) else {
        panic!("genesis has grants");
    };
    let Value::Map(mut root) = grants.get(1).unwrap().clone() else {
        panic!("a grant is a map");
    };
    for (k, v) in &mut root {
        if *k == Value::text("holder") {
            *v = SubjectSelector::Party(ROOT).to_value();
        }
    }
    grants.push(Value::Map(root));
    grants.sort_by_key(|v| dcbor::encode(v, Limits::CEILING).unwrap());
    let index = |party: Id| {
        let holder = SubjectSelector::Party(party).to_value();
        let found = grants
            .iter()
            .position(|v| v.get("holder") == Some(&holder))
            .unwrap();
        u64::try_from(found).unwrap()
    };
    let (root_index, alice_index) = (index(ROOT), index(ALICE));
    g.insert(
        "grants".to_owned(),
        Opened {
            value: Value::Array(grants),
            salt: [3; 32],
        },
    );
    (g, root_index, alice_index)
}

#[derive(Clone, Copy)]
enum Contributor {
    Requester,
    Other,
}

/// Whether the shop action commits with the contribution `by` makes.
async fn shop_with_contribution_by(term: RequirementTerm, by: Contributor) -> Outcome {
    let db = fresh().await.unwrap();
    let (g, root_index, alice_index) = genesis_with(term);
    let (mut core, d) = setup_with(&db, g).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let target = shop_request(d, 9, Mode::Commit, shop);
    let digest = access_kernel::intent::intent_digest(&target.intent).unwrap();
    let render = render_of(&target);
    let asked = send(&mut core, target.clone(), ROOT_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction, "{asked:?}");

    let (party, grant, instance, nonce, seed) = match by {
        Contributor::Requester => (ROOT, root_index, 2, 20, ROOT_KEY),
        Contributor::Other => (ALICE, alice_index, 4, 21, ALICE_KEY),
    };
    let given = send(
        &mut core,
        approval_by(d, (party, grant, instance), nonce, digest, render),
        seed,
    )
    .await
    .unwrap();
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
    done.decision.outcome
}

// SEC10, §2.4, §5.9, §13.7.3, OP-157 m.3 (b), (u), Ek B 5556
#[tokio::test]
async fn where_the_domain_declares_sod_the_requesters_own_contribution_does_not_count() {
    let term = sod::approve_term("approve", 1);
    assert_eq!(
        shop_with_contribution_by(term.clone(), Contributor::Requester).await,
        Outcome::RequireAction
    );
    assert_eq!(
        shop_with_contribution_by(term, Contributor::Other).await,
        Outcome::Allow
    );
}

// SEC10, §13.7.3, OP-157 m.3 (u), Ek B 5556
#[tokio::test]
async fn without_sod_the_actors_own_contribution_is_enough() {
    let term = term(
        ProofKind::Contribution,
        "approve",
        ProofBinding::IntentDigest,
    );
    assert_eq!(
        shop_with_contribution_by(term, Contributor::Requester).await,
        Outcome::Allow
    );
}

// TN-114, OP-157 m.3 (t), Ek B 5492, 5592
#[tokio::test]
async fn a_new_admin_grant_is_denied_with_the_flag_closed() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, gated(&[])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let authority = authority(
        vec![action("access", "grant_revoke")],
        selector("access.grant"),
    );
    let payload = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(meta::meta_anchor(&d)),
        holder: SubjectSelector::Party(ALICE),
        authority,
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    });
    let basis = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    let mut issue = meta_request(d, 5, basis, payload);
    issue.intent.resources = vec![ResourceRef {
        namespace: "access.domain".to_owned(),
        path: vec!["shop".to_owned()],
        incarnation: 0,
    }];
    let p = issue.payload.clone().unwrap();
    issue.intent.opaque = BTreeMap::from([("payload".to_owned(), p.digest().unwrap())]);
    let refused = send(&mut core, issue, ROOT_KEY).await.unwrap();
    assert_eq!(refused.decision.outcome, Outcome::Deny, "{refused:?}");
    assert_eq!(
        refused.decision.blockers[0].subcode.as_deref(),
        Some(delegated::OFF)
    );
}
