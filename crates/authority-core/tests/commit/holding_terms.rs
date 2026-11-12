//! Holding terms on meta-actions on the real store (L0-META-13, OP-157 m.22 (f), OP-159
//! m.3 (k)): a holding-based meta-Exercise meets the terms of the holding it declares.

use access_authority_core::restrict::patterns;

use super::*;

fn delegable() -> CanonicalAuthority {
    let mut a = authority(vec![action("shop", "read")], selector("shop"));
    a.delegation.depth = 1;
    a
}

fn issue(basis: GrantBasis, holder: Id, authority: CanonicalAuthority) -> Payload {
    Payload::GrantIssue(GrantContent {
        basis,
        holder: SubjectSelector::Party(holder),
        authority,
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    })
}

fn amend(grant: Id, authority: CanonicalAuthority) -> Payload {
    Payload::GrantAmend {
        grant,
        authority,
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    }
}

fn subcode(r: &Response) -> Option<&str> {
    r.decision
        .blockers
        .first()
        .and_then(|b| b.subcode.as_deref())
}

// L0-META-13, OP-157 m.22 (f), OP-159 m.3 (k)
#[tokio::test]
async fn a_holding_based_grant_amend_meets_the_holding_terms() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let first = send(
        &mut core,
        meta_request(
            d,
            10,
            ExerciseBasis::Anchor(shop),
            issue(GrantBasis::Anchor(shop), ALICE, delegable()),
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&first);
    let g1 = meta::object_id(&first.exercise.unwrap(), kind::GRANT, 0);
    let h1 = HoldingRef {
        grant: g1,
        holder: ALICE,
        since: first.record.unwrap(),
    };
    let mut child = authority(vec![action("shop", "read")], selector("shop"));
    child.delegation.depth = 0;
    let second = send(
        &mut core,
        meta_request(
            d,
            11,
            ExerciseBasis::Holding(h1),
            issue(GrantBasis::Holding(h1), BOB, child.clone()),
        ),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&second);
    let g2 = meta::object_id(&second.exercise.unwrap(), kind::GRANT, 0);
    let mut termed = delegable();
    termed.requirements.insert(patterns::contribution(
        "approve",
        Some(SubjectSelector::Party(ROOT)),
    ));
    allowed(
        &send(
            &mut core,
            meta_request(d, 12, ExerciseBasis::Anchor(shop), amend(g1, termed)),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let mut narrower = child;
    narrower.requirements.insert(patterns::contribution(
        "approve",
        Some(SubjectSelector::Party(ROOT)),
    ));
    narrower.authority.resource = ResourceSelector::Structural(Structural {
        namespace: "shop".to_owned(),
        prefix: vec!["item-1".to_owned()],
        kind: None,
        attrs: BTreeMap::new(),
    });
    let refused = send(
        &mut core,
        meta_request(
            d,
            13,
            ExerciseBasis::Holding(h1),
            amend(g2, narrower.clone()),
        ),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(refused.decision.outcome, Outcome::Deny);
    assert_eq!(subcode(&refused), Some("holding-terms"));
    assert!(refused.exercise.is_none());
    allowed(
        &send(
            &mut core,
            meta_request(d, 14, ExerciseBasis::Anchor(shop), amend(g2, narrower)),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    fold_check(&db.sequencer, d).await.unwrap();
}
