//! A Party restricting its own self-anchor on the real store (OP-157 m.11 (e), OP-158 m.3 (b),
//! TN-71 #8, L0-META-27a): the root of a self-anchor sets a narrowing policy on it with no
//! meta-anchor power, and only a narrowing one.

use super::*;

fn hex(id: &Id) -> String {
    use std::fmt::Write as _;
    id.0.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn own_selector(party: &Id) -> ResourceSelector {
    ResourceSelector::Structural(Structural {
        namespace: "access.party".to_owned(),
        prefix: vec![hex(party)],
        kind: None,
        attrs: BTreeMap::new(),
    })
}

fn on(target: Value, source: &str) -> Value {
    Value::Map(vec![
        (Value::text("schema"), Value::text(meta::RESTRICTION_SCHEMA)),
        (Value::text("source"), Value::text(source)),
        (Value::text("target"), target),
    ])
}

fn policy(basis: ExerciseBasis, content: Value, d: Digest, nonce: u8) -> Request {
    meta_request(
        d,
        nonce,
        basis,
        Payload::PolicySet {
            policy: None,
            content,
            defaults: None,
        },
    )
}

fn read_own(d: Digest, nonce: u8, basis: ExerciseBasis) -> Request {
    let mut r = shop_request(d, nonce, Mode::Commit, basis);
    r.intent.resources = vec![ResourceRef {
        namespace: "access.party".to_owned(),
        path: vec![hex(&ALICE)],
        incarnation: 0,
    }];
    r
}

// OP-157 m.11 (e), OP-158 m.3 (b), TN-71, L0-META-27a, Ek B 5515
#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scripted run")]
async fn a_party_restricts_its_own_self_anchor_and_only_narrows_it() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let registered = send(
        &mut core,
        meta_request(
            d,
            3,
            public_basis,
            Payload::PartyRegister {
                party: ALICE,
                root: Root::Sole(ALICE),
                actor_kind: ActorKind::Human,
            },
        ),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&registered);
    allowed(
        &send(
            &mut core,
            meta_request(
                d,
                4,
                public_basis,
                Payload::InstanceCreate {
                    party: ALICE,
                    key: public(ALICE_KEY),
                    mandate: None,
                },
            ),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    onboard(&mut core, d, BOB, BOB_KEY, (5, 6)).await;
    let own = meta::object_id(&registered.exercise.unwrap(), kind::ANCHOR, 0);
    let mine = ExerciseBasis::Anchor(own);

    let issued = send(
        &mut core,
        meta_request(
            d,
            10,
            mine,
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(own),
                holder: SubjectSelector::Party(BOB),
                authority: authority(vec![action("shop", "read")], own_selector(&ALICE)),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        ),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&issued);
    let holding = ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
        holder: BOB,
        since: issued.record.unwrap(),
    });
    allowed(
        &send(&mut core, read_own(d, 11, holding), BOB_KEY)
            .await
            .unwrap(),
    );

    let target = Value::Map(vec![(Value::text("anchor"), own.to_value())]);
    let permit = send(
        &mut core,
        policy(
            mine,
            on(
                target.clone(),
                r#"@id("open") permit(principal, action, resource);"#,
            ),
            d,
            12,
        ),
        ALICE_KEY,
    )
    .await;
    assert!(
        permit
            .as_ref()
            .is_err_and(|e| matches!(e, CoreError::Protocol("policy")))
            || permit.as_ref().unwrap().decision.outcome == Outcome::Deny,
        "{permit:?}"
    );
    let domain_wide = send(
        &mut core,
        policy(
            mine,
            on(
                Value::text("domain"),
                r#"@id("mine") forbid(principal, action, resource);"#,
            ),
            d,
            13,
        ),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(
        domain_wide.decision.outcome,
        Outcome::Deny,
        "{domain_wide:?}"
    );
    let not_root = send(
        &mut core,
        policy(
            mine,
            on(
                target.clone(),
                r#"@id("mine") forbid(principal, action, resource);"#,
            ),
            d,
            14,
        ),
        BOB_KEY,
    )
    .await
    .unwrap();
    assert_eq!(not_root.decision.outcome, Outcome::Deny, "{not_root:?}");

    let restricted = send(
        &mut core,
        policy(
            mine,
            on(
                target.clone(),
                r#"@id("mine") forbid(principal, action, resource);"#,
            ),
            d,
            15,
        ),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&restricted);
    let p = meta::object_id(&restricted.exercise.unwrap(), kind::POLICY, 0);
    let swapped = send(
        &mut core,
        meta_request(
            d,
            17,
            mine,
            Payload::PolicySet {
                policy: Some(p),
                content: on(
                    target.clone(),
                    r#"@id("other") forbid(principal, action, resource) when { context.tier > 2 };"#,
                ),
                defaults: None,
            },
        ),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(swapped.decision.outcome, Outcome::Deny, "{swapped:?}");
    let after = send(&mut core, read_own(d, 16, holding), BOB_KEY)
        .await
        .unwrap();
    assert_eq!(after.decision.outcome, Outcome::Deny, "{after:?}");
    assert_eq!(after.decision.blockers[0].class, BlockerClass::Restricted);

    fold_check(&db.sequencer, d).await.unwrap();
}
