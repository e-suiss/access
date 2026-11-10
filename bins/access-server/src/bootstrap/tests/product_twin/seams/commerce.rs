//! The Commerce seam (§7.9.10.1, §7.9.10.5, INV-16, OP-156 m.3 (b), (u)): the merchant is the
//! root of its own namespace Anchor and grants refund and admin authority from it; Commerce
//! keeps the order and its refund rule and says whether an order is refundable with its
//! `order_refundable` predicate, and who works for the merchant with its `seller_member` Claim.
//! Access consumes the predicate and never recomputes it; the membership only selects a
//! rule-shaped Grant the merchant made.

use access_kernel::claim::{PREDICATE_INPUT, SUBJECT_SELECTION};

use super::*;

/// The `order_refundable` requirement: Commerce's predicate about the very order, fresh.
fn refundable(commerce: Id) -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Claim,
        class: String::from("order_refundable"),
        count: 1,
        binding: Binding::Resource,
        freshness_ms: Some(600_000),
        independence: Independence::None,
        consumption: Consumption::Reusable,
        source: Some(SubjectSelector::Party(commerce)),
        assurance: BTreeMap::new(),
    }
}

fn order(id: &str) -> ResourceRef {
    ResourceRef {
        namespace: String::from("commerce.merchant"),
        path: vec![
            String::from("m-1"),
            String::from("orders"),
            String::from(id),
        ],
        incarnation: 0,
    }
}

/// Commerce's `order_refundable` Claim about `id`, bound to the order.
async fn order_refundable(p: &Product, subject: Id, id: &str) -> Id {
    let body = seam_body(
        "order_refundable",
        &Value::Map(vec![
            (Value::text("order"), Value::text(id)),
            (Value::text("refundable"), Value::Bool(true)),
        ]),
    );
    let mut claim = signed(subject, "order_refundable", body, 600_000);
    claim.issue.resource = Some(order(id));
    let issued = p.s.twin.issue_signed(&p.s.domain, claim).await.unwrap();
    assert_eq!(issued.disposition, "admit", "{issued:?}");
    schedule(&p.s.signer);
    issued.claim
}

/// Commerce's `seller_member` Claim: `subject` works for the merchant as `role`.
async fn member(p: &Product, subject: Id, role: &str) -> u64 {
    let issued =
        p.s.twin
            .issue_claim(
                &p.s.domain,
                Issue {
                    subject,
                    class: String::from("seller_member"),
                    value: Some(EqValue::Text(String::from(role))),
                    for_ms: 3_600_000,
                    resource: None,
                },
            )
            .await
            .unwrap();
    assert_eq!(issued.disposition, "admit", "{issued:?}");
    schedule(&p.s.signer);
    issued.position.unwrap()
}

// §7.9.10.1, §7.9.10.5, §2.6, INV-16, OP-156 m.3 (u), Ek B 5267
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "one merchant's refund, staff and admin authority with Commerce's predicate"
)]
async fn commerce_refunds_only_a_refundable_order_and_never_decides_it() {
    let p = Product::open("q17-commerce", "commerce").await;
    p.s.accept_claims(PREDICATE_INPUT, &["order_refundable"])
        .await;
    p.s.accept_claims(SUBJECT_SELECTION, &["seller_member"])
        .await;
    let merchant = p.s.actor().await;
    let alice = p.s.actor().await;
    let bob = p.s.actor().await;
    let carol = p.s.actor().await;
    let refund = p.action("refund");
    let update = p.action("policy_update");

    // §7.9.10.1
    let (created, _) =
        p.s.root(Payload::AnchorCreate {
            scope: meta::AnchorScope::Resource(structural("commerce.merchant", &["m-1"])),
            root: Root::Sole(merchant.party),
            root_terms: BTreeSet::new(),
        })
        .await;
    let anchor = meta::object_id(&created, kind::ANCHOR, 0);
    let from_merchant = async |holder: SubjectSelector, authority: CanonicalAuthority| {
        let (e, since) =
            p.s.own_commit(
                &merchant,
                ExerciseBasis::Anchor(anchor),
                Payload::GrantIssue(GrantContent {
                    basis: GrantBasis::Anchor(anchor),
                    holder,
                    authority,
                    agency: BTreeSet::from([Capacity::Own]),
                    named: None,
                }),
            )
            .await;
        (meta::object_id(&e, kind::GRANT, 0), since)
    };
    let refunds = || {
        canonical(
            std::slice::from_ref(&refund),
            structural("commerce.merchant", &["m-1", "orders"]),
            at_most(50_000),
            BTreeSet::new(),
            BTreeSet::from([refundable(p.s.party)]),
        )
    };
    let refund_of = |id: &str, kurus| {
        envelope(
            refund.clone(),
            ("commerce.merchant", &["m-1", "orders", id]),
            amount(kurus),
        )
    };

    // §2.6
    let (alice_grant, since) = from_merchant(SubjectSelector::Party(alice.party), refunds()).await;
    let alice_basis = holding(alice_grant, alice.party, since);
    let r =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(&alice, refund_of("o-1", 30_000), alice_basis, Vec::new()),
            )
            .await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");
    let o1 = order_refundable(&p, alice.party, "o-1").await;
    let intent = refund_of("o-1", 30_000);
    let allowed =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(
                    &alice,
                    intent.clone(),
                    alice_basis,
                    vec![Proof::Recorded(o1)],
                ),
            )
            .await
            .unwrap();
    let mut refunded = Vec::new();
    ProductTwin::enforce(allowed, &intent, || refunded.push("o-1")).unwrap();
    let over =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(
                    &alice,
                    refund_of("o-1", 60_000),
                    alice_basis,
                    vec![Proof::Recorded(o1)],
                ),
            )
            .await;
    assert!(
        matches!(over, Err(Denied::Refused(Refusal::Deny))),
        "{over:?}"
    );
    let r =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(
                    &alice,
                    refund_of("o-2", 10_000),
                    alice_basis,
                    vec![Proof::Recorded(o1)],
                ),
            )
            .await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");

    // INV-16
    let (staff_grant, _) = from_merchant(
        pred("seller_member", EqValue::Text(String::from("m-1"))),
        refunds(),
    )
    .await;
    let bob_since = member(&p, bob.party, "m-1").await;
    let o3 = order_refundable(&p, bob.party, "o-3").await;
    let intent = refund_of("o-3", 10_000);
    let allowed =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(
                    &bob,
                    intent.clone(),
                    holding(staff_grant, bob.party, bob_since),
                    vec![Proof::Recorded(o3)],
                ),
            )
            .await
            .unwrap();
    ProductTwin::enforce(allowed, &intent, || refunded.push("o-3")).unwrap();
    let r =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(
                    &carol,
                    refund_of("o-3", 10_000),
                    holding(staff_grant, carol.party, bob_since),
                    vec![Proof::Recorded(o3)],
                ),
            )
            .await;
    assert!(matches!(r, Err(Denied::Refused(Refusal::Deny))), "{r:?}");
    assert_eq!(refunded, ["o-1", "o-3"]);

    // §7.9.10.1
    let (admin_grant, _) = from_merchant(
        pred("seller_member", EqValue::Text(String::from("m-1:admin"))),
        canonical(
            std::slice::from_ref(&update),
            structural("commerce.merchant", &["m-1"]),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        ),
    )
    .await;
    let admin_since = member(&p, alice.party, "m-1:admin").await;
    let settings = || {
        envelope(
            update.clone(),
            ("commerce.merchant", &["m-1", "settings"]),
            BTreeMap::new(),
        )
    };
    let mut refund_window_days = 14;
    let change = settings();
    let allowed =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(
                    &alice,
                    change.clone(),
                    holding(admin_grant, alice.party, admin_since),
                    Vec::new(),
                ),
            )
            .await
            .unwrap();
    assert_ne!(*allowed.exercise(), Digest([0; 32]));
    ProductTwin::enforce(allowed, &change, || refund_window_days = 30).unwrap();
    assert_eq!(refund_window_days, 30);
    let r =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(
                    &bob,
                    settings(),
                    holding(admin_grant, bob.party, bob_since),
                    Vec::new(),
                ),
            )
            .await;
    assert!(matches!(r, Err(Denied::Refused(Refusal::Deny))), "{r:?}");
    p.s.only_public();
}
