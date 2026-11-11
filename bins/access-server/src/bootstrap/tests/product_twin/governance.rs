//! Governance seams on the real server path (CI-13, SEC10, C26, TN-114, OP-157 m.3 (i), (t), (u)):
//! legal process and ownership-change Claims, delegated administration and quorum in the
//! coordinator twin. Lanes V4 and V8 fill it.

use access_authority_core::app::templates::legal::{self, Setup};
use access_authority_core::app::templates::transfer::{OWNERSHIP_CHANGED, OwnershipChanged};
use access_kernel::model::PurposeRef;

use super::*;

/// `actor`'s own meta-Exercise of `payload` on `basis`: whether it committed.
async fn committed(s: &Seam, actor: &Actor, basis: ExerciseBasis, payload: Payload) -> bool {
    let now = server_time(&s.w.db.app).await.unwrap();
    let validity = Window {
        from: now - 60_000,
        until: now + 600_000,
    };
    let intent = self_signed_intent(&payload, actor.party, validity).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let ais = Seam::ais(
        &actor.key,
        &Statement {
            domain: s.domain,
            nonce: nonce.clone(),
            intent: intent_digest(&intent).unwrap(),
            mode: Mode::Commit,
            pep: String::from(IDENTITY_PEP),
            capacity: Capacity::Own,
            basis,
            iat: now,
            exercise: None,
        },
    );
    MetaExercises::lead(&s.w.plane, s.domain).await.unwrap();
    let verdict = Box::pin(MetaExercises::meta(
        &s.w.plane,
        Request {
            domain: s.domain,
            mode: Mode::Commit,
            nonce,
            intent,
            payload: Some(payload),
            basis,
            capacity: Capacity::Own,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        },
        ais,
        String::from(IDENTITY_PEP),
    ))
    .await;
    schedule(&s.signer);
    matches!(verdict, Ok(Verdict::Committed(_)))
}

fn hold(action: &ActionRef, account: &str, purpose: Option<&str>) -> IntentEnvelope {
    let mut e = envelope(
        action.clone(),
        ("pay.instrument", &[account]),
        BTreeMap::from([(
            String::from("amount"),
            ParamValue::Amount {
                value: 30_000,
                unit: String::from("try"),
            },
        )]),
    );
    e.purpose = purpose.map(|p| PurposeRef::Code(String::from(p)));
    e
}

// CI-13, SI-22, §6.1, §7.9.9.2, §7.9.12.7, OP-157 m.3 (i), OP-153 m.3 (gg), Ek B 5540, 5668, 5669
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::too_many_lines,
    reason = "one court order and one ownership change through the seam"
)]
async fn a_twins_court_order_and_ownership_change_act_only_through_the_grants_written_before() {
    let s = Seam::open("seam-legal", "pay").await;
    let pay = schema("pay");
    s.twin.publish_schema(&s.domain, &pay).await.unwrap();
    s.accept_schema(&pay).await;
    let acceptance = Value::Map(vec![
        (Value::text("issuer"), s.party.to_value()),
        (Value::text("use"), Value::text("predicate-input")),
        (
            Value::text("classes"),
            Value::Array(vec![
                Value::text(legal::COURT_ORDER),
                Value::text(OWNERSHIP_CHANGED),
            ]),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ]);
    s.root(Payload::AcceptanceEstablish(acceptance.clone()))
        .await;
    let legal_ops = s.actor().await;
    let action = pay.action("hold_create").unwrap();
    let content = Setup {
        basis: GrantBasis::Anchor(meta::meta_anchor(&s.domain)),
        holder: legal_ops.party,
        actions: BTreeSet::from([action.clone()]),
        resource: structural("pay.instrument", &[]),
        validity: Window {
            from: 0,
            until: u64::MAX,
        },
        approvals: 2,
        approvers: None,
        acceptance: access_kernel::claim::acceptance_digest(&acceptance),
    }
    .grant()
    .unwrap();
    let (exercise, since) = s.root(Payload::GrantIssue(content)).await;
    let basis = holding(
        meta::object_id(&exercise, kind::GRANT, 0),
        legal_ops.party,
        since,
    );

    // CI-13
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &legal_ops,
                hold(&action, "acct-1", Some(legal::PURPOSE)),
                basis,
                Vec::new(),
            ),
        )
        .await;
    assert!(matches!(r, Err(Denied::Refused(Refusal::Deny))), "{r:?}");

    let order = legal::body(
        &Digest(access_crypto::random::bytes::<32>().unwrap()),
        "TR",
        &BTreeSet::from([String::from("pay:hold_create")]),
        u64::MAX,
    );
    let issued = s
        .twin
        .issue_claim(
            &s.domain,
            Issue {
                subject: legal_ops.party,
                class: String::from(legal::COURT_ORDER),
                value: Some(EqValue::Bytes(legal::value_digest(&order).to_vec())),
                for_ms: 3_600_000,
                resource: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(issued.disposition, "admit");
    schedule(&s.signer);

    // §7.9.12.7
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &legal_ops,
                hold(&action, "acct-1", Some(legal::PURPOSE)),
                basis,
                Vec::new(),
            ),
        )
        .await;
    assert!(
        matches!(r, Err(Denied::Refused(Refusal::RequireAction))),
        "the order holds the Grant and its two approvals still stand: {r:?}"
    );
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &legal_ops,
                hold(&action, "acct-1", Some(legal::PURPOSE)),
                ExerciseBasis::Anchor(legal_ops.anchor),
                Vec::new(),
            ),
        )
        .await;
    assert!(matches!(r, Err(Denied::Refused(Refusal::Deny))), "{r:?}");
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(&legal_ops, hold(&action, "acct-1", None), basis, Vec::new()),
        )
        .await;
    assert!(r.is_err(), "{r:?}");

    // §7.9.9.2
    let owner = s.actor().await;
    let buyer = s.actor().await;
    let change = OwnershipChanged {
        anchor: owner.anchor,
        from: owner.party,
        to: buyer.party,
        effective_at: now_ms() - 1_000,
    };
    let issued = s
        .twin
        .issue_claim(
            &s.domain,
            Issue {
                subject: buyer.party,
                class: String::from(OWNERSHIP_CHANGED),
                value: Some(EqValue::Bytes(change.value_digest().to_vec())),
                for_ms: 3_600_000,
                resource: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(issued.disposition, "admit");
    schedule(&s.signer);
    let transfer = Payload::AnchorTransfer {
        anchor: owner.anchor,
        root: Root::Sole(buyer.party),
        disposition: BTreeMap::new(),
    };
    assert!(
        !committed(
            &s,
            &buyer,
            ExerciseBasis::Anchor(owner.anchor),
            transfer.clone()
        )
        .await,
        "an ownership change moves no root"
    );
    assert!(
        !committed(
            &s,
            &legal_ops,
            ExerciseBasis::Anchor(owner.anchor),
            transfer
        )
        .await,
        "nor does a Party that is not the root"
    );
    s.only_public();
}
