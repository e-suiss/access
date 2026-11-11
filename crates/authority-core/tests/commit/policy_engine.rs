//! The policy engine on the real store (OP-157 m.3 (n), (o), (q)): `policy.set` polarity by
//! structure and by the control-plane analysis, the `derived.*` values the restriction context
//! reads and cites, and the structuring guards.

use access_authority_core::ports::{Comparing, PolicyAnalysis, PolicyRelation};
use access_authority_core::restrict::patterns::{self, Pattern};
use access_kernel::intent::ParamValue;
use access_kernel::record::RecordEnvelope;

use super::*;

const NARROW: &str = r#"@id("no-reads") forbid(principal, action, resource) when { context.action == "shop:read" };"#;
const NARROWER: &str = r#"@id("no-reads") forbid(principal, action, resource) when { context.action == "shop:read" };
@id("no-agents") forbid(principal, action, resource) when { context.actor == "agent" };"#;

struct Answers(PolicyRelation);

impl PolicyAnalysis for Answers {
    fn compare<'a>(&'a self, schema: &'a str, old: &'a str, new: &'a str) -> Comparing<'a> {
        let _ = (schema, old, new);
        Box::pin(std::future::ready(self.0))
    }
}

async fn tier_of(db: &TestDb, d: Digest, nonce: u8) -> Option<u8> {
    access_store::authority::find_nonce(&db.app, &DomainId::from_bytes(d.0), &[nonce; 16])
        .await
        .unwrap()
        .and_then(|n| n.tier)
}

async fn state_basis(db: &TestDb, d: Digest, record: u64) -> Value {
    let log =
        access_store::authority::read_log(&db.app, &DomainId::from_bytes(d.0), record, record)
            .await
            .unwrap();
    let envelope = RecordEnvelope::from_bytes(&log.first().unwrap().envelope).unwrap();
    envelope.fields.get("state_basis").unwrap().value.clone()
}

fn retire_free(d: Digest, nonce: u8, policy: Id, source: &str) -> Request {
    policy_set(d, nonce, Some(policy), source, None)
}

/// A domain with one restriction policy that forbids nothing ROOT does, and its id.
async fn with_policy(db: &TestDb, analysis: PolicyRelation, wired: bool) -> (Core, Digest, Id) {
    let (core, d) = setup_with(db, gated(&[])).await;
    let mut core = if wired {
        core.with_analysis(std::sync::Arc::new(Answers(analysis)))
    } else {
        core
    };
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let set = send(&mut core, policy_set(d, 10, None, NARROW, None), ROOT_KEY)
        .await
        .unwrap();
    allowed(&set);
    (
        core,
        d,
        meta::object_id(&set.exercise.unwrap(), kind::POLICY, 0),
    )
}

// SI-18, INV-36, T13, OP-157 m.3 (b), Ek B 5660
#[tokio::test]
async fn adding_a_forbid_is_ct1_and_removing_one_is_ct3() {
    let db = fresh().await.unwrap();
    let (mut core, d, policy) = with_policy(&db, PolicyRelation::Unknown, false).await;
    allowed(
        &send(&mut core, retire_free(d, 11, policy, NARROWER), ROOT_KEY)
            .await
            .unwrap(),
    );
    assert_eq!(tier_of(&db, d, 11).await, Some(1));
    allowed(
        &send(&mut core, retire_free(d, 12, policy, NARROW), ROOT_KEY)
            .await
            .unwrap(),
    );
    assert_eq!(tier_of(&db, d, 12).await, Some(3));
    let looser = NARROW.replace("shop:read", "shop:write");
    allowed(
        &send(&mut core, retire_free(d, 13, policy, &looser), ROOT_KEY)
            .await
            .unwrap(),
    );
    assert_eq!(tier_of(&db, d, 13).await, Some(3));
    fold_check(&db.sequencer, d).await.unwrap();
}

// OP-157 m.3 (n), OP-105, Ek B 5660
#[tokio::test]
async fn the_analysis_only_raises_a_structural_narrowing() {
    for (relation, wired, tier) in [
        (PolicyRelation::Narrowing, true, 1),
        (PolicyRelation::Equivalent, true, 1),
        (PolicyRelation::Widening, true, 3),
        (PolicyRelation::Incomparable, true, 3),
        (PolicyRelation::MayError, true, 3),
        (PolicyRelation::Unknown, true, 3),
        (PolicyRelation::Unknown, false, 1),
    ] {
        let db = fresh().await.unwrap();
        let (mut core, d, policy) = with_policy(&db, relation, wired).await;
        let r = send(&mut core, retire_free(d, 11, policy, NARROWER), ROOT_KEY)
            .await
            .unwrap();
        allowed(&r);
        assert_eq!(
            tier_of(&db, d, 11).await,
            Some(tier),
            "{relation:?} {wired}"
        );
        let basis = state_basis(&db, d, r.record.unwrap()).await;
        assert_eq!(
            basis.get("policy_relation").is_some(),
            tier == 3,
            "{relation:?}"
        );
        if tier == 3 {
            assert_eq!(
                basis.get("policy_relation"),
                Some(&Value::text(relation.word()))
            );
        }
    }
    let db = fresh().await.unwrap();
    let (mut core, d, policy) = with_policy(&db, PolicyRelation::Narrowing, true).await;
    allowed(
        &send(
            &mut core,
            retire_free(
                d,
                11,
                policy,
                "@id(\"x\") forbid(principal, action, resource) when { false };",
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    assert_eq!(tier_of(&db, d, 11).await, Some(3), "never lowered");
}

fn paying(d: Digest, nonce: u8, cents: i64) -> Request {
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let mut r = shop_request(d, nonce, Mode::Commit, shop);
    r.intent.params.insert(
        "amount".to_owned(),
        ParamValue::Amount {
            value: cents,
            unit: access_kernel::tier::THRESHOLD_UNIT.to_owned(),
        },
    );
    r
}

fn guard(d: Digest, nonce: u8, p: &Pattern) -> Request {
    meta_request(
        d,
        nonce,
        ExerciseBasis::Anchor(meta::meta_anchor(&d)),
        Payload::PolicySet {
            policy: None,
            content: patterns::content(p).unwrap(),
            defaults: None,
        },
    )
}

// U18, MUST-NEVER-8, §13.7.6, OP-157 m.3 (q), Ek B 5670
#[tokio::test]
async fn the_third_threshold_adjacent_exercise_needs_an_approval() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, gated(&[])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let approval = patterns::contribution("approve", Some(SubjectSelector::Party(ALICE)));
    allowed(
        &send(
            &mut core,
            guard(d, 10, &Pattern::ThresholdAdjacent { approval }),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let near = 90_000;
    for nonce in [11, 12] {
        allowed(
            &send(&mut core, paying(d, nonce, near), ROOT_KEY)
                .await
                .unwrap(),
        );
    }
    allowed(
        &send(&mut core, paying(d, 13, 10_000), ROOT_KEY)
            .await
            .unwrap(),
    );
    let third = send(&mut core, paying(d, 14, near), ROOT_KEY)
        .await
        .unwrap();
    assert_eq!(third.decision.outcome, Outcome::RequireAction);
    assert!(
        third
            .decision
            .unmet
            .iter()
            .any(|u| u.term.class == "approve")
    );
    // SI-8
    let basis = state_basis(&db, d, third.record.unwrap()).await;
    let cited = basis.get("derived").unwrap();
    assert_eq!(cited.get("threshold_adjacent"), Some(&Value::Unsigned(3)));
    assert_eq!(
        cited.get("party_consumption"),
        Some(&Value::Unsigned(3 * 90_000 + 10_000))
    );
    let inc = incoming(paying(d, 14, near), ROOT_KEY);
    let again = core
        .explain_recorded(&inc, third.record.unwrap(), Scope::Requester, NOW)
        .await
        .unwrap();
    assert_eq!(again.decision, third.decision);
    fold_check(&db.sequencer, d).await.unwrap();
}

// U18, §13.7.6, OP-157 m.3 (q), Ek B 5670
#[tokio::test]
async fn a_party_total_above_the_domain_limit_needs_an_approval() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, gated(&[])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let approval = patterns::contribution("approve", Some(SubjectSelector::Party(ALICE)));
    allowed(
        &send(
            &mut core,
            guard(
                d,
                10,
                &Pattern::PartyTotal {
                    limit: 50_000,
                    approval,
                },
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    allowed(
        &send(&mut core, paying(d, 11, 30_000), ROOT_KEY)
            .await
            .unwrap(),
    );
    let over = send(&mut core, paying(d, 12, 30_000), ROOT_KEY)
        .await
        .unwrap();
    assert_eq!(over.decision.outcome, Outcome::RequireAction);
}

// SI-8, RT26, OP-157 m.3 (o), Ek B 5661
#[tokio::test]
async fn a_request_without_window_values_cites_none() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, gated(&[])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let plain = send(&mut core, shop_request(d, 9, Mode::Commit, shop), ROOT_KEY)
        .await
        .unwrap();
    allowed(&plain);
    let basis = state_basis(&db, d, plain.record.unwrap()).await;
    assert!(basis.get("derived").is_none());
}

// INV-36, RT26, OP-157 m.3 (o), Ek B 5661
#[tokio::test]
async fn a_policy_naming_a_value_outside_the_whitelist_is_refused() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, gated(&[])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let outside =
        r#"@id("x") forbid(principal, action, resource) when { context.derived.reputation > 0 };"#;
    assert!(matches!(
        send(&mut core, policy_set(d, 10, None, outside, None), ROOT_KEY).await,
        Err(CoreError::Protocol("policy"))
    ));
    let inside = r#"@id("x") forbid(principal, action, resource) when { context.derived.open_offline_paps > 3 };"#;
    allowed(
        &send(&mut core, policy_set(d, 11, None, inside, None), ROOT_KEY)
            .await
            .unwrap(),
    );
}

fn staff_claim(d: Digest, subject: Id) -> Vec<u8> {
    sign_claim(
        &access_kernel::claim::Statement {
            domain: d,
            issuer: ALICE,
            subject,
            class: "staff".to_owned(),
            value: Some(EqValue::Bool(true)),
            issued_at: NOW,
            validity: Window {
                from: 0,
                until: 1_000_000,
            },
            assurance: BTreeMap::new(),
            bound_intent: None,
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        ALICE_KEY,
    )
}

// U18, §13.7.6, OP-157 m.3 (q), Ek B 5670
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "six new holders of one selector, one after the other"
)]
async fn a_mass_selections_new_holders_need_an_approval_from_ct2() {
    let db = fresh().await.unwrap();
    let holders = u8::try_from(patterns::MASS_NEW_HOLDERS).unwrap() + 1;
    let d = create_genesis(&db.sequencer, TENANT, grouped(), 1_000)
        .await
        .unwrap();
    let log = PgLog::new(db.sequencer.clone(), d, TENANT, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    let Bound(mut bound) = binding();
    for i in 0..holders {
        bound.insert(
            thumbprint(&public(20 + i)),
            (Id([20 + i; 16]), public(20 + i)),
        );
    }
    let mut core = Authority::new(leader, reader, Bound(bound), Counter(0), d);
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let approval = patterns::contribution("approve", Some(SubjectSelector::Party(ALICE)));
    allowed(
        &send(
            &mut core,
            guard(d, 10, &Pattern::MassSelection { approval }),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let grant = meta::object_id(&d, kind::GRANT, 1);
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let mut nonce = 100u8;
    for i in 0..holders {
        let (party, seed) = (Id([20 + i; 16]), 20 + i);
        let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
        for (n, payload) in [
            (
                nonce,
                Payload::PartyRegister {
                    party,
                    root: Root::Sole(party),
                    actor_kind: ActorKind::Human,
                },
            ),
            (
                nonce + 1,
                Payload::InstanceCreate {
                    party,
                    key: public(seed),
                    mandate: None,
                },
            ),
        ] {
            let mut inc = incoming(meta_request(d, n, public_basis, payload), seed);
            inc.context = RateContext::parse(&format!("holder-{i}"));
            allowed(&core.exercise(&inc, NOW).await.unwrap());
        }
        let ingested = send(
            &mut core,
            with_proofs(
                shop_request(d, nonce + 2, Mode::Commit, shop),
                vec![ProofRef::Claim(staff_claim(d, party))],
            ),
            ROOT_KEY,
        )
        .await
        .unwrap();
        allowed(&ingested);
        let holding = ExerciseBasis::Holding(HoldingRef {
            grant,
            holder: party,
            since: ingested.record.unwrap() - 2,
        });
        let mut r = shop_request(d, nonce + 3, Mode::Commit, holding);
        r.intent.params.insert(
            "amount".to_owned(),
            ParamValue::Amount {
                value: 200_000,
                unit: access_kernel::tier::THRESHOLD_UNIT.to_owned(),
            },
        );
        let got = send(&mut core, r, seed).await.unwrap();
        let guarded = got.decision.unmet.iter().any(|u| u.term.class == "approve");
        assert_eq!(
            guarded,
            u64::from(i) >= patterns::MASS_NEW_HOLDERS,
            "holder {i}: {got:?}"
        );
        nonce += 4;
    }
    fold_check(&db.sequencer, d).await.unwrap();
}
