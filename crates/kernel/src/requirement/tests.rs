use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use super::*;

fn id(n: u8) -> Id {
    Id([n; 16])
}

fn term(count: u64, independence: Independence, consumption: Consumption) -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Claim,
        class: "approval".to_string(),
        count,
        binding: Binding::IntentDigest,
        freshness_ms: Some(1_000),
        independence,
        consumption,
        source: None,
        assurance: BTreeMap::new(),
    }
}

fn proof(n: u8, position: u64, party: u8) -> Proof {
    Proof {
        id: id(n),
        kind: ProofKind::Claim,
        class: "approval".to_string(),
        position,
        time: 9_500,
        party: id(party),
        instance: id(party),
        issuer: id(100),
        binding: ProofBinding {
            intent_digest: Some(Digest([1; 32])),
            ..ProofBinding::default()
        },
        assurance: BTreeMap::new(),
        consumed: false,
        surface: None,
    }
}

const DIGEST: Digest = Digest([1; 32]);

fn ctx() -> Context<'static> {
    Context {
        now: 10_000,
        actor_instance: Some(Id([9; 16])),
        actor_party: None,
        intent_digest: &DIGEST,
        resources: &[],
    }
}

fn run(terms: &[RequirementTerm], proofs: &[Proof]) -> Vec<Outcome> {
    let set: BTreeSet<RequirementTerm> = terms.iter().cloned().collect();
    resolve(&set, proofs, &ctx(), &mut Fuel(1_000))
        .unwrap()
        .into_iter()
        .map(|(_, o)| o)
        .collect()
}

// OP-111 m.4
#[test]
fn matching_rules() {
    let t = term(1, Independence::None, Consumption::Reusable);
    let p = proof(1, 5, 1);
    assert!(matches(&t, &p, &ctx()));
    assert!(!matches(
        &t,
        &Proof {
            class: "other".to_string(),
            ..p.clone()
        },
        &ctx()
    ));
    assert!(!matches(
        &t,
        &Proof {
            kind: ProofKind::Authentication,
            ..p.clone()
        },
        &ctx()
    ));
    assert!(!matches(
        &t,
        &Proof {
            time: 8_999,
            ..p.clone()
        },
        &ctx()
    ));
    assert!(!matches(
        &t,
        &Proof {
            time: 10_001,
            ..p.clone()
        },
        &ctx()
    ));
    assert!(!matches(
        &t,
        &Proof {
            binding: ProofBinding::default(),
            ..p.clone()
        },
        &ctx()
    ));
    let single = term(1, Independence::None, Consumption::SingleUse);
    assert!(!matches(
        &single,
        &Proof {
            consumed: true,
            surface: None,
            ..p.clone()
        },
        &ctx()
    ));
    let mut floor = t.clone();
    floor.assurance.insert("aal".to_string(), 2);
    assert!(!matches(&floor, &p, &ctx()));
    let mut strong = p.clone();
    strong.assurance.insert("aal".to_string(), 3);
    assert!(matches(&floor, &strong, &ctx()));
    let mut sourced = t.clone();
    sourced.source = Some(SubjectSelector::Party(id(101)));
    assert!(!matches(&sourced, &p, &ctx()));
    assert!(source_rejected(&sourced, &[p]));
}

// OP-111 m.8
#[test]
fn source_rejection_needs_the_terms_kind_and_class() {
    let mut t = term(1, Independence::None, Consumption::Reusable);
    t.source = Some(SubjectSelector::Party(id(100)));
    let p = proof(1, 5, 1);
    let outsider = Proof {
        issuer: id(101),
        ..p.clone()
    };
    assert!(!source_rejected(&t, core::slice::from_ref(&p)));
    assert!(source_rejected(&t, core::slice::from_ref(&outsider)));
    let other_class = Proof {
        class: "other".to_string(),
        ..outsider.clone()
    };
    let other_kind = Proof {
        kind: ProofKind::Authentication,
        ..outsider.clone()
    };
    assert!(!source_rejected(&t, &[other_class]));
    assert!(!source_rejected(&t, &[other_kind]));
    assert!(!source_rejected(
        &RequirementTerm {
            source: None,
            ..t.clone()
        },
        &[outsider]
    ));
}

// T14, OP-111 m.5
#[test]
fn earliest_set_is_chosen_with_independence() {
    let two_parties = term(2, Independence::DistinctParty, Consumption::Reusable);
    let proofs = [
        proof(1, 30, 1),
        proof(2, 10, 1),
        proof(3, 20, 2),
        proof(4, 40, 3),
    ];
    assert_eq!(
        run(core::slice::from_ref(&two_parties), &proofs),
        vec![Outcome::Satisfied(vec![id(2), id(3)])]
    );
    assert_eq!(
        run(&[two_parties], &[proof(1, 1, 1), proof(2, 2, 1)]),
        vec![Outcome::Unmet(1)]
    );
    let tie = term(1, Independence::None, Consumption::Reusable);
    assert_eq!(
        run(&[tie], &[proof(5, 7, 1), proof(4, 7, 2)]),
        vec![Outcome::Satisfied(vec![id(4)])]
    );
}

// OP-111 m.3
#[test]
fn single_use_proofs_count_once_across_terms() {
    let a = term(1, Independence::None, Consumption::SingleUse);
    let mut b = a.clone();
    b.freshness_ms = Some(2_000);
    let proofs = [proof(1, 1, 1)];
    assert_eq!(
        run(&[a.clone(), b.clone()], &proofs),
        vec![Outcome::Satisfied(vec![id(1)]), Outcome::Unmet(1)]
    );
    let mut ra = a;
    ra.consumption = Consumption::Reusable;
    let mut rb = b;
    rb.consumption = Consumption::Reusable;
    assert_eq!(
        run(&[ra, rb], &proofs),
        vec![
            Outcome::Satisfied(vec![id(1)]),
            Outcome::Satisfied(vec![id(1)])
        ]
    );
}

// OP-111 m.7
#[test]
fn fuel_runs_out() {
    let set: BTreeSet<RequirementTerm> = [term(3, Independence::None, Consumption::Reusable)]
        .into_iter()
        .collect();
    let proofs = [proof(1, 1, 1), proof(2, 2, 2), proof(3, 3, 3)];
    assert_eq!(
        resolve(&set, &proofs, &ctx(), &mut Fuel(2)),
        Err(Rejection::Fuel)
    );
    assert!(resolve(&set, &proofs, &ctx(), &mut Fuel(3)).is_ok());
}

// OP-157 m.3 (b), §13.7.3
#[test]
fn a_distinct_surface_term_is_unmet_until_proofs_carry_a_surface() {
    let surfaces = term(1, Independence::DistinctSurface, Consumption::Reusable);
    assert_eq!(
        run(
            core::slice::from_ref(&surfaces),
            &[proof(1, 1, 1), proof(2, 2, 2)]
        ),
        vec![Outcome::Unmet(1)]
    );
    assert_eq!(
        RequirementTerm::from_value(&surfaces.to_value()),
        Ok(surfaces)
    );
}

// L0-EVAL-26a, SEC10, SEC20, OP-158 m.19 (c)
#[test]
fn a_recover_contribution_of_the_actor_party_counts_and_any_other_does_not() {
    let actor_party = Id([1; 16]);
    let digest = Digest([9; 32]);
    let ctx = Context {
        now: 10,
        actor_instance: Some(Id([2; 16])),
        actor_party: Some(actor_party),
        intent_digest: &digest,
        resources: &[],
    };
    let term = |class: &str| RequirementTerm {
        proof_kind: ProofKind::Contribution,
        class: alloc::string::String::from(class),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: None,
        independence: Independence::DistinctInstance,
        consumption: Consumption::SingleUse,
        source: None,
        assurance: BTreeMap::new(),
    };
    let proof = |class: &str, instance: u8| Proof {
        id: Id([instance; 16]),
        kind: ProofKind::Contribution,
        class: alloc::string::String::from(class),
        position: 1,
        time: 1,
        party: actor_party,
        instance: Id([instance; 16]),
        issuer: actor_party,
        binding: ProofBinding {
            actor_instance: None,
            intent_digest: Some(digest),
            resource: None,
        },
        assurance: BTreeMap::new(),
        consumed: false,
        surface: None,
    };
    let recover = crate::recovery::RECOVER;
    assert!(matches(&term(recover), &proof(recover, 3), &ctx));
    assert!(!matches(&term(recover), &proof(recover, 2), &ctx));
    assert!(!matches(&term("approve"), &proof("approve", 3), &ctx));
}
