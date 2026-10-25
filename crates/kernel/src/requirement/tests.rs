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
    }
}

const DIGEST: Digest = Digest([1; 32]);

fn ctx() -> Context<'static> {
    Context {
        now: 10_000,
        actor_instance: Some(Id([9; 16])),
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
