//! SA-T8, MR4, GHSA-xxwr-vvr3-2g9f: the Decision Combinator the core relies on gives the same
//! decision whatever order the restriction policies and the candidate grants are assigned in.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::algebra::Catalog;
use access_kernel::codec::Stored;
use access_kernel::combinator::{
    Basis, Capacity, Decision, EvaluationInput, Fuel, Hop, HopStatus, Mode, PolicyResult, evaluate,
};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, Id,
    ResourceRef, ResourceSelector, Structural, Window,
};
use access_kernel::restriction::{PolicyDeny, RestrictionOutcome};
use proptest::prelude::*;

fn digest(n: u8) -> Digest {
    Digest(std::array::from_fn(|_| n))
}

fn id(n: u8) -> Id {
    Id(std::array::from_fn(|_| n))
}

fn action(name: &str) -> ActionRef {
    ActionRef {
        namespace: "pay".to_owned(),
        name: name.to_owned(),
        major: 1,
        schema: digest(9),
    }
}

/// One generated grant hop: whether it covers the action, its window end and status.
#[derive(Clone, Debug)]
struct HopSpec {
    covers: bool,
    until: u64,
    status: u8,
    conditions_hold: bool,
}

/// One generated restriction policy.
#[derive(Clone, Debug)]
struct PolicySpec {
    policy: u8,
    deny: bool,
    undisclosed: bool,
}

fn hop(s: &HopSpec) -> Hop {
    let exact: BTreeSet<ActionRef> = if s.covers {
        [action("refund")].into_iter().collect()
    } else {
        [action("charge")].into_iter().collect()
    };
    Hop {
        authority: CanonicalAuthority {
            authority: AuthoritySet {
                actions: ActionSet {
                    exact,
                    prefix: BTreeSet::new(),
                },
                resource: ResourceSelector::Structural(Structural {
                    namespace: "shop".to_owned(),
                    prefix: vec![],
                    kind: None,
                    attrs: BTreeMap::new(),
                }),
                params: BTreeMap::new(),
                recipient: None,
                purpose: None,
            },
            constraints: ConstraintSet {
                validity: Window {
                    from: 0,
                    until: s.until,
                },
                conditions: BTreeSet::new(),
                budget: BTreeSet::new(),
            },
            delegation: DelegationTerms {
                depth: 1,
                downstream_holder_class: None,
            },
            requirements: BTreeSet::new(),
        },
        status: match s.status % 3 {
            0 => HopStatus::Active,
            1 => HopStatus::Revoked,
            _ => HopStatus::Lapsed,
        },
        conditions_hold: s.conditions_hold,
        budgets: Vec::new(),
    }
}

fn policy(s: &PolicySpec) -> PolicyResult {
    PolicyResult {
        policy: id(s.policy),
        version: digest(2),
        outcome: if s.deny {
            RestrictionOutcome::Deny(PolicyDeny {
                policy: id(s.policy),
                version: digest(2),
                undisclosed: s.undisclosed,
            })
        } else {
            RestrictionOutcome::NoObjection
        },
    }
}

fn intent() -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: action("refund"),
        resources: vec![ResourceRef {
            namespace: "shop".to_owned(),
            path: vec!["o1".to_owned()],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 0,
            until: 100_000,
        },
    }
}

/// The decision, with its unordered parts in a canonical order.
fn decide(mode: Mode, bases: &[Basis], restrictions: &[PolicyResult]) -> Option<Decision> {
    let intent = intent();
    let catalog = Catalog::default();
    let input = EvaluationInput {
        mode,
        intent: &intent,
        intent_digest: digest(1),
        now: 50_000,
        actor_instance: Some(id(1)),
        actor_party: None,
        actor_is_agent: false,
        mandate: None,
        capacity: Capacity::Own,
        bases,
        restrictions,
        proofs: &[],
        catalog: &catalog,
        mappings: &[],
    };
    let mut d = evaluate(&input, &mut Fuel(100_000)).ok()?;
    d.blockers.sort();
    d.blockers.dedup();
    d.unmet.sort();
    d.relied_on.sort();
    d.relied_on.dedup();
    Some(d)
}

fn hop_spec() -> impl Strategy<Value = HopSpec> {
    (
        any::<bool>(),
        prop_oneof![Just(40_000_u64), Just(100_000_u64)],
        0_u8..3,
        any::<bool>(),
    )
        .prop_map(|(covers, until, status, conditions_hold)| HopSpec {
            covers,
            until,
            status,
            conditions_hold,
        })
}

fn policy_spec() -> impl Strategy<Value = PolicySpec> {
    (1_u8..12, any::<bool>(), any::<bool>()).prop_map(|(policy, deny, undisclosed)| PolicySpec {
        policy,
        deny,
        undisclosed,
    })
}

fn bases_of(specs: &[Vec<HopSpec>]) -> Vec<Basis> {
    specs
        .iter()
        .map(|hops| Basis {
            hops: hops.iter().map(|h| Stored::Known(hop(h))).collect(),
            capacities: [Capacity::Own].into_iter().collect(),
        })
        .collect()
}

fn permute<T: Clone>(items: &[T], order: &[usize]) -> Vec<T> {
    let mut keyed: Vec<(usize, T)> = items
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, t)| (order.get(i).copied().unwrap_or(i), t))
        .collect();
    keyed.sort_by_key(|(k, _)| *k);
    keyed.into_iter().map(|(_, t)| t).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // MR4, GHSA-xxwr-vvr3-2g9f
    #[test]
    fn mr4_permuting_restriction_policies_never_changes_the_decision(
        hops in prop::collection::vec(hop_spec(), 1..4),
        policies in prop::collection::vec(policy_spec(), 0..6),
        order in prop::collection::vec(any::<usize>(), 6),
        mode in prop_oneof![Just(Mode::Commit), Just(Mode::Check)],
    ) {
        let bases = bases_of(&[hops]);
        let restrictions: Vec<PolicyResult> = policies.iter().map(policy).collect();
        let shuffled = permute(&restrictions, &order);
        let before = decide(mode, &bases, &restrictions);
        prop_assert!(before.is_some());
        prop_assert_eq!(before, decide(mode, &bases, &shuffled));
    }

    // MR4, GHSA-xxwr-vvr3-2g9f
    #[test]
    fn mr4_permuting_candidate_grants_never_changes_the_check_decision(
        grants in prop::collection::vec(prop::collection::vec(hop_spec(), 1..3), 1..4),
        policies in prop::collection::vec(policy_spec(), 0..4),
        order in prop::collection::vec(any::<usize>(), 4),
    ) {
        let bases = bases_of(&grants);
        let shuffled = permute(&bases, &order);
        let restrictions: Vec<PolicyResult> = policies.iter().map(policy).collect();
        let a = decide(Mode::Check, &bases, &restrictions).map(|d| d.outcome);
        let b = decide(Mode::Check, &shuffled, &restrictions).map(|d| d.outcome);
        prop_assert_eq!(a, b);
    }
}

// MR4
#[test]
fn mr4_an_added_deny_in_any_position_denies() {
    let bases = bases_of(&[vec![HopSpec {
        covers: true,
        until: 100_000,
        status: 0,
        conditions_hold: true,
    }]]);
    let allow = decide(Mode::Commit, &bases, &[]).unwrap();
    assert_eq!(allow.outcome, access_kernel::combinator::Outcome::Allow);
    let deny = PolicySpec {
        policy: 7,
        deny: true,
        undisclosed: false,
    };
    let quiet = PolicySpec {
        policy: 8,
        deny: false,
        undisclosed: false,
    };
    let first = decide(Mode::Commit, &bases, &[policy(&deny), policy(&quiet)]).unwrap();
    let last = decide(Mode::Commit, &bases, &[policy(&quiet), policy(&deny)]).unwrap();
    assert_eq!(first, last);
    assert_eq!(first.outcome, access_kernel::combinator::Outcome::Deny);
}
