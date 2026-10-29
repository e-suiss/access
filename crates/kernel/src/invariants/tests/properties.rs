use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use proptest::prelude::*;
use suiss_crypto::dcbor::Value;

use crate::algebra::Catalog;
use crate::codec::{Canonical, Stored};
use crate::combinator::codec::OwnedInput;
use crate::combinator::{
    Basis, BudgetState, Capacity, Decision, EvaluationInput, Fuel, Hop, HopStatus, Mandate, Mode,
    Outcome, PolicyResult, Rejection, evaluate,
};
use crate::digest::{self, Context, Digest};
use crate::intent::{ContextRefs, IntentEnvelope};
use crate::model::{
    ActionRef, ActionSet, AuthoritySet, Binding, BudgetWindow, CanonicalAuthority, ConstraintSet,
    Consumption, DelegationTerms, Id, Independence, ProofKind, RequirementTerm, ResourceRef,
    ResourceSelector, Structural, SubjectSelector, Window,
};
use crate::record::{Header, Opened, RecordEnvelope, RecordKind, check_link};
use crate::requirement::{HUMAN_PRESENCE, Proof, ProofBinding};
use crate::restriction::{PolicyDeny, RestrictionOutcome};

const FUEL: u64 = 100_000;

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

fn action() -> ActionRef {
    ActionRef {
        namespace: "pay".to_string(),
        name: "refund".to_string(),
        major: 1,
        schema: d(9),
    }
}

fn authority(cover: bool) -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: if cover {
                [action()].into_iter().collect()
            } else {
                BTreeSet::new()
            },
            prefix: BTreeSet::new(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: "shop".to_string(),
            prefix: vec![],
            kind: None,
            attrs: BTreeMap::new(),
        }),
        params: BTreeMap::new(),
        recipient: None,
        purpose: None,
    }
}

fn approval(human: bool) -> RequirementTerm {
    let mut assurance = BTreeMap::new();
    if human {
        assurance.insert(HUMAN_PRESENCE.to_string(), 1);
    }
    RequirementTerm {
        proof_kind: ProofKind::Authentication,
        class: "step_up".to_string(),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: None,
        independence: Independence::None,
        consumption: Consumption::SingleUse,
        source: None,
        assurance,
    }
}

fn party(n: u8) -> Id {
    Id([n; 16])
}

#[derive(Clone, Debug)]
struct HopSpec {
    cover: bool,
    validity: u8,
    status: u8,
    conditions_hold: bool,
    budget: Option<(bool, u64, bool)>,
    recipient: bool,
    requirement: Option<bool>,
}

fn hop_spec() -> impl Strategy<Value = HopSpec> {
    (
        prop::bool::weighted(0.9),
        0_u8..10,
        0_u8..12,
        prop::bool::weighted(0.92),
        prop::option::weighted(0.2, (any::<bool>(), 0_u64..3, prop::bool::weighted(0.9))),
        prop::bool::weighted(0.1),
        prop::option::weighted(0.25, any::<bool>()),
    )
        .prop_map(
            |(cover, validity, status, conditions_hold, budget, recipient, requirement)| HopSpec {
                cover,
                validity,
                status,
                conditions_hold,
                budget,
                recipient,
                requirement,
            },
        )
}

fn hop(s: &HopSpec) -> Hop {
    let mut a = authority(s.cover);
    if s.recipient {
        a.recipient = Some(SubjectSelector::Party(party(5)));
    }
    let validity = match s.validity {
        0 => Window {
            from: 0,
            until: 40_000,
        },
        1 => Window {
            from: 60_000,
            until: 100_000,
        },
        _ => Window {
            from: 0,
            until: 100_000,
        },
    };
    Hop {
        authority: CanonicalAuthority {
            authority: a,
            constraints: ConstraintSet {
                validity,
                conditions: BTreeSet::new(),
                budget: BTreeSet::new(),
            },
            delegation: DelegationTerms {
                depth: 1,
                downstream_holder_class: None,
            },
            requirements: s.requirement.map(approval).into_iter().collect(),
        },
        status: match s.status {
            0 => HopStatus::Revoked,
            1 => HopStatus::Lapsed,
            _ => HopStatus::Active,
        },
        conditions_hold: s.conditions_hold,
        budgets: s
            .budget
            .map(|(rolling, remaining, resets)| BudgetState {
                window: if rolling {
                    BudgetWindow::RollingSeconds(60)
                } else {
                    BudgetWindow::Total
                },
                remaining,
                demand: 1,
                resets_at: (rolling && resets).then_some(70_000),
            })
            .into_iter()
            .collect(),
    }
}

fn basis() -> impl Strategy<Value = Basis> {
    (
        prop::collection::vec(hop_spec(), 1..5),
        prop::bool::weighted(0.5),
    )
        .prop_map(|(hops, for_party)| {
            let mut capacities: BTreeSet<Capacity> = [Capacity::Own].into_iter().collect();
            if for_party {
                capacities.insert(Capacity::For(party(9)));
            }
            Basis {
                hops: hops.iter().map(|h| Stored::Known(hop(h))).collect(),
                capacities,
            }
        })
}

fn restriction() -> impl Strategy<Value = (u8, bool)> {
    (0_u8..3, any::<bool>())
}

fn policy(n: u8, kind: u8, flag: bool) -> PolicyResult {
    let id = n.wrapping_add(7);
    PolicyResult {
        policy: Id([id; 16]),
        version: d(2),
        outcome: match kind {
            0 => RestrictionOutcome::Deny(PolicyDeny {
                policy: Id([id; 16]),
                version: d(2),
                undisclosed: flag,
            }),
            1 => RestrictionOutcome::Require([approval(flag)].into_iter().collect()),
            _ => RestrictionOutcome::NoObjection,
        },
    }
}

fn proof(n: u8, consumed: bool, time: u8, assured: bool, position: u64) -> Proof {
    Proof {
        id: Id([n.wrapping_add(3); 16]),
        kind: ProofKind::Authentication,
        class: "step_up".to_string(),
        position,
        time: [1, 49_999, 60_000][usize::from(time % 3)],
        party: party(1),
        instance: party(1),
        issuer: party(1),
        binding: ProofBinding {
            intent_digest: Some(d(1)),
            ..ProofBinding::default()
        },
        assurance: if assured {
            [(HUMAN_PRESENCE.to_string(), 1)].into_iter().collect()
        } else {
            BTreeMap::new()
        },
        consumed,
    }
}

#[derive(Clone, Debug)]
struct World {
    mode: Mode,
    intent: IntentEnvelope,
    bases: Vec<Basis>,
    restrictions: Vec<PolicyResult>,
    proofs: Vec<Proof>,
    mandate: Option<Mandate>,
    catalog: Catalog,
    capacity: Capacity,
    agent: bool,
}

impl World {
    fn input(&self) -> EvaluationInput<'_> {
        EvaluationInput {
            mode: self.mode,
            intent: &self.intent,
            intent_digest: d(1),
            now: 50_000,
            actor_instance: Some(party(1)),
            actor_is_agent: self.agent,
            mandate: self.mandate.as_ref(),
            capacity: self.capacity,
            bases: &self.bases,
            restrictions: &self.restrictions,
            proofs: &self.proofs,
            catalog: &self.catalog,
        }
    }

    fn owned(&self) -> OwnedInput {
        OwnedInput {
            mode: self.mode,
            intent: self.intent.clone(),
            intent_digest: d(1),
            now: 50_000,
            actor_instance: Some(party(1)),
            actor_is_agent: self.agent,
            mandate: self.mandate.clone(),
            capacity: self.capacity,
            bases: self.bases.clone(),
            restrictions: self.restrictions.clone(),
            proofs: self.proofs.clone(),
            catalog: self.catalog.clone(),
        }
    }

    fn run_with(&self, fuel: u64) -> (Result<Decision, Rejection>, u64) {
        let mut f = Fuel(fuel);
        let r = evaluate(&self.input(), &mut f);
        (r, fuel.checked_sub(f.0).unwrap())
    }

    fn run(&self) -> Result<Decision, Rejection> {
        self.run_with(FUEL).0
    }
}

fn intent(recipient: bool) -> IntentEnvelope {
    IntentEnvelope {
        action: action(),
        resources: vec![ResourceRef {
            namespace: "shop".to_string(),
            path: vec!["o1".to_string()],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: recipient.then(|| party(5)),
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 0,
            until: 100_000,
        },
    }
}

fn world_with(check: bool) -> impl Strategy<Value = World> {
    (
        (
            prop::collection::vec(basis(), if check { 0..5 } else { 1..2 }),
            any::<bool>(),
        ),
        prop::collection::vec(restriction(), 0..3),
        prop::collection::vec(
            (
                prop::bool::weighted(0.2),
                0_u8..3,
                prop::bool::weighted(0.8),
                0_u64..3,
            ),
            0..3,
        ),
        prop::bool::weighted(0.1),
        prop::option::weighted(0.25, prop::bool::weighted(0.7)),
        prop::bool::weighted(0.3),
        0_u8..2,
    )
        .prop_map(
            move |((bases, recipient), restrictions, proofs, for_party, mandate, agent, mode)| {
                World {
                    mode: if check {
                        Mode::Check
                    } else if mode == 0 {
                        Mode::Commit
                    } else {
                        Mode::Continue
                    },
                    intent: intent(recipient),
                    bases,
                    restrictions: restrictions
                        .iter()
                        .zip(0_u8..)
                        .map(|((k, f), n)| policy(n, *k, *f))
                        .collect(),
                    proofs: proofs
                        .iter()
                        .zip(0_u8..)
                        .map(|((c, t, a, p), n)| proof(n, *c, *t, *a, *p))
                        .collect(),
                    mandate: mandate.map(|cover| Mandate {
                        authority: authority(cover),
                        requirements: BTreeSet::new(),
                    }),
                    catalog: Catalog::default(),
                    capacity: if for_party {
                        Capacity::For(party(9))
                    } else {
                        Capacity::Own
                    },
                    agent,
                }
            },
        )
}

fn world() -> impl Strategy<Value = World> {
    prop_oneof![world_with(false), world_with(true)]
}

fn allowed(r: &Result<Decision, Rejection>) -> bool {
    matches!(r, Ok(d) if d.outcome == Outcome::Allow)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..ProptestConfig::default() })]

    // INV-27, CR-49 m.3 determinism, G17
    #[test]
    fn evaluation_is_deterministic(w in world()) {
        let first = w.run();
        prop_assert_eq!(&first, &w.run());
        let owned = w.owned();
        let bytes = owned.to_bytes().unwrap();
        let back = OwnedInput::from_bytes(&bytes).unwrap();
        prop_assert_eq!(back.to_bytes().unwrap(), bytes);
        prop_assert_eq!(&evaluate(&back.input(), &mut Fuel(FUEL)), &first);
        let mut shuffled = w.clone();
        shuffled.restrictions.reverse();
        shuffled.proofs.reverse();
        prop_assert_eq!(&shuffled.run(), &first);
    }

    // CR-49 m.3 monotonicity (−), MUST-NEVER-2: a restriction DENY always denies (INV-6)
    #[test]
    fn a_restriction_deny_never_allows(w in world(), undisclosed in any::<bool>()) {
        let before = w.run();
        let mut after = w.clone();
        after.restrictions.push(policy(40, 0, undisclosed));
        let r = after.run();
        if before.is_ok() {
            prop_assert!(matches!(&r, Ok(d) if d.outcome == Outcome::Deny), "{:?}", r);
        }
    }

    // CR-49 m.3 monotonicity (−): revoking a hop or dropping a proof never adds an ALLOW
    #[test]
    fn narrowing_never_adds_an_allow(
        w in world(),
        basis in any::<prop::sample::Index>(),
        hop in any::<prop::sample::Index>(),
        drop in any::<prop::sample::Index>(),
    ) {
        let before = w.run();
        if !w.bases.is_empty() {
            let mut after = w.clone();
            let b = basis.index(after.bases.len());
            let h = hop.index(after.bases[b].hops.len());
            if let Stored::Known(x) = &mut after.bases[b].hops[h] {
                x.status = HopStatus::Revoked;
            }
            let r = after.run();
            prop_assert!(!allowed(&r) || allowed(&before), "{:?} -> {:?}", before, r);
            if w.bases.len() == 1 {
                prop_assert!(!allowed(&r));
            }
        }
        if !w.proofs.is_empty() {
            let mut after = w.clone();
            after.proofs.remove(drop.index(w.proofs.len()));
            let r = after.run();
            prop_assert!(!allowed(&r) || allowed(&before), "{:?} -> {:?}", before, r);
        }
    }

    // CR-49 m.3 monotonicity (+): another candidate or another proof never removes an ALLOW
    #[test]
    fn widening_never_removes_an_allow(w in world_with(true), extra in basis(), time in 0_u8..3) {
        let before = w.run();
        if !allowed(&before) {
            return Ok(());
        }
        let mut alone = w.clone();
        alone.bases = vec![extra.clone()];
        let mut more = w.clone();
        more.bases.push(extra);
        if alone.run() == Err(Rejection::Input) {
            prop_assert_eq!(more.run(), Err(Rejection::Input));
        } else {
            prop_assert_eq!(&more.run(), &before);
        }
        let mut more = w.clone();
        more.proofs.push(proof(60, false, time, true, 0));
        prop_assert!(allowed(&more.run()));
    }

    // CR-49 m.3 batch = single: `check` is the first ALLOW of single checks
    #[test]
    fn check_is_the_first_allow_of_single_checks(w in world_with(true)) {
        let batch = w.run();
        let singles: Vec<Result<Decision, Rejection>> = w
            .bases
            .iter()
            .map(|b| {
                let mut one = w.clone();
                one.bases = vec![b.clone()];
                one.run()
            })
            .collect();
        let rejected = singles.iter().find_map(|s| s.as_ref().err().copied());
        let batch = match (batch, rejected) {
            (Err(e), r) => {
                prop_assert_eq!(Some(e), r);
                return Ok(());
            }
            (Ok(b), None) => b,
            (Ok(b), Some(e)) => {
                prop_assert!(false, "{:?} vs single {:?}", b, e);
                return Ok(());
            }
        };
        let singles: Vec<Decision> = singles.into_iter().map(Result::unwrap).collect();
        let first = |o: Outcome| singles.iter().find(|s| s.outcome == o);
        if let Some(a) = first(Outcome::Allow) {
            prop_assert_eq!(&batch, a);
        } else if let Some(r) = first(Outcome::RequireAction) {
            prop_assert_eq!(&batch, r);
        } else {
            prop_assert_eq!(batch.outcome, Outcome::Deny);
            if !singles.is_empty() {
                let union: BTreeSet<_> = singles.iter().flat_map(|s| s.blockers.iter().cloned()).collect();
                let got: BTreeSet<_> = batch.blockers.iter().cloned().collect();
                prop_assert_eq!(got, union);
            }
        }
    }

    // CR-49 m.3 termination, OP-108 m.11, SI-20: bounded fuel; too little is a rejection, never a decision
    #[test]
    fn evaluation_terminates_within_fuel(w in world(), cut in any::<prop::sample::Index>()) {
        let (full, used) = w.run_with(FUEL);
        prop_assert_ne!(&full, &Err(Rejection::Fuel));
        prop_assert!(used <= 2_000, "used {}", used);
        prop_assert_eq!(&w.run_with(used).0, &full);
        prop_assert_eq!(&w.run_with(used.saturating_mul(2)).0, &full);
        if used > 0 {
            let short = cut.index(usize::try_from(used).unwrap());
            let (r, spent) = w.run_with(u64::try_from(short).unwrap());
            prop_assert_eq!(r, Err(Rejection::Fuel));
            prop_assert!(spent <= u64::try_from(short).unwrap());
        }
    }
}

fn names() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("artifacts".to_string()),
        Just("basis".to_string()),
        Just("outcome".to_string()),
        Just("z".to_string()),
        Just("ab".to_string()),
    ]
}

fn field() -> impl Strategy<Value = Opened> {
    (
        prop_oneof![
            any::<i64>().prop_map(Value::int),
            "[a-z]{0,8}".prop_map(|s| Value::text(&s)),
            prop::collection::vec(any::<u8>(), 0..8).prop_map(Value::Bytes),
        ],
        any::<[u8; 32]>(),
    )
        .prop_map(|(value, salt)| Opened { value, salt })
}

fn record(domain: Digest, pos: u64) -> impl Strategy<Value = RecordEnvelope> {
    (
        prop::collection::btree_map(names(), field(), 1..5),
        any::<u64>(),
        any::<[u8; 32]>(),
    )
        .prop_map(move |(fields, recorded_at, prev)| RecordEnvelope {
            header: Header {
                domain: Some(domain),
                pos,
                kind: RecordKind::Decision,
                recorded_at,
                prev: Some(Digest(prev)),
            },
            fields,
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 500, ..ProptestConfig::default() })]

    // CR-49 m.3 domain isolation: a record, its leaf and its link belong to one domain only
    #[test]
    fn records_are_bound_to_their_domain(
        r in record(d(1), 7),
        other in any::<[u8; 32]>(),
        open in any::<prop::sample::Index>(),
    ) {
        prop_assume!(Digest(other) != d(1));
        let mut moved = r.clone();
        moved.header.domain = Some(Digest(other));
        prop_assert_ne!(r.leaf_hash().unwrap(), moved.leaf_hash().unwrap());
        let name = r.fields.keys().nth(open.index(r.fields.len())).unwrap().clone();
        let shown = r.disclose(|n| n == name).unwrap();
        let mut forged = shown.clone();
        forged.header.domain = Some(Digest(other));
        prop_assert_ne!(forged.leaf_hash().unwrap(), r.leaf_hash().unwrap());
        prop_assert_eq!(shown.leaf_hash().unwrap(), r.leaf_hash().unwrap());

        let previous = r.leaf_core().unwrap();
        let mut next = moved.leaf_core().unwrap();
        next.header.pos = 8;
        next.header.recorded_at = previous.header.recorded_at;
        next.header.prev = Some(Digest(previous.leaf_hash().unwrap()));
        prop_assert!(check_link(&previous, &next, &d(1)).is_err());
        prop_assert!(check_link(&previous, &next, &Digest(other)).is_err());
    }

    // OP-106 m.22: one value never has the same digest under two contexts
    #[test]
    fn digest_contexts_are_separated(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        prop_assert_ne!(digest::digest(Context::Intent, &bytes), digest::digest(Context::Genesis, &bytes));
        prop_assert_ne!(digest::domain_id(&bytes).0, digest::leaf_hash(&bytes));
    }
}
