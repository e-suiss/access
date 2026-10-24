use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::intent::ContextRefs;
use crate::model::{
    ActionRef, ActionSet, Binding, BudgetWindow, ConstraintSet, Consumption, DelegationTerms,
    Independence, ProofKind, ResourceRef, ResourceSelector, Structural, SubjectSelector,
    WhileCondition, Window,
};
use crate::requirement::ProofBinding;
use crate::restriction::PolicyDeny;

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

fn authority() -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: [action()].into_iter().collect(),
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

fn hop() -> Hop {
    Hop {
        authority: CanonicalAuthority {
            authority: authority(),
            constraints: ConstraintSet {
                validity: Window {
                    from: 0,
                    until: 100_000,
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
        status: HopStatus::Active,
        conditions_hold: true,
        budgets: Vec::new(),
    }
}

fn basis(hops: Vec<Hop>) -> Basis {
    Basis {
        hops,
        capacities: [Capacity::Own].into_iter().collect(),
    }
}

fn intent() -> IntentEnvelope {
    IntentEnvelope {
        action: action(),
        resources: vec![ResourceRef {
            namespace: "shop".to_string(),
            path: vec!["o1".to_string()],
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

fn step_up_proof() -> Proof {
    Proof {
        id: Id([3; 16]),
        kind: ProofKind::Authentication,
        class: "step_up".to_string(),
        position: 1,
        time: 1,
        party: Id([1; 16]),
        instance: Id([1; 16]),
        issuer: Id([1; 16]),
        binding: ProofBinding {
            intent_digest: Some(d(1)),
            ..ProofBinding::default()
        },
        assurance: [(HUMAN_PRESENCE.to_string(), 1)].into_iter().collect(),
        consumed: false,
    }
}

struct World {
    intent: IntentEnvelope,
    bases: Vec<Basis>,
    restrictions: Vec<PolicyResult>,
    proofs: Vec<Proof>,
    mandate: Option<Mandate>,
    catalog: Catalog,
    mode: Mode,
    capacity: Capacity,
    agent: bool,
}

impl World {
    fn new() -> Self {
        Self {
            intent: intent(),
            bases: vec![basis(vec![hop(), hop()])],
            restrictions: Vec::new(),
            proofs: Vec::new(),
            mandate: None,
            catalog: Catalog::default(),
            mode: Mode::Commit,
            capacity: Capacity::Own,
            agent: false,
        }
    }

    fn run(&self) -> Result<Decision, Rejection> {
        let input = EvaluationInput {
            mode: self.mode,
            intent: &self.intent,
            intent_digest: d(1),
            now: 50_000,
            actor_instance: Some(Id([1; 16])),
            actor_is_agent: self.agent,
            mandate: self.mandate.as_ref(),
            capacity: self.capacity,
            bases: &self.bases,
            restrictions: &self.restrictions,
            proofs: &self.proofs,
            catalog: &self.catalog,
        };
        evaluate(&input, &mut Fuel(10_000))
    }

    fn blockers(
        &self,
    ) -> Vec<(
        BlockerClass,
        Option<String>,
        Position,
        Resolver,
        Remediation,
    )> {
        let d = self.run().unwrap();
        assert_eq!(d.outcome, Outcome::Deny);
        d.blockers
            .into_iter()
            .map(|b| (b.class, b.subcode, b.position, b.resolver, b.remediation))
            .collect()
    }
}

#[test]
fn allow_when_every_hop_covers() {
    let d = World::new().run().unwrap();
    assert_eq!(
        (d.outcome, d.blockers.len(), d.unmet.len()),
        (Outcome::Allow, 0, 0)
    );
}

// OP-111 m.2, m.8
#[test]
fn blocker_table() {
    let mut w = World::new();
    w.bases[0].hops[1].authority.authority.actions.exact.clear();
    assert_eq!(
        w.blockers(),
        vec![(
            BlockerClass::NoCoveringAuthority,
            None,
            Position::Hop(1),
            Resolver::GrantorOfHop(1),
            Remediation::RouteToCoordinator
        )]
    );

    let mut w = World::new();
    let mut m_auth = authority();
    m_auth.actions.exact.clear();
    w.mandate = Some(Mandate {
        authority: m_auth,
        requirements: BTreeSet::new(),
    });
    assert_eq!(
        w.blockers(),
        vec![(
            BlockerClass::OutsideInstanceLimits,
            None,
            Position::Instance,
            Resolver::ActorParty,
            Remediation::RouteToCoordinator
        )]
    );
}

// OP-111 m.8
#[test]
fn blocker_table_restriction_and_budget() {
    let mut w = World::new();
    w.restrictions.push(PolicyResult {
        policy: Id([7; 16]),
        version: d(2),
        outcome: RestrictionOutcome::Deny(PolicyDeny {
            policy: Id([7; 16]),
            version: d(2),
            undisclosed: false,
        }),
    });
    let b = w.blockers();
    assert_eq!(
        (b[0].0, b[0].2, b[0].3, b[0].4),
        (
            BlockerClass::Restricted,
            Position::DomainPolicy,
            Resolver::RestrictionOwner,
            Remediation::NotSatisfiableByActor
        )
    );
    assert!(
        b[0].1
            .as_deref()
            .is_some_and(|s| s.starts_with("restricted/policy:"))
    );

    let mut w = World::new();
    w.bases[0].hops[0].budgets.push(BudgetState {
        window: BudgetWindow::RollingSeconds(60),
        remaining: 0,
        demand: 1,
        resets_at: Some(70_000),
    });
    w.bases[0].hops[1].budgets.push(BudgetState {
        window: BudgetWindow::Total,
        remaining: 5,
        demand: 6,
        resets_at: None,
    });
    assert_eq!(
        w.blockers(),
        vec![
            (
                BlockerClass::BudgetExhausted,
                None,
                Position::Hop(0),
                Resolver::Time,
                Remediation::WaitUntil(70_000)
            ),
            (
                BlockerClass::BudgetExhausted,
                None,
                Position::Hop(1),
                Resolver::GrantorOfHop(1),
                Remediation::RouteToCoordinator
            ),
        ]
    );
}

// OP-111 m.8
#[test]
fn blocker_table_ended_and_capacity() {
    let mut w = World::new();
    w.bases[0].hops[0].authority.constraints.validity = Window {
        from: 0,
        until: 49_999,
    };
    w.bases[0].hops[1].authority.constraints.validity = Window {
        from: 60_000,
        until: 90_000,
    };
    assert_eq!(
        w.blockers(),
        vec![
            (
                BlockerClass::Ended,
                Some("ended/expired".to_string()),
                Position::Hop(0),
                Resolver::GrantorOfHop(0),
                Remediation::NewRequestRequired
            ),
            (
                BlockerClass::Ended,
                Some("ended/expired".to_string()),
                Position::Hop(1),
                Resolver::Time,
                Remediation::WaitUntil(60_000)
            ),
        ]
    );

    let mut w = World::new();
    w.bases[0].hops[0].status = HopStatus::Revoked;
    w.bases[0].hops[1].conditions_hold = false;
    assert_eq!(
        w.blockers(),
        vec![
            (
                BlockerClass::Ended,
                Some("ended/lapsed".to_string()),
                Position::Hop(1),
                Resolver::GrantorOfHop(1),
                Remediation::NewRequestRequired
            ),
            (
                BlockerClass::Ended,
                Some("ended/revoked".to_string()),
                Position::Hop(0),
                Resolver::GrantorOfHop(0),
                Remediation::NewRequestRequired
            ),
        ]
    );

    let mut w = World::new();
    w.capacity = Capacity::For(Id([5; 16]));
    assert_eq!(
        w.blockers(),
        vec![(
            BlockerClass::CapacityMismatch,
            None,
            Position::Hop(0),
            Resolver::Actor,
            Remediation::NewRequestRequired
        )]
    );
}

// §5.8, OP-111 m.4, m.8
#[test]
fn requirements_and_deny_overrides() {
    let mut w = World::new();
    w.bases[0].hops[1]
        .authority
        .requirements
        .insert(approval(true));
    let dec = w.run().unwrap();
    assert_eq!(dec.outcome, Outcome::RequireAction);
    assert_eq!(
        (
            dec.unmet[0].position,
            dec.unmet[0].missing,
            dec.unmet[0].satisfiable_by_actor
        ),
        (Position::Hop(1), 1, true)
    );

    w.agent = true;
    assert!(!w.run().unwrap().unmet[0].satisfiable_by_actor);

    w.proofs.push(step_up_proof());
    let dec = w.run().unwrap();
    assert_eq!(
        (dec.outcome, dec.relied_on.clone()),
        (Outcome::Allow, vec![Id([3; 16])])
    );

    w.proofs.clear();
    w.restrictions.push(PolicyResult {
        policy: Id([7; 16]),
        version: d(2),
        outcome: RestrictionOutcome::Deny(PolicyDeny {
            policy: Id([7; 16]),
            version: d(2),
            undisclosed: true,
        }),
    });
    let dec = w.run().unwrap();
    assert_eq!(
        (dec.outcome, dec.unmet.len(), dec.relied_on.len()),
        (Outcome::Deny, 1, 0)
    );

    let mut w = World::new();
    w.restrictions.push(PolicyResult {
        policy: Id([8; 16]),
        version: d(3),
        outcome: RestrictionOutcome::Require([approval(false)].into_iter().collect()),
    });
    let dec = w.run().unwrap();
    assert_eq!(
        (dec.outcome, dec.unmet[0].position),
        (Outcome::RequireAction, Position::DomainPolicy)
    );

    let mut w = World::new();
    let mut sourced = approval(false);
    sourced.source = Some(crate::model::SubjectSelector::Party(Id([42; 16])));
    w.bases[0].hops[0].authority.requirements.insert(sourced);
    w.proofs.push(step_up_proof());
    assert_eq!(
        w.blockers(),
        vec![(
            BlockerClass::SourceNotAccepted,
            None,
            Position::ActorSide,
            Resolver::Issuer,
            Remediation::RefreshClaim
        )]
    );
}

// OP-111 m.6
#[test]
fn modes() {
    let mut w = World::new();
    w.bases.push(basis(vec![hop()]));
    assert_eq!(w.run(), Err(Rejection::Input));
    w.bases.clear();
    assert_eq!(w.run(), Err(Rejection::Input));

    w.mode = Mode::Check;
    let d = w.run().unwrap();
    assert_eq!(
        (d.outcome, d.blockers[0].class),
        (Outcome::Deny, BlockerClass::NoCoveringAuthority)
    );

    let mut revoked = hop();
    revoked.status = HopStatus::Revoked;
    let mut needs = hop();
    needs.authority.requirements.insert(approval(false));
    w.bases = vec![
        basis(vec![revoked.clone()]),
        basis(vec![needs]),
        basis(vec![hop()]),
    ];
    assert_eq!(w.run().unwrap().outcome, Outcome::Allow);
    w.bases.pop();
    assert_eq!(w.run().unwrap().outcome, Outcome::RequireAction);
    w.bases = vec![basis(vec![revoked]), basis(vec![])];
    assert_eq!(w.run(), Err(Rejection::Input));
}

// OP-108 m.10
#[test]
fn lineage_deeper_than_sixteen_is_rejected() {
    let mut w = World::new();
    w.bases = vec![basis(vec![hop(); MAX_LINEAGE])];
    assert_eq!(w.run().map(|dec| dec.outcome), Ok(Outcome::Allow));
    w.bases = vec![basis(vec![hop(); MAX_LINEAGE + 1])];
    assert_eq!(w.run(), Err(Rejection::Limit));
}

// OP-111 m.7
#[test]
fn fuel_exhaustion_is_a_rejection() {
    let w = World::new();
    let input = EvaluationInput {
        mode: Mode::Commit,
        intent: &w.intent,
        intent_digest: d(1),
        now: 0,
        actor_instance: None,
        actor_is_agent: false,
        mandate: None,
        capacity: Capacity::Own,
        bases: &w.bases,
        restrictions: &[],
        proofs: &[],
        catalog: &w.catalog,
    };
    assert_eq!(evaluate(&input, &mut Fuel(1)), Err(Rejection::Fuel));
    assert!(evaluate(&input, &mut Fuel(2)).is_ok());
}

impl World {
    fn owned(&self) -> codec::OwnedInput {
        codec::OwnedInput {
            mode: self.mode,
            intent: self.intent.clone(),
            intent_digest: d(1),
            now: 50_000,
            actor_instance: Some(Id([1; 16])),
            actor_is_agent: self.agent,
            mandate: self.mandate.clone(),
            capacity: self.capacity,
            bases: self.bases.clone(),
            restrictions: self.restrictions.clone(),
            proofs: self.proofs.clone(),
            catalog: self.catalog.clone(),
        }
    }
}

fn deny_policy(n: u8, undisclosed: bool) -> PolicyResult {
    PolicyResult {
        policy: Id([n; 16]),
        version: d(2),
        outcome: RestrictionOutcome::Deny(PolicyDeny {
            policy: Id([n; 16]),
            version: d(2),
            undisclosed,
        }),
    }
}

fn scenarios() -> Vec<(&'static str, World)> {
    let mut out = vec![("allow", World::new())];
    let mut w = World::new();
    w.bases[0].hops[1].authority.authority.actions.exact.clear();
    out.push(("deny-no-covering-authority-hop1", w));
    let mut w = World::new();
    let mut narrow = authority();
    narrow.actions.exact.clear();
    w.mandate = Some(Mandate {
        authority: narrow,
        requirements: BTreeSet::new(),
    });
    out.push(("deny-outside-instance-limits", w));
    let mut w = World::new();
    w.restrictions.push(deny_policy(7, true));
    out.push(("deny-restricted", w));
    let mut w = World::new();
    w.bases[0].hops[0].budgets.push(BudgetState {
        window: BudgetWindow::RollingSeconds(60),
        remaining: 0,
        demand: 1,
        resets_at: Some(70_000),
    });
    out.push(("deny-budget-rolling", w));
    let mut w = World::new();
    w.bases[0].hops[1].budgets.push(BudgetState {
        window: BudgetWindow::Total,
        remaining: 5,
        demand: 6,
        resets_at: None,
    });
    out.push(("deny-budget-total", w));
    let mut w = World::new();
    w.bases[0].hops[0].authority.constraints.validity = Window {
        from: 0,
        until: 49_999,
    };
    out.push(("deny-expired", w));
    let mut w = World::new();
    w.bases[0].hops[1].authority.constraints.validity = Window {
        from: 60_000,
        until: 90_000,
    };
    out.push(("deny-not-yet-valid", w));
    let mut w = World::new();
    w.bases[0].hops[0].status = HopStatus::Revoked;
    out.push(("deny-revoked", w));
    let mut w = World::new();
    w.bases[0].hops[1].conditions_hold = false;
    out.push(("deny-lapsed", w));
    let mut w = World::new();
    w.capacity = Capacity::For(Id([5; 16]));
    out.push(("deny-capacity-mismatch", w));
    out.extend(requirement_scenarios());
    out
}

fn requirement_scenarios() -> Vec<(&'static str, World)> {
    let mut out = Vec::new();
    let mut w = World::new();
    w.bases[0].hops[1]
        .authority
        .requirements
        .insert(approval(true));
    out.push(("require-step-up", w));
    let mut w = World::new();
    w.bases[0].hops[1]
        .authority
        .requirements
        .insert(approval(true));
    w.agent = true;
    out.push(("require-human-presence-agent", w));
    let mut w = World::new();
    w.bases[0].hops[1]
        .authority
        .requirements
        .insert(approval(true));
    w.proofs.push(step_up_proof());
    out.push(("allow-with-proof", w));
    let mut w = World::new();
    w.bases[0].hops[1]
        .authority
        .requirements
        .insert(approval(true));
    w.restrictions.push(deny_policy(7, false));
    out.push(("deny-overrides-require", w));
    let mut w = World::new();
    w.restrictions.push(PolicyResult {
        policy: Id([8; 16]),
        version: d(3),
        outcome: RestrictionOutcome::Require([approval(false)].into_iter().collect()),
    });
    out.push(("require-from-restriction", w));
    let mut w = World::new();
    let mut sourced = approval(false);
    sourced.source = Some(crate::model::SubjectSelector::Party(Id([42; 16])));
    w.bases[0].hops[0].authority.requirements.insert(sourced);
    w.proofs.push(step_up_proof());
    out.push(("deny-source-not-accepted", w));
    let mut w = World::new();
    w.mode = Mode::Check;
    w.bases.clear();
    out.push(("check-no-basis", w));
    let mut w = World::new();
    w.mode = Mode::Check;
    let mut revoked = hop();
    revoked.status = HopStatus::Revoked;
    let mut needs = hop();
    needs.authority.requirements.insert(approval(false));
    w.bases = vec![basis(vec![revoked]), basis(vec![needs])];
    out.push(("check-first-require", w));
    let mut w = World::new();
    w.bases.push(basis(vec![hop()]));
    out.push(("reject-commit-two-bases", w));
    out.extend(ordering_scenarios());
    out
}

// OP-114 m.2, m.5, m.11, m.13, m.14
fn ordering_scenarios() -> Vec<(&'static str, World)> {
    let mut out = Vec::new();
    let mut w = World::new();
    w.restrictions.push(deny_policy(7, false));
    w.bases[0].hops[1].status = HopStatus::Revoked;
    w.bases[0].hops[0].authority.constraints.validity.until = 40_000;
    w.capacity = Capacity::For(party(9));
    out.push(("deny-four-blocker-classes", w));
    let mut w = World::new();
    for h in &mut w.bases[0].hops {
        h.authority.requirements.insert(approval(true));
    }
    w.proofs.push(step_up_proof());
    out.push(("allow-inherited-term-counts-once", w));
    let mut w = World::new();
    for h in &mut w.bases[0].hops {
        h.authority.requirements.insert(approval(true));
    }
    out.push(("require-inherited-term-at-first-hop", w));
    let mut w = World::new();
    w.mode = Mode::Check;
    let mut needs = hop();
    needs.authority.requirements.insert(approval(false));
    needs.status = HopStatus::Revoked;
    let mut uncovered = hop();
    uncovered.authority.authority.actions.exact.clear();
    w.bases = vec![basis(vec![needs]), basis(vec![uncovered])];
    out.push(("check-deny-merges-blockers-only", w));
    let mut w = World::new();
    w.bases[0].hops[0].budgets.push(BudgetState {
        window: BudgetWindow::RollingSeconds(60),
        remaining: 0,
        demand: 1,
        resets_at: None,
    });
    out.push(("reject-rolling-budget-without-reset", w));
    let mut w = World::new();
    w.bases[0].hops[0]
        .authority
        .requirements
        .insert(approval(true));
    let mut future = step_up_proof();
    future.time = 60_000;
    w.proofs.push(future);
    out.push(("require-future-dated-proof", w));
    let mut w = World::new();
    w.mode = Mode::Check;
    w.bases.clear();
    w.restrictions.push(deny_policy(7, false));
    let mut narrow = authority();
    narrow.actions.exact.clear();
    w.mandate = Some(Mandate {
        authority: narrow,
        requirements: BTreeSet::new(),
    });
    out.push(("check-no-basis-only-no-covering", w));
    let mut w = World::new();
    w.mode = Mode::Check;
    let mut bad = hop();
    bad.budgets.push(BudgetState {
        window: BudgetWindow::RollingSeconds(60),
        remaining: 0,
        demand: 1,
        resets_at: None,
    });
    w.bases = vec![basis(vec![hop()]), basis(vec![bad])];
    out.push(("reject-check-bad-later-candidate", w));
    let mut w = World::new();
    w.proofs.push(step_up_proof());
    let mut twin = step_up_proof();
    twin.time = 2;
    w.proofs.push(twin);
    out.push(("reject-duplicate-proof-id", w));
    let mut w = World::new();
    w.bases[0].hops[0].authority.constraints.validity = Window {
        from: 60_000,
        until: 40_000,
    };
    out.push(("reject-inverted-hop-window", w));
    let mut w = World::new();
    w.intent.action.schema = d(10);
    out.push(("deny-schema-digest-mismatch", w));
    let mut w = World::new();
    w.agent = true;
    let mut zero = approval(false);
    zero.assurance.insert(HUMAN_PRESENCE.to_string(), 0);
    w.bases[0].hops[0].authority.requirements.insert(zero);
    out.push(("require-human-presence-zero-agent", w));
    let mut w = World::new();
    w.intent.validity.until = 40_000;
    out.push(("reject-intent-expired", w));
    let mut w = World::new();
    w.intent.validity.from = 60_000;
    out.push(("reject-intent-not-yet-valid", w));
    out
}

// OP-114 m.2, m.5, m.11, m.13, m.14
#[test]
fn ordering_and_merging_rules() {
    let all: BTreeMap<&str, World> = ordering_scenarios().into_iter().collect();
    let d = all["deny-four-blocker-classes"].run().unwrap();
    let classes: Vec<BlockerClass> = d.blockers.iter().map(|b| b.class).collect();
    assert_eq!(classes.len(), 4);
    let enc: Vec<Vec<u8>> = d
        .blockers
        .iter()
        .map(|b| {
            let mut one = vec![b.clone()];
            codec::order_blockers(&mut one);
            suiss_crypto::dcbor::encode(
                &codec::decision_value(&Decision {
                    outcome: Outcome::Deny,
                    blockers: one,
                    unmet: Vec::new(),
                    relied_on: Vec::new(),
                }),
                suiss_crypto::dcbor::Limits::CEILING,
            )
            .unwrap()
        })
        .collect();
    let mut sorted = enc.clone();
    sorted.sort();
    assert_eq!(enc, sorted);

    let d = all["allow-inherited-term-counts-once"].run().unwrap();
    assert_eq!((d.outcome, d.relied_on.len()), (Outcome::Allow, 1));
    let d = all["require-inherited-term-at-first-hop"].run().unwrap();
    assert_eq!(d.outcome, Outcome::RequireAction);
    assert_eq!(
        d.unmet.iter().map(|u| u.position).collect::<Vec<_>>(),
        vec![Position::Hop(0)]
    );
    let d = all["require-future-dated-proof"].run().unwrap();
    assert_eq!(d.outcome, Outcome::RequireAction);
    let d = all["check-no-basis-only-no-covering"].run().unwrap();
    assert_eq!(
        d.blockers.iter().map(|b| b.class).collect::<Vec<_>>(),
        vec![BlockerClass::NoCoveringAuthority]
    );
    let d = all["check-deny-merges-blockers-only"].run().unwrap();
    assert_eq!((d.outcome, d.unmet.len()), (Outcome::Deny, 0));
    assert_eq!(d.blockers.len(), 2);
    assert_eq!(
        all["reject-duplicate-proof-id"].run(),
        Err(Rejection::Input)
    );
    let d = all["deny-schema-digest-mismatch"].run().unwrap();
    assert!(
        d.blockers
            .iter()
            .all(|b| b.class == BlockerClass::NoCoveringAuthority)
    );
    let d = all["require-human-presence-zero-agent"].run().unwrap();
    assert!(d.unmet.iter().all(|u| u.satisfiable_by_actor));
    for id in [
        "reject-check-bad-later-candidate",
        "reject-rolling-budget-without-reset",
        "reject-intent-expired",
        "reject-intent-not-yet-valid",
    ] {
        assert_eq!(all[id].run(), Err(Rejection::Input), "{id}");
    }
}

// CR-49, OP-111 m.1: the CBOR bridge for the F0 reference evaluator
#[test]
fn decision_vectors_match() {
    extern crate std;
    use crate::codec::Canonical;
    use core::fmt::Write as _;
    use suiss_crypto::dcbor::{Limits, encode};
    let hex = |b: &[u8]| {
        b.iter().fold(String::new(), |mut h, x| {
            let _ = write!(h, "{x:02x}");
            h
        })
    };
    let mut json = String::from(
        "{\n \"rule\": \"OP-111\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"combinator.evaluate\",\n \"fuel\": 10000,\n \"cases\": [\n",
    );
    let all = scenarios();
    for (i, (id, w)) in all.iter().enumerate() {
        let owned = w.owned();
        let input = owned.to_bytes().unwrap();
        let Ok(back) = codec::OwnedInput::from_bytes(&input) else {
            let sep = if i + 1 == all.len() { "" } else { "," };
            let _ = writeln!(
                json,
                "  {{\"id\": \"{id}\", \"input\": \"{}\", \"rejection\": \"input\"}}{sep}",
                hex(&input)
            );
            continue;
        };
        assert_eq!(back.to_bytes().unwrap(), input, "{id}");
        let expect = match evaluate(&back.input(), &mut Fuel(10_000)) {
            Ok(dec) => {
                assert_eq!(Ok(dec.clone()), w.run(), "{id}");
                format!(
                    "\"decision\": \"{}\"",
                    hex(&encode(&codec::decision_value(&dec), Limits::CEILING).unwrap())
                )
            }
            Err(Rejection::Input) => "\"rejection\": \"input\"".to_string(),
            Err(Rejection::Fuel) => "\"rejection\": \"fuel\"".to_string(),
            Err(Rejection::Limit) => "\"rejection\": \"limit\"".to_string(),
        };
        let sep = if i + 1 == all.len() { "" } else { "," };
        let _ = writeln!(
            json,
            "  {{\"id\": \"{id}\", \"input\": \"{}\", {expect}}}{sep}",
            hex(&input)
        );
    }
    json.push_str(" ]\n}\n");
    #[cfg(not(target_os = "wasi"))]
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../conformance/vectors/core/1/decision.json"
            ),
            &json,
        )
        .unwrap();
        return;
    }
    assert_eq!(
        include_str!("../../../../conformance/vectors/core/1/decision.json"),
        json
    );
}

enum Cve {
    Evaluate(World, Outcome, Option<BlockerClass>),
    Delegate {
        child: CanonicalAuthority,
        parent: CanonicalAuthority,
        holder: SubjectSelector,
        within: bool,
    },
}

fn party(n: u8) -> Id {
    Id([n; 16])
}

fn delegate(child: CanonicalAuthority, holder: SubjectSelector, within: bool) -> Cve {
    Cve::Delegate {
        child,
        parent: hop().authority,
        holder,
        within,
    }
}

fn leaf() -> CanonicalAuthority {
    let mut c = hop().authority;
    c.delegation.depth = 0;
    c
}

fn with_recipient(sel: &SubjectSelector, recipient: u8, allow: bool) -> Cve {
    let mut w = World::new();
    for h in &mut w.bases[0].hops {
        h.authority.authority.recipient = Some(sel.clone());
    }
    w.intent.recipient = Some(party(recipient));
    if allow {
        Cve::Evaluate(w, Outcome::Allow, None)
    } else {
        Cve::Evaluate(w, Outcome::Deny, Some(BlockerClass::NoCoveringAuthority))
    }
}

fn pinned_catalog(pin: u8) -> World {
    let mut w = World::new();
    let capture = ActionRef {
        name: "capture".to_string(),
        ..action()
    };
    w.catalog
        .catalogs
        .insert(d(20), [capture.clone()].into_iter().collect());
    w.catalog
        .catalogs
        .insert(d(21), [capture, action()].into_iter().collect());
    for h in &mut w.bases[0].hops {
        h.authority.authority.actions = ActionSet {
            exact: BTreeSet::new(),
            prefix: [("pay".to_string(), d(pin))].into_iter().collect(),
        };
    }
    w
}

const WILDCARD: &[&str] = &["CVE-2022-39341"];
const MIXED: &[&str] = &["CVE-2026-24851", "CVE-2025-25196", "CVE-2025-48371"];
const CONDITION: &[&str] = &["CVE-2025-64751"];
const NESTED: &[&str] = &["CVE-2026-61709", "GHSA-h7w8-xr72-cv4r"];
const PINNED: &[&str] = &["CVE-2022-23542"];
const IMPERSONATION: &[&str] = &["CVE-2026-17526", "CVE-2026-109374"];

fn cve_cases() -> Vec<(&'static str, &'static [&'static str], Cve)> {
    let mut out: Vec<(&'static str, &'static [&'static str], Cve)> = Vec::new();
    out.push((
        "delegate-to-party",
        WILDCARD,
        delegate(leaf(), SubjectSelector::Party(party(2)), true),
    ));
    let mut c = hop().authority;
    c.delegation.depth = 0;
    out.push((
        "delegate-to-public-leaf",
        WILDCARD,
        delegate(c, SubjectSelector::Public, true),
    ));
    let mut c = hop().authority;
    c.delegation.depth = 0;
    let mut p = hop().authority;
    p.delegation.depth = 2;
    c.delegation.depth = 1;
    out.push((
        "delegate-onward-to-public",
        WILDCARD,
        Cve::Delegate {
            child: c,
            parent: p,
            holder: SubjectSelector::Public,
            within: false,
        },
    ));
    let mut p = hop().authority;
    p.delegation.downstream_holder_class = Some(SubjectSelector::Public);
    out.push((
        "delegate-public-holder-class",
        WILDCARD,
        Cve::Delegate {
            child: leaf(),
            parent: p,
            holder: SubjectSelector::Party(party(2)),
            within: false,
        },
    ));

    let mut p = hop().authority;
    p.constraints
        .conditions
        .insert(WhileCondition::InstanceAlive(party(8)));
    let mut kept = leaf();
    kept.constraints
        .conditions
        .insert(WhileCondition::InstanceAlive(party(8)));
    out.push((
        "delegate-keeps-condition",
        CONDITION,
        Cve::Delegate {
            child: kept,
            parent: p.clone(),
            holder: SubjectSelector::Party(party(2)),
            within: true,
        },
    ));
    out.push((
        "delegate-drops-condition",
        CONDITION,
        Cve::Delegate {
            child: leaf(),
            parent: p,
            holder: SubjectSelector::Party(party(2)),
            within: false,
        },
    ));

    out.extend(cve_evaluation_cases());
    out
}

fn cve_evaluation_cases() -> Vec<(&'static str, &'static [&'static str], Cve)> {
    let mut out: Vec<(&'static str, &'static [&'static str], Cve)> = Vec::new();
    out.push((
        "recipient-party-same",
        MIXED,
        with_recipient(&SubjectSelector::Party(party(5)), 5, true),
    ));
    out.push((
        "recipient-party-other",
        MIXED,
        with_recipient(&SubjectSelector::Party(party(5)), 6, false),
    ));
    let pred = SubjectSelector::Pred(
        [crate::model::Conjunct {
            claim_class: "employee".to_string(),
            value: None,
        }]
        .into_iter()
        .collect(),
    );
    out.push((
        "recipient-pred-not-party",
        MIXED,
        with_recipient(&pred, 5, false),
    ));
    let foreign = SubjectSelector::Foreign {
        domain: d(30),
        class: "auditor".to_string(),
    };
    out.push((
        "recipient-foreign-not-party",
        MIXED,
        with_recipient(&foreign, 5, false),
    ));

    let mut w = World::new();
    w.restrictions.push(deny_policy(7, false));
    out.push((
        "exclusion-over-covering-grant",
        &["CVE-2022-21646"],
        Cve::Evaluate(w, Outcome::Deny, Some(BlockerClass::Restricted)),
    ));
    let mut w = World::new();
    w.restrictions = vec![deny_policy(7, false), deny_policy(8, false)];
    out.push((
        "two-exclusions",
        NESTED,
        Cve::Evaluate(w, Outcome::Deny, Some(BlockerClass::Restricted)),
    ));
    let mut w = World::new();
    w.restrictions = vec![deny_policy(8, false), deny_policy(7, false)];
    out.push((
        "two-exclusions-reordered",
        NESTED,
        Cve::Evaluate(w, Outcome::Deny, Some(BlockerClass::Restricted)),
    ));

    let mut w = World::new();
    w.bases[0].hops[0].authority.constraints.validity.until = 40_000;
    out.push((
        "expired-invitation",
        &["CVE-2025-64708"],
        Cve::Evaluate(w, Outcome::Deny, Some(BlockerClass::Ended)),
    ));
    let mut w = World::new();
    w.bases[0].hops[0].budgets.push(BudgetState {
        window: BudgetWindow::Total,
        remaining: 0,
        demand: 1,
        resets_at: None,
    });
    out.push((
        "invitation-reused",
        &["CVE-2022-23555"],
        Cve::Evaluate(w, Outcome::Deny, Some(BlockerClass::BudgetExhausted)),
    ));

    out.extend(cve_capacity_cases());
    out
}

fn cve_capacity_cases() -> Vec<(&'static str, &'static [&'static str], Cve)> {
    let mut out: Vec<(&'static str, &'static [&'static str], Cve)> = Vec::new();
    out.push((
        "prefix-current-catalog",
        PINNED,
        Cve::Evaluate(pinned_catalog(21), Outcome::Allow, None),
    ));
    out.push((
        "prefix-old-catalog",
        PINNED,
        Cve::Evaluate(
            pinned_catalog(20),
            Outcome::Deny,
            Some(BlockerClass::NoCoveringAuthority),
        ),
    ));

    let mut w = World::new();
    w.capacity = Capacity::For(party(9));
    out.push((
        "impersonate-admin",
        IMPERSONATION,
        Cve::Evaluate(w, Outcome::Deny, Some(BlockerClass::CapacityMismatch)),
    ));
    let mut wider = leaf();
    wider.authority.actions.exact.insert(ActionRef {
        name: "admin".to_string(),
        ..action()
    });
    out.push((
        "delegate-above-own-authority",
        IMPERSONATION,
        delegate(wider, SubjectSelector::Party(party(2)), false),
    ));
    out
}

// CR-57, §6.2, CR-49 m.4
#[test]
fn cve_regression_vectors_match() {
    extern crate std;
    use crate::codec::Canonical;
    use core::fmt::Write as _;
    use suiss_crypto::dcbor::{Limits, encode};
    let hex = |b: &[u8]| {
        b.iter().fold(String::new(), |mut h, x| {
            let _ = write!(h, "{x:02x}");
            h
        })
    };
    let mut json = String::from(
        "{\n \"rule\": \"CR-57\",\n \"track\": \"core\",\n \"version\": 1,\n \"fuel\": 10000,\n \"cases\": [\n",
    );
    let all = cve_cases();
    let mut decisions = BTreeMap::new();
    for (i, (id, cves, case)) in all.iter().enumerate() {
        let refs = cves
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let body = match case {
            Cve::Evaluate(w, outcome, class) => {
                let dec = w.run().unwrap();
                assert_eq!(dec.outcome, *outcome, "{id}");
                assert_eq!(dec.blockers.first().map(|b| b.class), *class, "{id}");
                let bytes = encode(&codec::decision_value(&dec), Limits::CEILING).unwrap();
                decisions.insert(*id, bytes.clone());
                format!(
                    "\"operation\": \"combinator.evaluate\", \"input\": \"{}\", \"decision\": \"{}\"",
                    hex(&w.owned().to_bytes().unwrap()),
                    hex(&bytes)
                )
            }
            Cve::Delegate {
                child,
                parent,
                holder,
                within,
            } => {
                let cat = Catalog::default();
                assert_eq!(
                    crate::algebra::child_within_parent(child, parent, holder, &cat),
                    *within,
                    "{id}"
                );
                format!(
                    "\"operation\": \"algebra.child_within_parent\", \"child\": \"{}\", \"parent\": \"{}\", \"holder\": \"{}\", \"within\": {within}",
                    hex(&child.to_bytes().unwrap()),
                    hex(&parent.to_bytes().unwrap()),
                    hex(&holder.to_bytes().unwrap()),
                )
            }
        };
        let sep = if i + 1 == all.len() { "" } else { "," };
        let _ = writeln!(
            json,
            "  {{\"id\": \"{id}\", \"cve\": [{refs}], {body}}}{sep}"
        );
    }
    json.push_str(" ]\n}\n");
    assert_eq!(
        decisions.get("two-exclusions"),
        decisions.get("two-exclusions-reordered")
    );
    #[cfg(not(target_os = "wasi"))]
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../conformance/vectors/core/1/cve-regressions.json"
            ),
            &json,
        )
        .unwrap();
        return;
    }
    assert_eq!(
        include_str!("../../../../conformance/vectors/core/1/cve-regressions.json"),
        json
    );
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next().checked_rem(n).unwrap_or(0)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

fn random_hop(r: &mut Rng) -> Hop {
    let mut h = hop();
    if r.chance(10) {
        h.authority.authority.actions.exact.clear();
    }
    match r.below(10) {
        0 => h.authority.constraints.validity.until = 40_000,
        1 => h.authority.constraints.validity.from = 60_000,
        _ => {}
    }
    h.status = match r.below(12) {
        0 => HopStatus::Revoked,
        1 => HopStatus::Lapsed,
        _ => HopStatus::Active,
    };
    h.conditions_hold = !r.chance(8);
    if r.chance(20) {
        let rolling = r.chance(50);
        h.budgets.push(BudgetState {
            window: if rolling {
                BudgetWindow::RollingSeconds(60)
            } else {
                BudgetWindow::Total
            },
            remaining: r.below(3),
            demand: 1,
            resets_at: (rolling && !r.chance(10)).then_some(70_000),
        });
    }
    if r.chance(10) {
        h.authority.authority.recipient = Some(SubjectSelector::Party(party(5)));
    }
    if r.chance(25) {
        h.authority.requirements.insert(approval(r.chance(50)));
    }
    h
}

fn random_world(r: &mut Rng) -> World {
    let mut w = World::new();
    w.mode = match r.below(5) {
        0 => Mode::Check,
        1 => Mode::Continue,
        _ => Mode::Commit,
    };
    let bases = if w.mode == Mode::Check { r.below(4) } else { 1 };
    w.bases = (0..bases)
        .map(|_| {
            let mut b = basis((0..=r.below(4)).map(|_| random_hop(r)).collect());
            if r.chance(50) {
                b.capacities.insert(Capacity::For(party(9)));
            }
            b
        })
        .collect();
    if r.chance(50) {
        w.intent.recipient = Some(party(5));
    }
    for n in 0..r.below(3) {
        let id = u8::try_from(n).unwrap().checked_add(7).unwrap();
        w.restrictions.push(match r.below(3) {
            0 => deny_policy(id, r.chance(30)),
            1 => PolicyResult {
                policy: Id([id; 16]),
                version: d(2),
                outcome: RestrictionOutcome::Require(
                    [approval(r.chance(50))].into_iter().collect(),
                ),
            },
            _ => PolicyResult {
                policy: Id([id; 16]),
                version: d(2),
                outcome: RestrictionOutcome::NoObjection,
            },
        });
    }
    for n in 0..r.below(3) {
        let mut p = step_up_proof();
        p.id = Id([u8::try_from(n).unwrap().checked_add(3).unwrap(); 16]);
        p.consumed = r.chance(20);
        p.time = [1, 49_999, 60_000][usize::try_from(r.below(3)).unwrap()];
        if r.chance(20) {
            p.assurance.clear();
        }
        w.proofs.push(p);
    }
    if r.chance(10) {
        w.capacity = Capacity::For(party(9));
    }
    if r.chance(25) {
        let mut a = authority();
        if r.chance(30) {
            a.actions.exact.clear();
        }
        w.mandate = Some(Mandate {
            authority: a,
            requirements: BTreeSet::new(),
        });
    }
    w.agent = r.chance(30);
    w
}

// OP-112 m.4: random inputs for the nightly Kernel ↔ F0 differential run
#[test]
#[ignore = "nightly: set ACCESS_RANDOM_VECTORS to an output directory"]
fn random_inputs_for_f0() {
    extern crate std;
    use crate::codec::Canonical;
    use core::fmt::Write as _;
    use suiss_crypto::dcbor::{Limits, encode};
    let Some(dir) = std::env::var_os("ACCESS_RANDOM_VECTORS") else {
        return;
    };
    let count: u64 = std::env::var("ACCESS_RANDOM_COUNT")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(10_000);
    let seed: u64 = std::env::var("ACCESS_RANDOM_SEED")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0x005e_edac_ce55)
        | 1;
    let mut r = Rng(seed);
    let mut json = format!(
        "{{\n \"rule\": \"OP-112\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"combinator.evaluate\",\n \"seed\": {seed},\n \"fuel\": 10000,\n \"cases\": [\n"
    );
    for i in 0..count {
        let w = random_world(&mut r);
        let input = w.owned().to_bytes().unwrap();
        let back = codec::OwnedInput::from_bytes(&input).unwrap();
        let expect = match evaluate(&back.input(), &mut Fuel(10_000)) {
            Ok(dec) => format!(
                "\"decision\": \"{}\"",
                hex_of(&encode(&codec::decision_value(&dec), Limits::CEILING).unwrap())
            ),
            Err(Rejection::Input) => "\"rejection\": \"input\"".to_string(),
            Err(Rejection::Fuel) => "\"rejection\": \"fuel\"".to_string(),
            Err(Rejection::Limit) => "\"rejection\": \"limit\"".to_string(),
        };
        let sep = if i + 1 == count { "" } else { "," };
        let _ = writeln!(
            json,
            "  {{\"id\": \"random-{i}\", \"input\": \"{}\", {expect}}}{sep}",
            hex_of(&input)
        );
    }
    json.push_str(" ]\n}\n");
    let path = std::path::PathBuf::from(dir).join("core/1");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("random.json"), json).unwrap();
}

fn hex_of(b: &[u8]) -> String {
    use core::fmt::Write as _;
    b.iter().fold(String::new(), |mut h, x| {
        let _ = write!(h, "{x:02x}");
        h
    })
}
