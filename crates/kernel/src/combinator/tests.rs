use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::intent::ContextRefs;
use crate::model::{
    ActionRef, ActionSet, Binding, BudgetWindow, ConstraintSet, Consumption, DelegationTerms,
    Independence, ProofKind, ResourceRef, ResourceSelector, Structural, Window,
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
    out
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
        let back = codec::OwnedInput::from_bytes(&input).unwrap();
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
