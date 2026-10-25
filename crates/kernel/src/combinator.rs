//! Decision Combinator (§5.8, §9.6, OP-111): deny-overrides, no UNKNOWN (INV-26).

pub mod codec;

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::algebra::Catalog;
use crate::codec::Stored;
use crate::digest::Digest;
use crate::intent::{IntentEnvelope, covers};
use crate::model::{
    AuthoritySet, BudgetWindow, CanonicalAuthority, Id, RequirementTerm, TrustedTime,
};
use crate::requirement::{self, HUMAN_PRESENCE, Outcome as TermOutcome, Proof, check_assurance};
use crate::restriction::RestrictionOutcome;

/// Step budget (OP-108 m.11, OP-111 m.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fuel(pub u64);

impl Fuel {
    /// Spends `n` steps.
    ///
    /// # Errors
    /// [`Rejection::Fuel`] when the budget is exhausted.
    pub fn spend(&mut self, n: u64) -> Result<(), Rejection> {
        self.0 = self.0.checked_sub(n).ok_or(Rejection::Fuel)?;
        Ok(())
    }
}

/// A protocol rejection: not a decision, nothing is recorded (OP-108 m.3, m.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    /// Step budget exhausted.
    #[error("step budget exhausted")]
    Fuel,
    /// Input outside the contract (e.g. `commit` without a basis).
    #[error("malformed input")]
    Input,
    /// Lineage deeper than [`MAX_LINEAGE`] (OP-108 m.10, SI-20).
    #[error("lineage too deep")]
    Limit,
}

/// Maximum lineage depth on the Kernel and commit paths (OP-108 m.10).
pub const MAX_LINEAGE: usize = 16;

/// Evaluation mode (§9.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Relied-upon decision.
    Commit,
    /// Continuation of an exercise.
    Continue,
    /// Advisory; not recorded.
    Check,
}

/// Exercise capacity (§9.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capacity {
    /// For oneself.
    Own,
    /// On behalf of a party.
    For(Id),
}

/// State of one lineage hop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HopStatus {
    /// In force.
    Active,
    /// Revoked.
    Revoked,
    /// A while-condition no longer holds.
    Lapsed,
}

/// Budget state of one term on a hop; the demand comes from the action schema (OP-111 m.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetState {
    /// Window of the term.
    pub window: BudgetWindow,
    /// Remaining capacity.
    pub remaining: u64,
    /// This intent's demand.
    pub demand: u64,
    /// When a rolling window frees capacity again.
    pub resets_at: Option<TrustedTime>,
}

/// One lineage hop; index 0 is the basis grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    /// The grant's canonical authority.
    pub authority: CanonicalAuthority,
    /// Status.
    pub status: HopStatus,
    /// Whether every while-condition holds now.
    pub conditions_hold: bool,
    /// Budget states.
    pub budgets: Vec<BudgetState>,
}

/// A candidate basis: hops from the basis grant to the root, and the capacities its agency terms allow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Basis {
    /// Hops; never empty. A stored grant the reading layer did not understand covers nothing
    /// (OP-108 m.4, OP-118 m.2).
    pub hops: Vec<Stored<Hop>>,
    /// Allowed capacities.
    pub capacities: BTreeSet<Capacity>,
}

/// Actor instance limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mandate {
    /// What the instance may do.
    pub authority: AuthoritySet,
    /// What it must present.
    pub requirements: BTreeSet<RequirementTerm>,
}

/// One restriction policy's outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyResult {
    /// Policy.
    pub policy: Id,
    /// Policy version digest.
    pub version: Digest,
    /// Outcome.
    pub outcome: RestrictionOutcome,
}

/// Prepared evaluation input (OP-111 m.1).
#[derive(Clone, Debug)]
pub struct EvaluationInput<'a> {
    /// Mode.
    pub mode: Mode,
    /// Intent.
    pub intent: &'a IntentEnvelope,
    /// Access-computed intent digest.
    pub intent_digest: Digest,
    /// Trusted time.
    pub now: TrustedTime,
    /// Actor instance, if authenticated.
    pub actor_instance: Option<Id>,
    /// Whether the actor instance is an agent.
    pub actor_is_agent: bool,
    /// Instance limits.
    pub mandate: Option<&'a Mandate>,
    /// Declared capacity.
    pub capacity: Capacity,
    /// Declared basis (`commit`, `continue`) or candidates (`check`).
    pub bases: &'a [Basis],
    /// Restriction outcomes.
    pub restrictions: &'a [PolicyResult],
    /// Presented proofs.
    pub proofs: &'a [Proof],
    /// Catalog view.
    pub catalog: &'a Catalog,
}

/// Decision outcome (§9.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Allowed.
    Allow,
    /// Denied.
    Deny,
    /// Allowed once the unmet requirements are presented.
    RequireAction,
}

/// Blocker class, closed set (§9.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockerClass {
    /// `no-covering-authority`.
    NoCoveringAuthority,
    /// `outside-instance-limits`.
    OutsideInstanceLimits,
    /// `restricted`.
    Restricted,
    /// `budget-exhausted`.
    BudgetExhausted,
    /// `ended`.
    Ended,
    /// `capacity-mismatch`.
    CapacityMismatch,
    /// `source-not-accepted`.
    SourceNotAccepted,
    /// `schema-not-accepted`.
    SchemaNotAccepted,
    /// `nonce-closed`.
    NonceClosed,
    /// `foreign-status-unavailable`.
    ForeignStatusUnavailable,
}

/// Where a blocker sits (§9.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Position {
    /// Actor mandate.
    Instance,
    /// Lineage hop `k` (0 = basis grant).
    Hop(u64),
    /// Anchor root terms.
    Anchor,
    /// Restriction policy.
    DomainPolicy,
    /// Foreign domain.
    Foreign,
    /// Actor side.
    ActorSide,
}

/// Who can remove a blocker (§9.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Resolver {
    /// Grantor of hop `k`.
    GrantorOfHop(u64),
    /// Root.
    Root,
    /// Restriction owner.
    RestrictionOwner,
    /// Issuer.
    Issuer,
    /// Domain admin.
    DomainAdmin,
    /// Actor.
    Actor,
    /// Actor's party.
    ActorParty,
    /// Time.
    Time,
}

/// Typed remediation (§9.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Remediation {
    /// `route-to-coordinator`.
    RouteToCoordinator,
    /// `refresh-claim`.
    RefreshClaim,
    /// `self-authenticate`.
    SelfAuthenticate,
    /// `wait-until(T)`.
    WaitUntil(TrustedTime),
    /// `not-satisfiable-by-actor`.
    NotSatisfiableByActor,
    /// `new-request-required`.
    NewRequestRequired,
}

/// One blocker of a DENY (§9.6).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Blocker {
    /// Class.
    pub class: BlockerClass,
    /// Namespaced subcode.
    pub subcode: Option<String>,
    /// Position.
    pub position: Position,
    /// Resolver.
    pub resolver: Resolver,
    /// Remediation.
    pub remediation: Remediation,
}

/// One unmet requirement of a `REQUIRE_ACTION`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Unmet {
    /// The term.
    pub term: RequirementTerm,
    /// Proofs still missing.
    pub missing: u64,
    /// Where it comes from.
    pub position: Position,
    /// Whether the actor can satisfy it.
    pub satisfiable_by_actor: bool,
}

/// A decision; blockers and unmet terms are sorted for determinism (OP-108 m.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// Outcome.
    pub outcome: Outcome,
    /// Blockers (DENY).
    pub blockers: Vec<Blocker>,
    /// Unmet requirements.
    pub unmet: Vec<Unmet>,
    /// Proofs relied on, if allowed.
    pub relied_on: Vec<Id>,
}

fn blocker(
    class: BlockerClass,
    subcode: Option<&str>,
    position: Position,
    resolver: Resolver,
    remediation: Remediation,
) -> Blocker {
    Blocker {
        class,
        subcode: subcode.map(String::from),
        position,
        resolver,
        remediation,
    }
}

fn hop_blockers(
    k: u64,
    hop: &Hop,
    input: &EvaluationInput<'_>,
    out: &mut Vec<Blocker>,
) -> Result<(), Rejection> {
    let at = Position::Hop(k);
    let grantor = Resolver::GrantorOfHop(k);
    if !covers(&hop.authority.authority, input.intent, input.catalog) {
        out.push(blocker(
            BlockerClass::NoCoveringAuthority,
            None,
            at,
            grantor,
            Remediation::RouteToCoordinator,
        ));
    }
    let validity = hop.authority.constraints.validity;
    if input.now < validity.from {
        out.push(blocker(
            BlockerClass::Ended,
            Some("ended/expired"),
            at,
            Resolver::Time,
            Remediation::WaitUntil(validity.from),
        ));
    } else if input.now > validity.until {
        out.push(blocker(
            BlockerClass::Ended,
            Some("ended/expired"),
            at,
            grantor,
            Remediation::NewRequestRequired,
        ));
    }
    match hop.status {
        HopStatus::Active => {}
        HopStatus::Revoked => {
            out.push(blocker(
                BlockerClass::Ended,
                Some("ended/revoked"),
                at,
                grantor,
                Remediation::NewRequestRequired,
            ));
        }
        HopStatus::Lapsed => {
            out.push(blocker(
                BlockerClass::Ended,
                Some("ended/lapsed"),
                at,
                grantor,
                Remediation::NewRequestRequired,
            ));
        }
    }
    if !hop.conditions_hold && hop.status != HopStatus::Lapsed {
        out.push(blocker(
            BlockerClass::Ended,
            Some("ended/lapsed"),
            at,
            grantor,
            Remediation::NewRequestRequired,
        ));
    }
    for b in &hop.budgets {
        if b.demand > b.remaining {
            out.push(match (b.window, b.resets_at) {
                (BudgetWindow::RollingSeconds(_), Some(t)) => blocker(
                    BlockerClass::BudgetExhausted,
                    None,
                    at,
                    Resolver::Time,
                    Remediation::WaitUntil(t),
                ),
                // OP-114 m.11
                (BudgetWindow::RollingSeconds(_), None) => return Err(Rejection::Input),
                (BudgetWindow::Total, _) => blocker(
                    BlockerClass::BudgetExhausted,
                    None,
                    at,
                    grantor,
                    Remediation::RouteToCoordinator,
                ),
            });
        }
    }
    Ok(())
}

fn mandate_and_restrictions(
    input: &EvaluationInput<'_>,
    fuel: &mut Fuel,
    blockers: &mut Vec<Blocker>,
    terms: &mut Vec<(RequirementTerm, Position)>,
) -> Result<(), Rejection> {
    if let Some(m) = input.mandate {
        if !covers(&m.authority, input.intent, input.catalog) {
            blockers.push(blocker(
                BlockerClass::OutsideInstanceLimits,
                None,
                Position::Instance,
                Resolver::ActorParty,
                Remediation::RouteToCoordinator,
            ));
        }
        terms.extend(
            m.requirements
                .iter()
                .map(|t| (t.clone(), Position::Instance)),
        );
    }
    for r in input.restrictions {
        fuel.spend(1)?;
        match &r.outcome {
            RestrictionOutcome::NoObjection => {}
            RestrictionOutcome::Deny(_) => blockers.push(Blocker {
                class: BlockerClass::Restricted,
                subcode: Some(policy_subcode(&r.policy)),
                position: Position::DomainPolicy,
                resolver: Resolver::RestrictionOwner,
                remediation: Remediation::NotSatisfiableByActor,
            }),
            RestrictionOutcome::Require(req) => {
                terms.extend(req.iter().map(|t| (t.clone(), Position::DomainPolicy)));
            }
        }
    }
    Ok(())
}

fn evaluate_basis(
    basis: &Basis,
    input: &EvaluationInput<'_>,
    fuel: &mut Fuel,
) -> Result<Decision, Rejection> {
    if basis.hops.is_empty() {
        return Err(Rejection::Input);
    }
    if basis.hops.len() > MAX_LINEAGE {
        return Err(Rejection::Limit);
    }
    let mut blockers = Vec::new();
    let mut terms: Vec<(RequirementTerm, Position)> = Vec::new();
    for (k, hop) in basis.hops.iter().enumerate() {
        fuel.spend(1)?;
        let k = u64::try_from(k).map_err(|_| Rejection::Input)?;
        let Stored::Known(hop) = hop else {
            // OP-118 m.2
            blockers.push(blocker(
                BlockerClass::NoCoveringAuthority,
                None,
                Position::Hop(k),
                Resolver::GrantorOfHop(k),
                Remediation::RouteToCoordinator,
            ));
            continue;
        };
        hop_blockers(k, hop, input, &mut blockers)?;
        terms.extend(
            hop.authority
                .requirements
                .iter()
                .map(|t| (t.clone(), Position::Hop(k))),
        );
    }
    if !basis.capacities.contains(&input.capacity) {
        blockers.push(blocker(
            BlockerClass::CapacityMismatch,
            None,
            Position::Hop(0),
            Resolver::Actor,
            Remediation::NewRequestRequired,
        ));
    }
    mandate_and_restrictions(input, fuel, &mut blockers, &mut terms)?;
    let unique: BTreeSet<RequirementTerm> = terms.iter().map(|(t, _)| t.clone()).collect();
    let ctx = requirement::Context {
        now: input.now,
        actor_instance: input.actor_instance,
        intent_digest: &input.intent_digest,
        resources: &input.intent.resources,
    };
    let resolved = requirement::resolve(&unique, input.proofs, &ctx, fuel)?;
    let mut unmet = Vec::new();
    let mut relied_on = BTreeSet::new();
    for (term, outcome) in resolved {
        match outcome {
            TermOutcome::Satisfied(ids) => relied_on.extend(ids),
            TermOutcome::Unmet(missing) => {
                if requirement::source_rejected(&term, input.proofs) {
                    blockers.push(blocker(
                        BlockerClass::SourceNotAccepted,
                        None,
                        Position::ActorSide,
                        Resolver::Issuer,
                        Remediation::RefreshClaim,
                    ));
                }
                let position = terms
                    .iter()
                    .find(|(t, _)| *t == term)
                    .map_or(Position::ActorSide, |(_, p)| *p);
                let satisfiable_by_actor = !(input.actor_is_agent
                    && term.assurance.get(HUMAN_PRESENCE).is_some_and(|v| *v > 0));
                unmet.push(Unmet {
                    term,
                    missing,
                    position,
                    satisfiable_by_actor,
                });
            }
        }
    }
    codec::order_blockers(&mut blockers);
    codec::order_unmet(&mut unmet);
    let outcome = if !blockers.is_empty() {
        Outcome::Deny
    } else if !unmet.is_empty() {
        Outcome::RequireAction
    } else {
        Outcome::Allow
    };
    let relied_on = if outcome == Outcome::Allow {
        relied_on.into_iter().collect()
    } else {
        Vec::new()
    };
    Ok(Decision {
        outcome,
        blockers,
        unmet,
        relied_on,
    })
}

fn known_hops(basis: &Basis) -> impl Iterator<Item = &Hop> {
    basis.hops.iter().filter_map(|h| match h {
        Stored::Known(h) => Some(h),
        Stored::NotUnderstood => None,
    })
}

fn assurance_known(input: &EvaluationInput<'_>) -> bool {
    let hops = input
        .bases
        .iter()
        .flat_map(known_hops)
        .flat_map(|h| &h.authority.requirements);
    let mandate = input.mandate.into_iter().flat_map(|m| &m.requirements);
    let restrictions = input
        .restrictions
        .iter()
        .filter_map(|r| match &r.outcome {
            RestrictionOutcome::Require(t) => Some(t),
            RestrictionOutcome::NoObjection | RestrictionOutcome::Deny(_) => None,
        })
        .flatten();
    hops.chain(mandate)
        .chain(restrictions)
        .map(|t| &t.assurance)
        .chain(input.proofs.iter().map(|p| &p.assurance))
        .all(|a| check_assurance(a).is_ok())
}

fn policy_subcode(policy: &Id) -> String {
    let mut s = String::from("restricted/policy:");
    s.push_str(&crate::json::b64url_encode(&policy.0));
    s
}

/// Evaluates an intent (OP-111 m.6, m.8).
///
/// # Errors
/// [`Rejection`]: not a decision, nothing is recorded.
pub fn evaluate(input: &EvaluationInput<'_>, fuel: &mut Fuel) -> Result<Decision, Rejection> {
    // OP-114 m.13
    let window = input.intent.validity;
    if input.now < window.from || input.now > window.until {
        return Err(Rejection::Input);
    }
    // OP-117 m.7
    let ids: BTreeSet<Id> = input.proofs.iter().map(|p| p.id).collect();
    if ids.len() != input.proofs.len() {
        return Err(Rejection::Input);
    }
    // OP-118 m.3
    if !assurance_known(input) {
        return Err(Rejection::Input);
    }
    // OP-114 m.11
    let unresettable = |b: &BudgetState| {
        matches!(b.window, BudgetWindow::RollingSeconds(_))
            && b.resets_at.is_none()
            && b.demand > b.remaining
    };
    if input
        .bases
        .iter()
        .flat_map(known_hops)
        .flat_map(|hop| &hop.budgets)
        .any(unresettable)
    {
        return Err(Rejection::Input);
    }
    match input.mode {
        Mode::Commit | Mode::Continue => match input.bases {
            [basis] => Ok(evaluate_basis(basis, input, fuel)?),
            _ => Err(Rejection::Input),
        },
        Mode::Check => {
            let mut denied: Vec<Blocker> = Vec::new();
            let mut first_require: Option<Decision> = None;
            for basis in input.bases {
                let d = evaluate_basis(basis, input, fuel)?;
                match d.outcome {
                    Outcome::Allow => return Ok(d),
                    Outcome::RequireAction => {
                        if first_require.is_none() {
                            first_require = Some(d);
                        }
                    }
                    Outcome::Deny => denied.extend(d.blockers),
                }
            }
            if let Some(d) = first_require {
                return Ok(d);
            }
            if denied.is_empty() {
                denied.push(blocker(
                    BlockerClass::NoCoveringAuthority,
                    None,
                    Position::Hop(0),
                    Resolver::GrantorOfHop(0),
                    Remediation::RouteToCoordinator,
                ));
            }
            codec::order_blockers(&mut denied);
            Ok(Decision {
                outcome: Outcome::Deny,
                blockers: denied,
                unmet: Vec::new(),
                relied_on: Vec::new(),
            })
        }
    }
}

#[cfg(test)]
mod tests;
