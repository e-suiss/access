//! Canonical form of the evaluation input and the decision (`kernel.cddl`, OP-111 m.1). This is the
//! CBOR bridge between the Kernel and the F0 reference evaluator (CR-49).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use suiss_crypto::dcbor::Value;

use super::{
    Basis, Blocker, BlockerClass, BudgetState, Capacity, Decision, EvaluationInput, Hop, HopStatus,
    Mandate, Mode, Outcome, PolicyResult, Position, Remediation, Resolver, Unmet,
};
use crate::algebra::Catalog;
use crate::codec::{
    Canonical, Fields, ModelError, PROOF_KINDS, Stored, assurance, ident, map, map_value,
    set_items, set_of, set_value, single, tagged, text, uint, word, word_of,
};
use crate::digest::Digest;
use crate::intent::IntentEnvelope;
use crate::model::{
    ActionRef, AuthoritySet, BudgetWindow, CanonicalAuthority, Id, PurposeRef, RequirementTerm,
    ResourceRef,
};
use crate::requirement::{Proof, ProofBinding};
use crate::restriction::{PolicyDeny, RestrictionOutcome};

/// An owned evaluation input, decodable from a vector.
#[derive(Clone, Debug)]
pub struct OwnedInput {
    /// Mode.
    pub mode: Mode,
    /// Intent.
    pub intent: IntentEnvelope,
    /// Intent digest.
    pub intent_digest: Digest,
    /// Trusted time.
    pub now: u64,
    /// Actor instance.
    pub actor_instance: Option<Id>,
    /// Whether the actor is an agent.
    pub actor_is_agent: bool,
    /// Mandate.
    pub mandate: Option<Mandate>,
    /// Capacity.
    pub capacity: Capacity,
    /// Bases.
    pub bases: Vec<Basis>,
    /// Restriction outcomes.
    pub restrictions: Vec<PolicyResult>,
    /// Proofs.
    pub proofs: Vec<Proof>,
    /// Catalog.
    pub catalog: Catalog,
}

impl OwnedInput {
    /// Borrows it as an [`EvaluationInput`].
    #[must_use]
    pub fn input(&self) -> EvaluationInput<'_> {
        EvaluationInput {
            mode: self.mode,
            intent: &self.intent,
            intent_digest: self.intent_digest,
            now: self.now,
            actor_instance: self.actor_instance,
            actor_is_agent: self.actor_is_agent,
            mandate: self.mandate.as_ref(),
            capacity: self.capacity,
            bases: &self.bases,
            restrictions: &self.restrictions,
            proofs: &self.proofs,
            catalog: &self.catalog,
        }
    }
}

const MODES: [(&str, Mode); 3] = [
    ("commit", Mode::Commit),
    ("continue", Mode::Continue),
    ("check", Mode::Check),
];

fn capacity_value(c: Capacity) -> Value {
    match c {
        Capacity::Own => Value::text("own"),
        Capacity::For(id) => tagged("for", id.to_value()),
    }
}

fn capacity(v: &Value) -> Result<Capacity, ModelError> {
    if matches!(v, Value::Text(t) if t == "own") {
        return Ok(Capacity::Own);
    }
    match single(v)? {
        ("for", id) => Ok(Capacity::For(Id::from_value(id)?)),
        _ => Err(ModelError::Unknown),
    }
}

fn window_value(w: BudgetWindow) -> Value {
    match w {
        BudgetWindow::Total => Value::text("total"),
        BudgetWindow::RollingSeconds(s) => tagged("rolling_s", Value::Unsigned(s)),
    }
}

fn window(v: &Value) -> Result<BudgetWindow, ModelError> {
    if matches!(v, Value::Text(t) if t == "total") {
        return Ok(BudgetWindow::Total);
    }
    match single(v)? {
        ("rolling_s", s) => Ok(BudgetWindow::RollingSeconds(uint(s)?)),
        _ => Err(ModelError::Unknown),
    }
}

fn terms_value(t: &BTreeSet<RequirementTerm>) -> Option<Value> {
    (!t.is_empty()).then(|| set_value(t.iter().map(Canonical::to_value)))
}

fn terms(v: Option<&Value>) -> Result<BTreeSet<RequirementTerm>, ModelError> {
    v.map(|t| set_of(t, true, RequirementTerm::from_value))
        .transpose()
        .map(Option::unwrap_or_default)
}

impl Canonical for BudgetState {
    fn to_value(&self) -> Value {
        map([
            ("window", Some(window_value(self.window))),
            ("remaining", Some(Value::Unsigned(self.remaining))),
            ("demand", Some(Value::Unsigned(self.demand))),
            ("resets_at", self.resets_at.map(Value::Unsigned)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let b = BudgetState {
            window: window(f.req("window")?)?,
            remaining: uint(f.req("remaining")?)?,
            demand: uint(f.req("demand")?)?,
            resets_at: f.opt("resets_at").map(uint).transpose()?,
        };
        f.done()?;
        Ok(b)
    }
}

impl Canonical for Hop {
    fn to_value(&self) -> Value {
        map([
            ("authority", Some(self.authority.to_value())),
            (
                "status",
                match self.status {
                    HopStatus::Active => None,
                    HopStatus::Revoked => Some(Value::text("revoked")),
                    HopStatus::Lapsed => Some(Value::text("lapsed")),
                },
            ),
            (
                "conditions_fail",
                (!self.conditions_hold).then_some(Value::Bool(true)),
            ),
            (
                "budgets",
                (!self.budgets.is_empty())
                    .then(|| Value::Array(self.budgets.iter().map(Canonical::to_value).collect())),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let status = match f.opt("status") {
            None => HopStatus::Active,
            Some(s) => match text(s)? {
                "revoked" => HopStatus::Revoked,
                "lapsed" => HopStatus::Lapsed,
                _ => return Err(ModelError::Unknown),
            },
        };
        let conditions_hold = match f.opt("conditions_fail") {
            None => true,
            Some(Value::Bool(true)) => false,
            Some(_) => return Err(ModelError::Range),
        };
        let budgets = match f.opt("budgets") {
            None => Vec::new(),
            Some(Value::Array(items)) if !items.is_empty() => items
                .iter()
                .map(BudgetState::from_value)
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(ModelError::Range),
        };
        let h = Hop {
            authority: CanonicalAuthority::from_value(f.req("authority")?)?,
            status,
            conditions_hold,
            budgets,
        };
        f.done()?;
        Ok(h)
    }
}

// OP-118 m.2
fn stored_hop_value(h: &Stored<Hop>) -> Value {
    match h {
        Stored::Known(h) => h.to_value(),
        Stored::NotUnderstood => map([("not_understood", Some(Value::Bool(true)))]),
    }
}

fn stored_hop(v: &Value) -> Result<Stored<Hop>, ModelError> {
    let mut f = Fields::of(v)?;
    match f.opt("not_understood") {
        None => Hop::from_value(v).map(Stored::Known),
        Some(Value::Bool(true)) => {
            f.done()?;
            Ok(Stored::NotUnderstood)
        }
        Some(_) => Err(ModelError::Range),
    }
}

impl Canonical for Basis {
    fn to_value(&self) -> Value {
        map([
            (
                "hops",
                Some(Value::Array(
                    self.hops.iter().map(stored_hop_value).collect(),
                )),
            ),
            (
                "capacities",
                Some(set_value(
                    self.capacities.iter().copied().map(capacity_value),
                )),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let Value::Array(hops) = f.req("hops")? else {
            return Err(ModelError::Shape);
        };
        if hops.is_empty() {
            return Err(ModelError::Range);
        }
        let b = Basis {
            hops: hops.iter().map(stored_hop).collect::<Result<_, _>>()?,
            capacities: set_of(f.req("capacities")?, true, capacity)?,
        };
        f.done()?;
        Ok(b)
    }
}

impl Canonical for Mandate {
    fn to_value(&self) -> Value {
        map([
            ("authority", Some(self.authority.to_value())),
            ("requirements", terms_value(&self.requirements)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let m = Mandate {
            authority: AuthoritySet::from_value(f.req("authority")?)?,
            requirements: terms(f.opt("requirements"))?,
        };
        f.done()?;
        Ok(m)
    }
}

impl Canonical for RestrictionOutcome {
    fn to_value(&self) -> Value {
        match self {
            Self::NoObjection => Value::text("no_objection"),
            Self::Deny(d) => tagged(
                "deny",
                map([
                    ("policy", Some(d.policy.to_value())),
                    ("policy_version", Some(d.version.to_value())),
                    ("undisclosed", d.undisclosed.then_some(Value::Bool(true))),
                ]),
            ),
            Self::Require(t) => tagged("require", set_value(t.iter().map(Canonical::to_value))),
        }
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        if matches!(v, Value::Text(t) if t == "no_objection") {
            return Ok(Self::NoObjection);
        }
        match single(v)? {
            ("deny", d) => {
                let mut f = Fields::of(d)?;
                let undisclosed = match f.opt("undisclosed") {
                    None => false,
                    Some(Value::Bool(true)) => true,
                    Some(_) => return Err(ModelError::Range),
                };
                let deny = PolicyDeny {
                    policy: Id::from_value(f.req("policy")?)?,
                    version: Canonical::from_value(f.req("policy_version")?)?,
                    undisclosed,
                };
                f.done()?;
                Ok(Self::Deny(deny))
            }
            ("require", t) => Ok(Self::Require(set_of(t, true, RequirementTerm::from_value)?)),
            _ => Err(ModelError::Unknown),
        }
    }
}

impl Canonical for PolicyResult {
    fn to_value(&self) -> Value {
        map([
            ("policy", Some(self.policy.to_value())),
            ("version", Some(self.version.to_value())),
            ("outcome", Some(self.outcome.to_value())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let r = PolicyResult {
            policy: Id::from_value(f.req("policy")?)?,
            version: Canonical::from_value(f.req("version")?)?,
            outcome: RestrictionOutcome::from_value(f.req("outcome")?)?,
        };
        f.done()?;
        Ok(r)
    }
}

impl Canonical for Proof {
    fn to_value(&self) -> Value {
        map([
            ("id", Some(self.id.to_value())),
            ("kind", Some(word_of(self.kind, &PROOF_KINDS))),
            ("class", Some(Value::text(&self.class))),
            ("position", Some(Value::Unsigned(self.position))),
            ("time", Some(Value::Unsigned(self.time))),
            ("party", Some(self.party.to_value())),
            ("instance", Some(self.instance.to_value())),
            ("issuer", Some(self.issuer.to_value())),
            (
                "bound_instance",
                self.binding
                    .actor_instance
                    .as_ref()
                    .map(Canonical::to_value),
            ),
            (
                "bound_intent",
                self.binding.intent_digest.as_ref().map(Digest::to_value),
            ),
            (
                "bound_resource",
                self.binding.resource.as_ref().map(Canonical::to_value),
            ),
            (
                "assurance",
                map_value(&self.assurance, |n| Value::Unsigned(*n)),
            ),
            ("consumed", self.consumed.then_some(Value::Bool(true))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let p = Proof {
            id: Id::from_value(f.req("id")?)?,
            kind: word(f.req("kind")?, &PROOF_KINDS)?,
            class: ident(f.req("class")?)?,
            position: uint(f.req("position")?)?,
            time: uint(f.req("time")?)?,
            party: Id::from_value(f.req("party")?)?,
            instance: Id::from_value(f.req("instance")?)?,
            issuer: Id::from_value(f.req("issuer")?)?,
            binding: ProofBinding {
                actor_instance: f.opt("bound_instance").map(Id::from_value).transpose()?,
                intent_digest: f
                    .opt("bound_intent")
                    .map(<Digest as Canonical>::from_value)
                    .transpose()?,
                resource: f
                    .opt("bound_resource")
                    .map(ResourceRef::from_value)
                    .transpose()?,
            },
            assurance: assurance(f.opt("assurance"))?,
            consumed: match f.opt("consumed") {
                None => false,
                Some(Value::Bool(true)) => true,
                Some(_) => return Err(ModelError::Range),
            },
        };
        f.done()?;
        Ok(p)
    }
}

impl Canonical for Catalog {
    fn to_value(&self) -> Value {
        map([
            (
                "catalogs",
                (!self.catalogs.is_empty()).then(|| {
                    set_value(self.catalogs.iter().map(|(d, actions)| {
                        map([
                            ("catalog", Some(d.to_value())),
                            (
                                "actions",
                                Some(set_value(actions.iter().map(Canonical::to_value))),
                            ),
                        ])
                    }))
                }),
            ),
            (
                "reserved",
                (!self.reserved.is_empty())
                    .then(|| set_value(self.reserved.iter().map(Canonical::to_value))),
            ),
            (
                "purposes",
                (!self.purposes.is_empty()).then(|| {
                    set_value(self.purposes.iter().map(|(p, below)| {
                        map([
                            ("purpose", Some(p.to_value())),
                            (
                                "below",
                                Some(set_value(below.iter().map(Canonical::to_value))),
                            ),
                        ])
                    }))
                }),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let mut c = Catalog::default();
        if let Some(cats) = f.opt("catalogs") {
            for item in set_items(cats, true)? {
                let mut cf = Fields::of(item)?;
                let d = <Digest as Canonical>::from_value(cf.req("catalog")?)?;
                let actions = set_of(cf.req("actions")?, true, ActionRef::from_value)?;
                cf.done()?;
                if c.catalogs.insert(d, actions).is_some() {
                    return Err(ModelError::SetOrder);
                }
            }
        }
        c.reserved = f
            .opt("reserved")
            .map(|r| set_of(r, true, ActionRef::from_value))
            .transpose()?
            .unwrap_or_default();
        if let Some(ps) = f.opt("purposes") {
            let mut purposes: BTreeMap<PurposeRef, BTreeSet<PurposeRef>> = BTreeMap::new();
            for item in set_items(ps, true)? {
                let mut pf = Fields::of(item)?;
                let p = PurposeRef::from_value(pf.req("purpose")?)?;
                let below = set_of(pf.req("below")?, true, PurposeRef::from_value)?;
                pf.done()?;
                if purposes.insert(p, below).is_some() {
                    return Err(ModelError::SetOrder);
                }
            }
            c.purposes = purposes;
        }
        f.done()?;
        Ok(c)
    }
}

fn list(v: Option<&Value>) -> Result<&[Value], ModelError> {
    v.map_or(Ok(&[][..]), |v| set_items(v, true))
}

impl Canonical for OwnedInput {
    fn to_value(&self) -> Value {
        map([
            ("mode", Some(word_of(self.mode, &MODES))),
            ("intent", Some(self.intent.to_value())),
            ("intent_digest", Some(self.intent_digest.to_value())),
            ("now", Some(Value::Unsigned(self.now))),
            (
                "actor_instance",
                self.actor_instance.as_ref().map(Canonical::to_value),
            ),
            (
                "actor_is_agent",
                self.actor_is_agent.then_some(Value::Bool(true)),
            ),
            ("mandate", self.mandate.as_ref().map(Canonical::to_value)),
            ("capacity", Some(capacity_value(self.capacity))),
            (
                "bases",
                Some(Value::Array(
                    self.bases.iter().map(Canonical::to_value).collect(),
                )),
            ),
            (
                "restrictions",
                (!self.restrictions.is_empty())
                    .then(|| set_value(self.restrictions.iter().map(Canonical::to_value))),
            ),
            (
                "proofs",
                (!self.proofs.is_empty())
                    .then(|| set_value(self.proofs.iter().map(Canonical::to_value))),
            ),
            ("catalog", Some(self.catalog.to_value())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let Value::Array(bases) = f.req("bases")? else {
            return Err(ModelError::Shape);
        };
        let i = OwnedInput {
            mode: word(f.req("mode")?, &MODES)?,
            intent: IntentEnvelope::from_value(f.req("intent")?)?,
            intent_digest: Canonical::from_value(f.req("intent_digest")?)?,
            now: uint(f.req("now")?)?,
            actor_instance: f.opt("actor_instance").map(Id::from_value).transpose()?,
            actor_is_agent: match f.opt("actor_is_agent") {
                None => false,
                Some(Value::Bool(true)) => true,
                Some(_) => return Err(ModelError::Range),
            },
            mandate: f.opt("mandate").map(Mandate::from_value).transpose()?,
            capacity: capacity(f.req("capacity")?)?,
            bases: bases
                .iter()
                .map(Basis::from_value)
                .collect::<Result<_, _>>()?,
            restrictions: list(f.opt("restrictions"))?
                .iter()
                .map(PolicyResult::from_value)
                .collect::<Result<_, _>>()?,
            proofs: list(f.opt("proofs"))?
                .iter()
                .map(Proof::from_value)
                .collect::<Result<_, _>>()?,
            catalog: Catalog::from_value(f.req("catalog")?)?,
        };
        f.done()?;
        Ok(i)
    }
}

const CLASSES: [(&str, BlockerClass); 10] = [
    ("no-covering-authority", BlockerClass::NoCoveringAuthority),
    (
        "outside-instance-limits",
        BlockerClass::OutsideInstanceLimits,
    ),
    ("restricted", BlockerClass::Restricted),
    ("budget-exhausted", BlockerClass::BudgetExhausted),
    ("ended", BlockerClass::Ended),
    ("capacity-mismatch", BlockerClass::CapacityMismatch),
    ("source-not-accepted", BlockerClass::SourceNotAccepted),
    ("schema-not-accepted", BlockerClass::SchemaNotAccepted),
    ("nonce-closed", BlockerClass::NonceClosed),
    (
        "foreign-status-unavailable",
        BlockerClass::ForeignStatusUnavailable,
    ),
];

fn position(p: Position) -> Value {
    match p {
        Position::Instance => Value::text("instance"),
        Position::Hop(k) => tagged("hop", Value::Unsigned(k)),
        Position::Anchor => Value::text("anchor"),
        Position::DomainPolicy => Value::text("domain-policy"),
        Position::Foreign => Value::text("foreign"),
        Position::ActorSide => Value::text("actor-side"),
    }
}

fn resolver(r: Resolver) -> Value {
    match r {
        Resolver::GrantorOfHop(k) => tagged("grantor_of_hop", Value::Unsigned(k)),
        Resolver::Root => Value::text("root"),
        Resolver::RestrictionOwner => Value::text("restriction-owner"),
        Resolver::Issuer => Value::text("issuer"),
        Resolver::DomainAdmin => Value::text("domain-admin"),
        Resolver::Actor => Value::text("actor"),
        Resolver::ActorParty => Value::text("actor-party"),
        Resolver::Time => Value::text("time"),
    }
}

fn remediation(r: Remediation) -> Value {
    match r {
        Remediation::RouteToCoordinator => Value::text("route-to-coordinator"),
        Remediation::RefreshClaim => Value::text("refresh-claim"),
        Remediation::SelfAuthenticate => Value::text("self-authenticate"),
        Remediation::WaitUntil(t) => tagged("wait_until", Value::Unsigned(t)),
        Remediation::NotSatisfiableByActor => Value::text("not-satisfiable-by-actor"),
        Remediation::NewRequestRequired => Value::text("new-request-required"),
    }
}

/// Sorts blockers by the bytes of their canonical encoding and drops repeats (OP-114 m.2).
pub(crate) fn order_blockers(v: &mut Vec<Blocker>) {
    order_by(v, blocker);
}

/// Sorts unmet terms by the bytes of their canonical encoding (OP-114 m.3).
pub(crate) fn order_unmet(v: &mut Vec<Unmet>) {
    order_by(v, unmet);
}

fn order_by<T>(v: &mut Vec<T>, encode: impl Fn(&T) -> Value) {
    let mut keyed: Vec<(Vec<u8>, T)> = v
        .drain(..)
        .map(|x| {
            (
                suiss_crypto::dcbor::encode(&encode(&x), suiss_crypto::dcbor::Limits::CEILING)
                    .unwrap_or_default(),
                x,
            )
        })
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.dedup_by(|a, b| a.0 == b.0);
    v.extend(keyed.into_iter().map(|(_, x)| x));
}

fn blocker(b: &Blocker) -> Value {
    map([
        ("class", Some(word_of(b.class, &CLASSES))),
        ("subcode", b.subcode.as_deref().map(Value::text)),
        ("position", Some(position(b.position))),
        ("resolver", Some(resolver(b.resolver))),
        ("remediation", Some(remediation(b.remediation))),
    ])
}

fn unmet(u: &Unmet) -> Value {
    map([
        ("term", Some(u.term.to_value())),
        ("missing", Some(Value::Unsigned(u.missing))),
        ("position", Some(position(u.position))),
        (
            "satisfiable_by_actor",
            Some(Value::Bool(u.satisfiable_by_actor)),
        ),
    ])
}

/// The canonical form of a decision; blockers and unmet terms keep the combinator's order.
#[must_use]
pub fn decision_value(d: &Decision) -> Value {
    let outcome = match d.outcome {
        Outcome::Allow => "allow",
        Outcome::Deny => "deny",
        Outcome::RequireAction => "require_action",
    };
    map([
        ("outcome", Some(Value::text(outcome))),
        (
            "blockers",
            (!d.blockers.is_empty())
                .then(|| Value::Array(d.blockers.iter().map(blocker).collect())),
        ),
        (
            "unmet",
            (!d.unmet.is_empty()).then(|| Value::Array(d.unmet.iter().map(unmet).collect())),
        ),
        (
            "relied_on",
            (!d.relied_on.is_empty())
                .then(|| Value::Array(d.relied_on.iter().map(Canonical::to_value).collect())),
        ),
    ])
}
