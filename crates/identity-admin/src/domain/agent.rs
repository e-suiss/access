//! Agents of a realm (OP-154 m.3 (c), (e), (g); AG-19, AG-20, AG-21, AG-41, E23).
//!
//! An agent is an actor-capable Party of its own (`actor_kind = agent`) whose root is its
//! operator Party, an organization or a person, with Instances its runtime keys create. There is
//! no agent-only authority primitive (F15, AG-19): an agent acts only through a Grant, within
//! its Instance's Mandate and the Grant's budget, and what makes it an agent's Grant is the
//! template it is issued from. The identity record below is the identity plane's own
//! (`IdentitySubject`, AG-20); it reaches the authority plane only as the realm issuer's Claims
//! `operated_by`, `agent_kind` and `sponsored_by`.
//!
//! How an `AgentIdentity` record of other products maps onto Access (AG-20, Ek B 4321):
//!
//! | `AgentIdentity` field | Access |
//! |---|---|
//! | workload URI | the `identity_binding_workload` Claim of an Instance (OP-154 m.3 (d)) |
//! | blueprint | an [`AgentTemplate`] |
//! | owner, sponsor | the `operated_by` and `sponsored_by` Claims |
//! | tenant | the realm's governing `AuthorityDomain` |
//! | status | the agent's status and its Instances' lifecycle |
//! | trusted issuers | Acceptances of the domain |
//! | `default_token_ttl` | the template's horizon, [`AgentTemplate::ttl_ms`] |
//!
//! Scale levels (AG-21, Ek B 4322): the template is the blueprint, the Instance the unit of
//! audit and revocation, the Exercise the unit of action. Replicas sharing one key binding are
//! one Instance; an Instance per task is recommended, not required.
//!
//! A personal agent, Suiss One included, is an ordinary agent whose operator is the person
//! (E23, E24): it has no other path.

use std::collections::{BTreeMap, BTreeSet};

use access_internal_api::idp::IdpAction;
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::Capacity;
use access_kernel::json::b64url_encode;
use access_kernel::meta::{GrantBasis, GrantContent};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, Binding, Bound, BudgetDimension, BudgetTerm, BudgetWindow,
    CanonicalAuthority, Conjunct, ConstraintSet, Consumption, DelegationTerms, EqValue, Id,
    Independence, ProofKind, RequirementTerm, ResourceSelector, Structural, SubjectSelector,
    Window,
};
use suiss_crypto::dcbor::{self, Limits, Value};

use super::{Invalid, Name};

/// Most sponsors one registration names.
pub const MAX_SPONSORS: usize = 16;

/// Most actions one template covers.
pub const MAX_TEMPLATE_ACTIONS: usize = 32;

/// The longest horizon a template gives its Grants (PD): 90 days.
pub const MAX_TTL_MS: u64 = 90 * 24 * 3_600_000;

/// The shortest horizon a template gives its Grants: one minute.
pub const MIN_TTL_MS: u64 = 60_000;

/// The daily window of a template's spend budget (OP-154 m.3 (g)).
pub const DAY_S: u64 = 86_400;

/// The longest count window a template may name: 31 days.
pub const MAX_WINDOW_S: u64 = 31 * DAY_S;

/// The deepest delegation an agent Grant allows (OP-154 m.3 (g), C15).
pub const MAX_DEPTH: u64 = 1;

/// Threshold-adjacent guard (OP-154 m.3 (g), PD): this many intents in one hour between
/// [`ADJACENT_FROM_PERCENT`] and 100 % of the per-intent cap answer `REQUIRE_ACTION`.
pub const ADJACENT_INTENTS: u64 = 3;

/// The lower bound of the threshold-adjacent band, in percent of the per-intent cap.
pub const ADJACENT_FROM_PERCENT: u64 = 95;

/// Mass-selection guard (OP-154 m.3 (g), PD): an intent naming more resources answers
/// `REQUIRE_ACTION`.
pub const MASS_SELECTION: usize = 100;

/// Stable code of an agent exercise whose `sponsored_by` requirement found no live Claim: the
/// agent has no active human sponsor and waits for one (OP-154 m.3 (e), AG-41).
pub const SPONSOR_REQUIRED: &str = "sponsor-required";

/// Whether `decision` is an agent waiting for a sponsor: a `REQUIRE_ACTION` whose unmet terms
/// include the `sponsored_by` Claim (OP-154 m.3 (e)).
#[must_use]
pub fn sponsor_required(decision: &access_kernel::combinator::Decision) -> bool {
    let sponsored = access_kernel::claim::body::Class::SponsoredBy.name();
    decision.outcome == access_kernel::combinator::Outcome::RequireAction
        && decision
            .unmet
            .iter()
            .any(|u| u.term.proof_kind == ProofKind::Claim && u.term.class == sponsored)
}

/// What kind of agent it is (AG-20).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentKind {
    /// Runs on an operator's cloud.
    Cloud,
    /// Runs on a person's own device.
    Local,
    /// Runs inside an organization.
    Enterprise,
    /// Acts in the physical world.
    Robot,
}

impl AgentKind {
    /// Every kind.
    pub const ALL: [Self; 4] = [Self::Cloud, Self::Local, Self::Enterprise, Self::Robot];

    /// Its name, the `agent_kind` Claim's value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cloud => "cloud",
            Self::Local => "local",
            Self::Enterprise => "enterprise",
            Self::Robot => "robot",
        }
    }

    /// The kind named `s`.
    ///
    /// # Errors
    /// [`Invalid::Agent`].
    pub fn parse(s: &str) -> Result<Self, Invalid> {
        Self::ALL
            .into_iter()
            .find(|k| k.name() == s)
            .ok_or(Invalid::Agent)
    }
}

fn text_ok(s: &str, max: usize) -> bool {
    let n = s.chars().count();
    n >= 1 && n <= max && !s.chars().any(char::is_control)
}

/// An agent to register, bound to the agent Party its operator's client registered with a
/// one-time key (OP-154 m.3 (c), L0-META-7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRegister {
    /// The agent's own Party.
    pub party: [u8; 16],
    /// The operator Party: an organization or a person, the agent Party's root.
    pub operator: [u8; 16],
    /// Its kind.
    pub kind: AgentKind,
    /// Name shown to people; attacker input, rendered as text.
    pub display_name: String,
    /// Description shown to people.
    pub description: Option<String>,
    /// Its first human sponsors' subjects: at least one (AG-41).
    pub sponsors: Vec<[u8; 16]>,
}

impl AgentRegister {
    fn check(&self) -> Result<(), Invalid> {
        let distinct: BTreeSet<_> = self.sponsors.iter().collect();
        if !text_ok(&self.display_name, 128)
            || self
                .description
                .as_deref()
                .is_some_and(|d| !text_ok(d, 1024))
            || self.sponsors.is_empty()
            || self.sponsors.len() > MAX_SPONSORS
            || distinct.len() != self.sponsors.len()
            || self.party == self.operator
        {
            return Err(Invalid::Agent);
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        let mut m = vec![
            (Value::text("party"), Value::Bytes(self.party.to_vec())),
            (
                Value::text("operator"),
                Value::Bytes(self.operator.to_vec()),
            ),
            (Value::text("kind"), Value::text(self.kind.name())),
            (Value::text("display_name"), Value::text(&self.display_name)),
            (
                Value::text("sponsors"),
                Value::Array(
                    self.sponsors
                        .iter()
                        .map(|s| Value::Bytes(s.to_vec()))
                        .collect(),
                ),
            ),
        ];
        if let Some(d) = &self.description {
            m.push((Value::text("description"), Value::text(d)));
        }
        Value::Map(m)
    }
}

/// A new name and description of an agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentUpdate {
    /// The agent's Party.
    pub agent: [u8; 16],
    /// Name shown to people.
    pub display_name: String,
    /// Description shown to people.
    pub description: Option<String>,
}

impl AgentUpdate {
    fn check(&self) -> Result<(), Invalid> {
        if !text_ok(&self.display_name, 128)
            || self
                .description
                .as_deref()
                .is_some_and(|d| !text_ok(d, 1024))
        {
            return Err(Invalid::Agent);
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        let mut m = vec![
            (Value::text("agent"), Value::Bytes(self.agent.to_vec())),
            (Value::text("display_name"), Value::text(&self.display_name)),
        ];
        if let Some(d) = &self.description {
            m.push((Value::text("description"), Value::text(d)));
        }
        Value::Map(m)
    }
}

/// One sponsorship: the agent and the sponsor's subject (AG-41).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sponsor {
    /// The agent's Party.
    pub agent: [u8; 16],
    /// The sponsor's subject.
    pub subject: [u8; 16],
}

impl Sponsor {
    fn to_value(self) -> Value {
        Value::Map(vec![
            (Value::text("agent"), Value::Bytes(self.agent.to_vec())),
            (Value::text("subject"), Value::Bytes(self.subject.to_vec())),
        ])
    }
}

/// The spend budget of a consumption-bearing template (OP-154 m.3 (g), §13.7.6, X10): a cap per
/// intent on one amount parameter and a daily window over the same unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    /// The typed parameter the amount is in.
    pub param: String,
    /// Its unit.
    pub unit: String,
    /// The most one intent may spend.
    pub per_intent: i64,
    /// The most a rolling day may spend.
    pub daily: u64,
}

/// An agent Grant template (OP-154 m.3 (g), §11.9.1, §13.7.6): what agents of the realm may be
/// granted, with the budget and delegation terms no agent Grant goes without.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentTemplate {
    /// Its natural key.
    pub name: Name,
    /// The actions it covers; never a core meta-action (RR-12: an agent issues itself no Grant).
    pub actions: BTreeSet<ActionRef>,
    /// The resource namespace.
    pub namespace: String,
    /// The resource path prefix.
    pub prefix: Vec<String>,
    /// Whether the actions consume: then [`AgentTemplate::spend`] is mandatory.
    pub consumption: bool,
    /// The spend budget.
    pub spend: Option<Spend>,
    /// Most Exercises per [`AgentTemplate::window_s`]; mandatory.
    pub count: u64,
    /// The count window in seconds.
    pub window_s: u64,
    /// Delegation depth, at most [`MAX_DEPTH`].
    pub depth: u64,
    /// How long a Grant from it holds.
    pub ttl_ms: u64,
}

impl AgentTemplate {
    /// OP-154 m.3 (g): a template without its budget, deeper than one hop, or covering core
    /// meta-actions is refused when it is defined.
    ///
    /// # Errors
    /// [`Invalid::AgentTemplate`].
    pub fn check(&self) -> Result<(), Invalid> {
        let bad = self.actions.is_empty()
            || self.actions.len() > MAX_TEMPLATE_ACTIONS
            // RR-12, AG-19
            || self
                .actions
                .iter()
                .any(|a| a.namespace == access_kernel::meta::NAMESPACE)
            || self.namespace.is_empty()
            || self.namespace == access_kernel::meta::NAMESPACE
            || self.prefix.len() > 8
            || self.prefix.iter().any(|p| !text_ok(p, 128))
            // X10, §13.7.6
            || self.count == 0
            || self.window_s == 0
            || self.window_s > MAX_WINDOW_S
            || (self.consumption && self.spend.is_none())
            || self.spend.as_ref().is_some_and(|s| {
                s.per_intent <= 0
                    || u64::try_from(s.per_intent).is_ok_and(|p| s.daily < p)
                    || !text_ok(&s.param, 64)
                    || !text_ok(&s.unit, 16)
            })
            // C15
            || self.depth > MAX_DEPTH
            || self.ttl_ms < MIN_TTL_MS
            || self.ttl_ms > MAX_TTL_MS;
        if bad {
            Err(Invalid::AgentTemplate)
        } else {
            Ok(())
        }
    }

    /// Its stored and signed form.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut m = vec![
            (Value::text("name"), Value::text(self.name.as_str())),
            (
                Value::text("actions"),
                Value::Array(self.actions.iter().map(ActionRef::to_value).collect()),
            ),
            (Value::text("namespace"), Value::text(&self.namespace)),
            (
                Value::text("prefix"),
                Value::Array(self.prefix.iter().map(|p| Value::text(p)).collect()),
            ),
            (Value::text("consumption"), Value::Bool(self.consumption)),
            (Value::text("count"), Value::Unsigned(self.count)),
            (Value::text("window_s"), Value::Unsigned(self.window_s)),
            (Value::text("depth"), Value::Unsigned(self.depth)),
            (Value::text("ttl_ms"), Value::Unsigned(self.ttl_ms)),
        ];
        if let Some(s) = &self.spend {
            m.push((
                Value::text("spend"),
                Value::Map(vec![
                    (Value::text("param"), Value::text(&s.param)),
                    (Value::text("unit"), Value::text(&s.unit)),
                    (Value::text("per_intent"), Value::int(s.per_intent)),
                    (Value::text("daily"), Value::Unsigned(s.daily)),
                ]),
            ));
        }
        Value::Map(m)
    }

    /// The template from its stored form.
    ///
    /// # Errors
    /// [`Invalid::AgentTemplate`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Invalid> {
        let v = dcbor::decode(bytes, Limits::CEILING).map_err(|_| Invalid::AgentTemplate)?;
        let bad = || Invalid::AgentTemplate;
        let text = |k: &str| match v.get(k) {
            Some(Value::Text(t)) => Ok(t.clone()),
            _ => Err(bad()),
        };
        let uint = |k: &str| match v.get(k) {
            Some(Value::Unsigned(n)) => Ok(*n),
            _ => Err(bad()),
        };
        let actions = match v.get("actions") {
            Some(Value::Array(a)) => a
                .iter()
                .map(|x| ActionRef::from_value(x).map_err(|_| bad()))
                .collect::<Result<BTreeSet<_>, _>>()?,
            _ => return Err(bad()),
        };
        let prefix = match v.get("prefix") {
            Some(Value::Array(a)) => a
                .iter()
                .map(|x| match x {
                    Value::Text(t) => Ok(t.clone()),
                    _ => Err(bad()),
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(bad()),
        };
        let spend = match v.get("spend") {
            None => None,
            Some(s) => Some(Spend {
                param: match s.get("param") {
                    Some(Value::Text(t)) => t.clone(),
                    _ => return Err(bad()),
                },
                unit: match s.get("unit") {
                    Some(Value::Text(t)) => t.clone(),
                    _ => return Err(bad()),
                },
                per_intent: match s.get("per_intent") {
                    Some(Value::Unsigned(n)) => i64::try_from(*n).map_err(|_| bad())?,
                    _ => return Err(bad()),
                },
                daily: match s.get("daily") {
                    Some(Value::Unsigned(n)) => *n,
                    _ => return Err(bad()),
                },
            }),
        };
        let t = Self {
            name: Name::parse(&text("name")?).map_err(|_| bad())?,
            actions,
            namespace: text("namespace")?,
            prefix,
            consumption: matches!(v.get("consumption"), Some(Value::Bool(true))),
            spend,
            count: uint("count")?,
            window_s: uint("window_s")?,
            depth: uint("depth")?,
            ttl_ms: uint("ttl_ms")?,
        };
        t.check()?;
        Ok(t)
    }

    /// The Grant content an agent gets from this template (OP-154 m.3 (e), (g)): held by the
    /// agent Party, bounded by the template's budget, delegable at most one hop and only to
    /// agents the same operator runs, and requiring a live `sponsored_by` Claim of the realm
    /// issuer on every exercise, so an agent whose last sponsor left answers `REQUIRE_ACTION`
    /// [`SPONSOR_REQUIRED`]. Issuing it is the user's own `grant_issue` (RR-12): nothing here
    /// signs or commits.
    #[must_use]
    pub fn grant(&self, to: &Placement) -> GrantContent {
        let mut params = BTreeMap::new();
        let mut budget = BTreeSet::from([BudgetTerm {
            dimension: BudgetDimension::Count,
            capacity: self.count,
            window: BudgetWindow::RollingSeconds(self.window_s),
        }]);
        if let Some(s) = &self.spend {
            params.insert(
                s.param.clone(),
                Bound::Range {
                    min: Some(0),
                    max: Some(s.per_intent),
                    unit: s.unit.clone(),
                },
            );
            budget.insert(BudgetTerm {
                dimension: BudgetDimension::Amount(s.unit.clone()),
                capacity: s.daily,
                window: BudgetWindow::RollingSeconds(DAY_S),
            });
        }
        // C15, OP-154 m.3 (g)
        let downstream = (self.depth > 0).then(|| {
            SubjectSelector::Pred(BTreeSet::from([Conjunct {
                claim_class: access_kernel::claim::body::Class::OperatedBy.name(),
                value: Some(EqValue::Bytes(to.operator.0.to_vec())),
            }]))
        });
        // AG-41, OP-154 m.3 (e)
        let sponsored = RequirementTerm {
            proof_kind: ProofKind::Claim,
            class: access_kernel::claim::body::Class::SponsoredBy.name(),
            count: 1,
            binding: Binding::None,
            freshness_ms: None,
            independence: Independence::None,
            consumption: Consumption::Reusable,
            source: Some(SubjectSelector::Party(to.issuer)),
            assurance: BTreeMap::new(),
        };
        GrantContent {
            basis: to.basis,
            holder: SubjectSelector::Party(to.agent),
            authority: CanonicalAuthority {
                authority: AuthoritySet {
                    actions: ActionSet {
                        exact: self.actions.clone(),
                        prefix: BTreeSet::new(),
                    },
                    resource: ResourceSelector::Structural(Structural {
                        namespace: self.namespace.clone(),
                        prefix: self.prefix.clone(),
                        kind: None,
                        attrs: BTreeMap::new(),
                    }),
                    params,
                    recipient: None,
                    purpose: None,
                },
                constraints: ConstraintSet {
                    validity: Window {
                        from: to.from,
                        until: to.from.saturating_add(self.ttl_ms),
                    },
                    conditions: BTreeSet::new(),
                    budget,
                },
                delegation: DelegationTerms {
                    depth: self.depth,
                    downstream_holder_class: downstream,
                },
                requirements: BTreeSet::from([sponsored]),
            },
            agency: BTreeSet::from([Capacity::Own]),
            named: None,
        }
    }
}

/// Where a Grant from a template lands: its basis, the agent, its operator, the realm issuer
/// whose `sponsored_by` Claims it requires, and when it starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    /// The issuer's basis: an Anchor it roots or a holding it delegates from.
    pub basis: GrantBasis,
    /// The agent Party.
    pub agent: Id,
    /// The operator Party.
    pub operator: Id,
    /// The realm's Claim issuer Party.
    pub issuer: Id,
    /// Start of validity, Unix milliseconds.
    pub from: u64,
}

/// One `idp.agent.*` change (OP-154 m.3 (a)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentChange {
    /// `idp.agent.register`.
    Register(AgentRegister),
    /// `idp.agent.update`.
    Update(AgentUpdate),
    /// `idp.agent.sponsor_assign`.
    SponsorAssign(Sponsor),
    /// `idp.agent.sponsor_remove`: the last sponsor leaving suspends the agent.
    SponsorRemove(Sponsor),
    /// `idp.agent.retire`: nothing is deleted (OP-73).
    Retire([u8; 16]),
    /// `idp.agent.template_define`.
    TemplateDefine(AgentTemplate),
}

impl AgentChange {
    /// Its action.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::Register(_) => IdpAction::AgentRegister,
            Self::Update(_) => IdpAction::AgentUpdate,
            Self::SponsorAssign(_) => IdpAction::AgentSponsorAssign,
            Self::SponsorRemove(_) => IdpAction::AgentSponsorRemove,
            Self::Retire(_) => IdpAction::AgentRetire,
            Self::TemplateDefine(_) => IdpAction::AgentTemplateDefine,
        }
    }

    /// The agent it changes, unless it defines a template.
    #[must_use]
    pub const fn agent(&self) -> Option<[u8; 16]> {
        match self {
            Self::Register(r) => Some(r.party),
            Self::Update(u) => Some(u.agent),
            Self::SponsorAssign(s) | Self::SponsorRemove(s) => Some(s.agent),
            Self::Retire(a) => Some(*a),
            Self::TemplateDefine(_) => None,
        }
    }

    pub(crate) fn check(&self) -> Result<(), Invalid> {
        match self {
            Self::Register(r) => r.check(),
            Self::Update(u) => u.check(),
            Self::TemplateDefine(t) => t.check(),
            Self::SponsorAssign(_) | Self::SponsorRemove(_) | Self::Retire(_) => Ok(()),
        }
    }

    pub(crate) fn body(&self) -> Value {
        match self {
            Self::Register(r) => r.to_value(),
            Self::Update(u) => u.to_value(),
            Self::SponsorAssign(s) | Self::SponsorRemove(s) => s.to_value(),
            Self::Retire(a) => Value::Map(vec![(Value::text("agent"), Value::Bytes(a.to_vec()))]),
            Self::TemplateDefine(t) => t.to_value(),
        }
    }

    /// Its resource path under the realm's slug: `agent/<party>` or `agent-template/<name>`.
    #[must_use]
    pub fn path(&self) -> [String; 2] {
        match (self, self.agent()) {
            (Self::TemplateDefine(t), _) => [
                String::from("agent-template"),
                String::from(t.name.as_str()),
            ],
            (_, Some(a)) => [String::from("agent"), b64url_encode(&a)],
            (_, None) => [String::from("agent"), String::new()],
        }
    }
}

#[cfg(test)]
mod tests;
