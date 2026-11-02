//! The pure part of the commit path (§17.1.1 steps 4–8, OP-63): a snapshot of the state that
//! records what it served, and the decision for one request over it.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use access_kernel::algebra::Catalog;
use access_kernel::algebra::subject_le;
use access_kernel::claim::{self, ClaimState, Statement};
use access_kernel::codec::{Canonical, Stored};
use access_kernel::combinator::{
    Basis, Blocker, BlockerClass, BudgetState, Capacity, Decision, EvaluationInput, Fuel, Hop,
    HopStatus, Mandate, Mode, Outcome as KernelOutcome, Position, Rejection, Remediation, Resolver,
    evaluate,
};
use access_kernel::digest::Digest;
use access_kernel::fold::Effect;
use access_kernel::intent::{IntentEnvelope, ParamValue};
use access_kernel::meta::{
    self, Actor, AnchorState, ContentState, ExerciseBasis, GrantBasis, GrantState, InstanceState,
    MandateState, MetaError, Payload, View, kind,
};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, BudgetDimension, BudgetWindow, CanonicalAuthority,
    ConstraintSet, DelegationTerms, Id, ResourceSelector, Structural, SubjectSelector,
    WhileCondition, Window,
};
use access_kernel::schema::{ActionSchema, Spp};
use suiss_crypto::dcbor::Value;

/// Fuel for one evaluation (OP-111 m.7, PD).
pub const FUEL: u64 = 100_000;

/// The state at one position as far as it was fetched; every key it serves enters the read
/// set with the version it had (TI-4). A key not fetched yet is noted as missing.
#[derive(Debug, Default)]
pub struct Snapshot {
    values: BTreeMap<Vec<u8>, (Option<Value>, u64)>,
    reads: RefCell<BTreeSet<Vec<u8>>>,
    missing: RefCell<BTreeSet<Vec<u8>>>,
    counters: BTreeMap<Vec<u8>, u64>,
    missing_counters: RefCell<BTreeSet<Vec<u8>>>,
    scans: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
    missing_scans: RefCell<BTreeSet<Vec<u8>>>,
}

impl Snapshot {
    /// Adds fetched keys: `None` for a key that is absent, at version 0.
    pub fn fill(&mut self, rows: impl IntoIterator<Item = (Vec<u8>, Option<Value>, u64)>) {
        for (k, v, version) in rows {
            self.missing.borrow_mut().remove(&k);
            self.values.insert(k, (v, version));
        }
    }

    /// The value of a fetched key, without recording a read.
    #[must_use]
    pub fn values_of(&self, key: &[u8]) -> Option<Value> {
        self.values.get(key).and_then(|(v, _)| v.clone())
    }

    /// Adds fetched SYNC-DERIVED counters (OP-141 m.26).
    pub fn fill_counters(&mut self, rows: impl IntoIterator<Item = (Vec<u8>, u64)>) {
        for (k, used) in rows {
            self.missing_counters.borrow_mut().remove(&k);
            self.counters.insert(k, used);
        }
    }

    /// A counter's used amount, noting it as missing when not fetched yet.
    #[must_use]
    pub fn counter(&self, key: &[u8]) -> u64 {
        if let Some(used) = self.counters.get(key) {
            return *used;
        }
        self.missing_counters.borrow_mut().insert(key.to_vec());
        0
    }

    /// Counters asked for and not fetched yet.
    #[must_use]
    pub fn missing_counters(&self) -> Vec<Vec<u8>> {
        self.missing_counters.borrow().iter().cloned().collect()
    }

    /// Adds the live rows found under `prefix`; their values are served like fetched keys.
    pub fn fill_scan(&mut self, prefix: Vec<u8>, rows: Vec<(Vec<u8>, Option<Value>, u64)>) {
        self.missing_scans.borrow_mut().remove(&prefix);
        let keys = rows.iter().map(|(k, _, _)| k.clone()).collect();
        self.fill(rows);
        self.scans.insert(prefix, keys);
    }

    /// The keys found under `prefix` with their values, noting the prefix as missing when it was
    /// not scanned yet.
    #[must_use]
    pub fn scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Value)> {
        let Some(keys) = self.scans.get(prefix) else {
            self.missing_scans.borrow_mut().insert(prefix.to_vec());
            return Vec::new();
        };
        keys.iter()
            .filter_map(|k| self.values_of(k).map(|v| (k.clone(), v)))
            .collect()
    }

    /// Prefixes asked for and not scanned yet.
    #[must_use]
    pub fn missing_scans(&self) -> Vec<Vec<u8>> {
        self.missing_scans.borrow().iter().cloned().collect()
    }

    /// Whether `key` was fetched.
    #[must_use]
    pub fn has(&self, key: &[u8]) -> bool {
        self.values.contains_key(key)
    }

    /// Every fetched key with its version.
    #[must_use]
    pub fn fetched(&self) -> Vec<(Vec<u8>, u64)> {
        self.values
            .iter()
            .map(|(k, (_, v))| (k.clone(), *v))
            .collect()
    }

    /// The version of a fetched key, 0 when absent or not fetched.
    #[must_use]
    pub fn version_of(&self, key: &[u8]) -> u64 {
        self.values.get(key).map_or(0, |(_, v)| *v)
    }

    /// Keys asked for and not fetched yet.
    #[must_use]
    pub fn missing(&self) -> Vec<Vec<u8>> {
        self.missing.borrow().iter().cloned().collect()
    }

    /// Clears the read set and the missing keys before an evaluation is run again.
    pub fn restart(&self) {
        self.reads.borrow_mut().clear();
        self.missing.borrow_mut().clear();
        self.missing_counters.borrow_mut().clear();
        self.missing_scans.borrow_mut().clear();
    }

    /// The keys served, with the version each had.
    #[must_use]
    pub fn read_set(&self) -> Vec<(Vec<u8>, u64)> {
        self.reads
            .borrow()
            .iter()
            .filter_map(|k| self.values.get(k).map(|(_, v)| (k.clone(), *v)))
            .collect()
    }
}

impl View for Snapshot {
    fn get(&self, key: &[u8]) -> Option<Value> {
        self.reads.borrow_mut().insert(key.to_vec());
        if let Some((v, _)) = self.values.get(key) {
            return v.clone();
        }
        self.missing.borrow_mut().insert(key.to_vec());
        None
    }
}

/// The request as the commit path sees it after the transport layer.
#[derive(Clone, Debug)]
pub struct Request {
    /// The domain addressed.
    pub domain: Digest,
    /// The mode.
    pub mode: Mode,
    /// The nonce.
    pub nonce: Vec<u8>,
    /// The intent.
    pub intent: IntentEnvelope,
    /// The meta-action body, for an intent in the `access` namespace.
    pub payload: Option<Payload>,
    /// Declared basis.
    pub basis: ExerciseBasis,
    /// Declared capacity.
    pub capacity: Capacity,
    /// Proofs sent with the request (L1-ADP-12).
    pub proofs: Vec<ProofRef>,
    /// The Exercise continued, for `continue` (L1-ADP-13).
    pub exercise: Option<Digest>,
    /// The position the reader has seen, as an opaque token (OP-141 m.22 (f)).
    pub consistency: Option<String>,
}

/// A proof as the request carries it (L1-ADP-12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofRef {
    /// A Claim's `COSE_Sign1`.
    Claim(Vec<u8>),
    /// A recorded Claim.
    ClaimRef(access_kernel::model::Id),
    /// The `ExerciseID` of an allowed `contribute`.
    Contribution(Digest),
}

/// What an evaluation produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    /// The Kernel decision.
    pub decision: Decision,
    /// State changes of an allowed meta-action.
    pub effects: Vec<Effect>,
    /// Budget draws of an allow (OP-141 m.26).
    pub draws: Vec<DrawSpec>,
    /// Budget counter keys and amounts an allowed release returns (OP-141 m.28 (g)).
    pub releases: Vec<(Vec<u8>, u64)>,
    /// Whether the meta-action widens authority (L0-META-28).
    pub expansion: bool,
    /// The accepted Action Schema of a domain action (OP-141 m.35 (e)).
    pub action: Option<Box<ActionSchema>>,
}

/// A budget draw: counter key, limit, demand and the unit of an `amount` term.
pub type DrawSpec = (Vec<u8>, u64, u64, Option<String>);

/// The step after one pass over the snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pass {
    /// Fetch these keys and run again.
    Need(Vec<Vec<u8>>),
    /// Fetch these counters and run again.
    NeedCounters(Vec<Vec<u8>>),
    /// Scan these prefixes and run again (OP-141 m.33).
    NeedScans(Vec<Vec<u8>>),
    /// The evaluation is complete over the snapshot.
    Done(Evaluation),
    /// A protocol rejection: no decision, no record (L0-EVAL-61).
    Rejected(Rejection),
}

fn deny(class: BlockerClass, subcode: &str, resolver: Resolver) -> Decision {
    Decision {
        outcome: KernelOutcome::Deny,
        blockers: vec![Blocker {
            class,
            subcode: Some(subcode.to_owned()),
            position: Position::Anchor,
            resolver,
            remediation: Remediation::NotSatisfiableByActor,
        }],
        unmet: Vec::new(),
        relied_on: Vec::new(),
    }
}

/// The blocker a refused meta-action produces.
fn meta_denial(e: MetaError) -> Decision {
    // P14, OP-141 m.28 (f)
    if e == MetaError::ReleaseExceedsDraw {
        return deny(
            BlockerClass::BudgetExhausted,
            "release-exceeds-draw",
            Resolver::Actor,
        );
    }
    let class = match e {
        MetaError::Ended => BlockerClass::Ended,
        _ => BlockerClass::NoCoveringAuthority,
    };
    deny(class, e.code(), Resolver::Root)
}

fn everything() -> Window {
    Window {
        from: 0,
        until: u64::MAX,
    }
}

/// A hop that covers exactly the intent, with `requirements`: how an implicit power enters the
/// evaluator, so its requirements are resolved like any other.
fn exact_hop(
    intent: &IntentEnvelope,
    scope: Option<ResourceSelector>,
    requirements: BTreeSet<access_kernel::model::RequirementTerm>,
) -> Hop {
    let resource = scope.unwrap_or_else(|| {
        ResourceSelector::Structural(Structural {
            namespace: intent
                .resources
                .first()
                .map_or_else(String::new, |r| r.namespace.clone()),
            prefix: Vec::new(),
            kind: None,
            attrs: BTreeMap::new(),
        })
    });
    Hop {
        authority: CanonicalAuthority {
            authority: AuthoritySet {
                actions: ActionSet {
                    exact: BTreeSet::from([intent.action.clone()]),
                    prefix: BTreeSet::new(),
                },
                resource,
                params: BTreeMap::new(),
                recipient: None,
                purpose: None,
            },
            constraints: ConstraintSet {
                validity: everything(),
                conditions: BTreeSet::new(),
                budget: BTreeSet::new(),
            },
            delegation: DelegationTerms {
                depth: 0,
                downstream_holder_class: None,
            },
            requirements,
        },
        status: HopStatus::Active,
        conditions_hold: true,
        budgets: Vec::new(),
    }
}

pub(crate) fn read<T: Canonical>(
    view: &dyn View,
    kind: &str,
    id: &access_kernel::model::Id,
) -> Option<T> {
    view.get(&meta::key(kind, id))
        .and_then(|v| T::from_value(&v).ok())
}

/// The lineage of a basis as Kernel hops, from the Anchor down to the basis Grant; an ended
/// Grant anywhere above makes the hops below it `Revoked` (INV-5).
pub(crate) fn lineage_hops(
    view: &dyn View,
    grant: &access_kernel::model::Id,
) -> Option<(Vec<Hop>, BTreeSet<Capacity>)> {
    let mut chain = Vec::new();
    let mut at = *grant;
    loop {
        if chain.len() >= meta::MAX_LINEAGE {
            return None;
        }
        let g: GrantState = read(view, kind::GRANT, &at)?;
        let next = g.content.basis;
        chain.push(g);
        match next {
            GrantBasis::Anchor(a) => {
                let anchor: AnchorState = read(view, kind::ANCHOR, &a)?;
                chain.reverse();
                let mut ended = anchor.ended.is_some();
                let capacities = chain.last()?.content.agency.clone();
                let hops = chain
                    .into_iter()
                    .map(|g| {
                        ended |= g.ended.is_some();
                        Hop {
                            authority: g.content.authority,
                            status: if ended {
                                HopStatus::Revoked
                            } else {
                                HopStatus::Active
                            },
                            conditions_hold: true,
                            budgets: Vec::new(),
                        }
                    })
                    .collect();
                return Some((hops, capacities));
            }
            GrantBasis::Holding(h) => at = h.grant,
        }
    }
}

/// The live `schema-definition` Acceptances of `namespace`: their SPPs (OP-141 m.35 (e)).
fn live_spps(view: &Snapshot, namespace: &str, now: u64) -> Vec<Spp> {
    let ids = match view.get(&access_kernel::schema::schemas_key(namespace)) {
        Some(Value::Array(ids)) => ids,
        _ => Vec::new(),
    };
    ids.iter()
        .filter_map(|v| Id::from_value(v).ok())
        .filter_map(|id| {
            let a =
                read::<ContentState>(view, kind::ACCEPTANCE, &id).filter(|a| a.ended.is_none())?;
            a.content
                .get("validity")
                .and_then(|w| Window::from_value(w).ok())
                .filter(|w| w.from <= now && now <= w.until)?;
            a.content.get("spp").and_then(|v| Spp::from_value(v).ok())
        })
        .collect()
}

/// `base` with the catalogs and reserved actions of the live SPPs of `namespace` (OP-141
/// m.35 (e), m.39 (c)).
pub(crate) fn accepted_catalog(
    view: &Snapshot,
    namespace: &str,
    now: u64,
    base: &Catalog,
) -> Catalog {
    let mut catalog = base.clone();
    for spp in live_spps(view, namespace, now) {
        let refs = spp.refs();
        catalog.catalogs.insert(
            spp.catalog_digest(),
            refs.iter().map(|(r, _)| r.clone()).collect(),
        );
        for (r, s) in refs {
            if s.reserved {
                catalog.reserved.insert(r);
            }
        }
    }
    catalog
}

/// The catalog an action of a domain namespace is evaluated with, and its Action Schema: the
/// live `schema-definition` Acceptances of the namespace (OP-141 m.35 (e), (f)).
///
/// # Errors
/// The `schema-not-accepted` subcode.
fn schema_catalog(
    view: &Snapshot,
    action: &ActionRef,
    now: u64,
    base: &Catalog,
) -> Result<(Catalog, ActionSchema), &'static str> {
    let mut found = None;
    let mut retired = false;
    for spp in live_spps(view, &action.namespace, now) {
        for (r, s) in spp.refs() {
            if r == *action {
                if spp.retirements.contains(&r) {
                    retired = true;
                } else {
                    found = Some(s.clone());
                }
            }
        }
    }
    match (found, retired) {
        (Some(s), _) => Ok((accepted_catalog(view, &action.namespace, now, base), s)),
        (None, true) => Err("retired"),
        (None, false) => Err("unknown-action"),
    }
}

/// Whether every while-condition of a hop holds now (OP-141 m.33); what is not fetched yet is
/// noted as missing and reads as not holding.
fn conditions_hold(
    view: &Snapshot,
    conditions: &BTreeSet<WhileCondition>,
    actor: Option<&Actor>,
    now: u64,
) -> bool {
    conditions.iter().all(|c| match c {
        WhileCondition::InstanceAlive(i) => {
            read::<InstanceState>(view, kind::INSTANCE, i).is_some_and(|s| s.ended.is_none())
        }
        WhileCondition::ClaimHeld {
            class,
            subject,
            acceptance,
        } => {
            let who = match subject {
                SubjectSelector::Party(p) => Some(*p),
                sel => actor
                    .map(|a| a.party)
                    .filter(|p| subject_le(&SubjectSelector::Party(*p), sel)),
            };
            who.is_some_and(|who| claim_held(view, class, &who, acceptance, now))
        }
    })
}

/// Whether `who` holds a current Claim of `class` that the Acceptance with digest `acceptance`
/// admits (OP-141 m.33 (b)).
fn claim_held(view: &Snapshot, class: &str, who: &Id, acceptance: &Digest, now: u64) -> bool {
    view.scan(&claim::member_prefix(class, who))
        .into_iter()
        .filter_map(|(_, v)| Id::from_value(&v).ok())
        .any(|id| {
            let Some(state) = read::<ClaimState>(view, kind::CLAIM, &id).filter(|s| {
                s.ended.is_none()
                    && s.statement.class == class
                    && s.statement.subject == *who
                    && s.statement.validity.from <= now
                    && now <= s.statement.validity.until
            }) else {
                return false;
            };
            let admitted = view
                .get(&meta::key(kind::ACCEPTANCES, &state.statement.issuer))
                .map(|v| match v {
                    Value::Array(ids) => ids,
                    _ => Vec::new(),
                })
                .unwrap_or_default()
                .iter()
                .filter_map(|v| Id::from_value(v).ok())
                .filter_map(|a| read::<ContentState>(view, kind::ACCEPTANCE, &a))
                .filter(|a| {
                    a.ended.is_none() && claim::acceptance_digest(&a.content) == *acceptance
                })
                .filter_map(|a| claim::Gate::of(&a.content).ok())
                .any(|g| g.admits_for(&g.use_.clone(), &state.statement, now));
            admitted && in_line(view, &id, &state.statement)
        })
}

/// Whether a recorded Claim asserts in its issuer line (TI-RT7, OP-141 m.30 (c), (d)).
fn in_line(view: &Snapshot, id: &Id, s: &Statement) -> bool {
    let successors = |of: &Id, line: &Statement, except: &Id| {
        view.scan(&claim::successor_prefix(of))
            .into_iter()
            .filter_map(|(_, v)| Id::from_value(&v).ok())
            .filter(|c| c != except)
            .filter(|c| {
                read::<ClaimState>(view, kind::CLAIM, c)
                    .is_some_and(|c| claim::same_line(line, &c.statement))
            })
            .count()
    };
    if successors(id, s, id) > 0 {
        return false;
    }
    s.supersedes.is_none_or(|prev| {
        read::<ClaimState>(view, kind::CLAIM, &prev)
            .filter(|p| claim::same_line(&p.statement, s))
            .is_none_or(|p| successors(&prev, &p.statement, id) == 0)
    })
}

/// Whether `party` may view decisions made on `basis`: the root of its Anchor, or the root of
/// the top Anchor or the extensional holder of a live Grant in its lineage (OP-141 m.38 (c)).
pub(crate) fn views(view: &Snapshot, basis: &ExerciseBasis, party: &Id) -> bool {
    let actor = Actor {
        party: *party,
        instance: Id([0; 16]),
    };
    let root_of = |a: &Id| {
        read::<AnchorState>(view, kind::ANCHOR, a)
            .is_some_and(|s| s.ended.is_none() && meta::root_requirements(&s, &actor).is_some())
    };
    let grant = match basis {
        ExerciseBasis::Anchor(a) => return root_of(a),
        ExerciseBasis::Holding(h) => h.grant,
        ExerciseBasis::Public(g) => *g,
    };
    let Some(ids) = chain_ids(view, &grant) else {
        return false;
    };
    let holds = ids.iter().any(|id| {
        read::<GrantState>(view, kind::GRANT, id).is_some_and(|g| {
            g.ended.is_none() && g.content.holder == SubjectSelector::Party(*party)
        })
    });
    holds || top_anchor(view, basis).is_some_and(|a| root_of(&a))
}

/// Whether Grant `g` is held by `party`, live along its lineage, and covers
/// `access:audit.export` by name (OP-141 m.38 (d), m.39 (b)).
pub(crate) fn audit_grant(view: &Snapshot, g: &Id, party: &Id) -> bool {
    let Some(state) = read::<GrantState>(view, kind::GRANT, g) else {
        return false;
    };
    let named = state
        .content
        .authority
        .authority
        .actions
        .exact
        .iter()
        .any(|a| a.namespace == meta::NAMESPACE && a.name == "audit.export");
    named
        && state.content.holder == SubjectSelector::Party(*party)
        && lineage_hops(view, g)
            .is_some_and(|(hops, _)| hops.iter().all(|h| h.status == HopStatus::Active))
}

/// The Anchor a basis rests on: the Anchor itself, or the top of the Grant's lineage.
fn top_anchor(view: &dyn View, basis: &ExerciseBasis) -> Option<access_kernel::model::Id> {
    let mut at = match basis {
        ExerciseBasis::Anchor(a) => return Some(*a),
        ExerciseBasis::Holding(h) => h.grant,
        ExerciseBasis::Public(g) => *g,
    };
    for _ in 0..meta::MAX_LINEAGE {
        let g: GrantState = read(view, kind::GRANT, &at)?;
        match g.content.basis {
            GrantBasis::Anchor(a) => return Some(a),
            GrantBasis::Holding(h) => at = h.grant,
        }
    }
    None
}

/// The live restriction policies that apply to a request (OP-141 m.27 (c)).
fn applicable_policies(
    view: &dyn View,
    basis: &ExerciseBasis,
    actor: Option<&Actor>,
) -> Vec<(access_kernel::model::Id, ContentState)> {
    let tagged =
        |k: &str, id: &access_kernel::model::Id| Value::Map(vec![(Value::text(k), id.to_value())]);
    let mut targets = vec![Value::text("domain")];
    if let Some(a) = top_anchor(view, basis) {
        targets.push(tagged("anchor", &a));
    }
    if let Some(a) = actor {
        targets.push(tagged("party", &a.party));
        targets.push(tagged("instance", &a.instance));
    }
    let mut out = Vec::new();
    for t in targets {
        let Some(Value::Array(ids)) = view.get(&meta::policies_key(&t)) else {
            continue;
        };
        for v in ids {
            let Ok(id) = access_kernel::model::Id::from_value(&v) else {
                continue;
            };
            if let Some(state) = read::<ContentState>(view, kind::POLICY, &id)
                && state.ended.is_none()
            {
                out.push((id, state));
            }
        }
    }
    out
}

/// The Grants of a lineage in the order of its hops.
fn chain_ids(
    view: &dyn View,
    grant: &access_kernel::model::Id,
) -> Option<Vec<access_kernel::model::Id>> {
    let mut ids = Vec::new();
    let mut at = *grant;
    loop {
        if ids.len() >= meta::MAX_LINEAGE {
            return None;
        }
        let g: GrantState = read(view, kind::GRANT, &at)?;
        ids.push(at);
        match g.content.basis {
            GrantBasis::Anchor(_) => {
                ids.reverse();
                return Some(ids);
            }
            GrantBasis::Holding(h) => at = h.grant,
        }
    }
}

/// The counter of one budget term of a Grant for the window holding `now` (OP-141 m.26 (a)),
/// with the window's reset time for a rolling window.
fn budget_key(
    grant: &access_kernel::model::Id,
    term: usize,
    window: BudgetWindow,
    now: u64,
) -> (Vec<u8>, Option<u64>) {
    let (start, resets) = match window {
        BudgetWindow::Total => (0, None),
        BudgetWindow::RollingSeconds(r) => {
            let len = r.saturating_mul(1_000).max(1);
            let start = now.saturating_sub(now.checked_rem(len).unwrap_or(0));
            (start, Some(start.saturating_add(len)))
        }
    };
    let key = suiss_crypto::dcbor::encode(
        &Value::Array(vec![
            Value::text("budget"),
            grant.to_value(),
            Value::Unsigned(u64::try_from(term).unwrap_or(u64::MAX)),
            Value::Unsigned(start),
        ]),
        suiss_crypto::dcbor::Limits::CEILING,
    )
    .unwrap_or_default();
    (key, resets)
}

/// The intent's demand on a budget term (OP-141 m.26 (b)); `None` for a negative amount.
fn demand(term: &BudgetDimension, intent: &IntentEnvelope) -> Option<u64> {
    match term {
        BudgetDimension::Count => Some(1),
        BudgetDimension::Amount(unit) => {
            let mut total: u64 = 0;
            for v in intent.params.values() {
                if let ParamValue::Amount { value, unit: u } = v
                    && u == unit
                {
                    total = total.checked_add(u64::try_from(*value).ok()?)?;
                }
            }
            Some(total)
        }
    }
}

/// Fills the budget states of a lineage's hops and returns the draws an allow makes (L0-EVAL-15,
/// OP-141 m.26); `None` while the lineage is not fetched yet.
fn budgets(
    view: &Snapshot,
    grant: &access_kernel::model::Id,
    intent: &IntentEnvelope,
    now: u64,
    hops: &mut [Hop],
) -> Option<Result<Vec<DrawSpec>, Rejection>> {
    let ids = chain_ids(view, grant)?;
    let mut draws = Vec::new();
    for (hop, id) in hops.iter_mut().zip(ids) {
        let g: GrantState = read(view, kind::GRANT, &id)?;
        for (i, term) in g.content.authority.constraints.budget.iter().enumerate() {
            let Some(d) = demand(&term.dimension, intent) else {
                return Some(Err(Rejection::Input));
            };
            if d == 0 {
                continue;
            }
            let (key, resets_at) = budget_key(&id, i, term.window, now);
            let used = view.counter(&key);
            // OP-141 m.28 (g)
            let limit = term
                .capacity
                .saturating_add(view.counter(&meta::released_key(&key)));
            hop.budgets.push(BudgetState {
                window: term.window,
                remaining: limit.saturating_sub(used),
                demand: d,
                resets_at,
            });
            let unit = match &term.dimension {
                BudgetDimension::Amount(u) => Some(u.clone()),
                BudgetDimension::Count => None,
            };
            draws.push((key, limit, d, unit));
        }
    }
    Some(Ok(draws))
}

/// The Instance's Mandate, if it has a live one; the first by id (C14).
fn mandate(view: &dyn View, actor: Option<&Actor>) -> Option<Mandate> {
    let actor = actor?;
    let list = view.get(&meta::key(kind::MANDATES, &actor.instance))?;
    let Value::Array(ids) = list else {
        return None;
    };
    ids.iter().find_map(|id| {
        let id = access_kernel::model::Id::from_value(id).ok()?;
        let m: MandateState = read(view, kind::MANDATE, &id)?;
        m.ended.is_none().then_some(Mandate {
            authority: m.envelope.authority,
            requirements: m.envelope.requirements,
        })
    })
}

/// What one evaluation is made against besides the request and the state.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    /// The intent digest Access computed (TI-11).
    pub intent_digest: Digest,
    /// The `ExerciseID` (L0-META-3).
    pub exercise: Digest,
    /// Position the decision record will have.
    pub pos: u64,
    /// The actor, `None` for an anonymous request.
    pub actor: Option<Actor>,
    /// Trusted time.
    pub now: u64,
    /// The pinned catalog.
    pub catalog: &'a Catalog,
    /// The usable proofs (OP-141 m.19 (f)).
    pub proofs: &'a [access_kernel::requirement::Proof],
    /// For a holding basis on a Grant held by a predicate, the actor's episode start.
    pub held: Option<u64>,
    /// Compiled restriction policies (OP-141 m.27 (d)).
    pub policies: &'a crate::restrict::Cache,
    /// Whether a `party_compromise` overlay covers the actor (OP-141 m.31).
    pub compromised: bool,
}

/// One pass of the evaluation over `snapshot` (§17.1.1 steps 7–8). Implicit powers of a
/// meta-action are decided by the Kernel's meta module; their requirements, and every domain
/// action, go through the Kernel evaluator.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the two branches, meta-action and domain action, read best together"
)]
pub fn pass(req: &Request, frame: &Frame<'_>, snapshot: &Snapshot) -> Pass {
    let Frame {
        intent_digest,
        exercise,
        pos,
        actor,
        now,
        catalog,
        proofs,
        held,
        policies,
        compromised,
    } = *frame;
    snapshot.restart();
    // SEC12, OP-141 m.31 (c), (d)
    if compromised && !matches!(req.payload, Some(Payload::InstanceTerminate { .. })) {
        return Pass::Done(Evaluation {
            decision: deny(BlockerClass::Restricted, "party-compromise", Resolver::Root),
            effects: Vec::new(),
            draws: Vec::new(),
            releases: Vec::new(),
            expansion: false,
            action: None,
        });
    }
    // OP-141 m.35 (e), (f)
    let accepted;
    let mut schema = None;
    let catalog = if req.payload.is_none() && req.intent.action.namespace != meta::NAMESPACE {
        match schema_catalog(snapshot, &req.intent.action, now, catalog) {
            Ok((c, s)) => {
                accepted = c;
                schema = Some(Box::new(s));
                &accepted
            }
            Err(subcode) => {
                let missing = snapshot.missing();
                if !missing.is_empty() {
                    return Pass::Need(missing);
                }
                return Pass::Done(Evaluation {
                    decision: deny(BlockerClass::SchemaNotAccepted, subcode, Resolver::Root),
                    effects: Vec::new(),
                    draws: Vec::new(),
                    releases: Vec::new(),
                    expansion: false,
                    action: None,
                });
            }
        }
    } else {
        catalog
    };
    let mut effects = Vec::new();
    let mut draws = Vec::new();
    let mut releases = Vec::new();
    let mut expansion = false;
    // L0-META-30: a contribution is authorized like a domain action and records itself
    let contribute = matches!(req.payload, Some(Payload::Contribute { .. }));
    if let Some(payload) = req.payload.as_ref().filter(|_| contribute) {
        let Some(actor) = actor else {
            return Pass::Done(Evaluation {
                decision: deny(
                    BlockerClass::NoCoveringAuthority,
                    "anonymous-meta",
                    Resolver::Actor,
                ),
                effects,
                draws: Vec::new(),
                releases: Vec::new(),
                expansion: false,
                action: None,
            });
        };
        let ctx = meta::Context {
            domain: req.domain,
            exercise,
            pos,
            actor,
            basis: req.basis,
            capacity: req.capacity,
            catalog,
        };
        match meta::apply(&ctx, payload, snapshot) {
            Ok(out) => effects = out.effects,
            Err(e) => {
                return Pass::Done(Evaluation {
                    decision: meta_denial(e),
                    effects: Vec::new(),
                    draws: Vec::new(),
                    releases: Vec::new(),
                    expansion: false,
                    action: None,
                });
            }
        }
    }
    let (mut bases, mandate) = if let Some(payload) = req.payload.as_ref().filter(|_| !contribute) {
        let Some(actor) = actor else {
            return Pass::Done(Evaluation {
                decision: deny(
                    BlockerClass::NoCoveringAuthority,
                    "anonymous-meta",
                    Resolver::Actor,
                ),
                effects,
                draws: Vec::new(),
                releases: Vec::new(),
                expansion: false,
                action: None,
            });
        };
        let ctx = meta::Context {
            domain: req.domain,
            exercise,
            pos,
            actor,
            basis: req.basis,
            capacity: req.capacity,
            catalog,
        };
        let out = meta::apply(&ctx, payload, snapshot);
        let missing = snapshot.missing();
        if !missing.is_empty() {
            return Pass::Need(missing);
        }
        match out {
            Err(e) => {
                return Pass::Done(Evaluation {
                    decision: meta_denial(e),
                    effects,
                    draws: Vec::new(),
                    releases: Vec::new(),
                    expansion: false,
                    action: None,
                });
            }
            Ok(out) => {
                effects = out.effects;
                releases = out.releases;
                expansion = out.expansion;
                // L0-META-13: a self-acting meta-action names a live Grant held by Public that
                // covers it, like any other basis
                let basis = if let ExerciseBasis::Public(g) = req.basis {
                    let public = read::<GrantState>(snapshot, kind::GRANT, &g)
                        .filter(|s| {
                            s.content.holder == access_kernel::model::SubjectSelector::Public
                        })
                        .and_then(|_| lineage_hops(snapshot, &g));
                    let missing = snapshot.missing();
                    if !missing.is_empty() {
                        return Pass::Need(missing);
                    }
                    public.map(|(hops, capacities)| Basis {
                        hops: hops.into_iter().map(Stored::Known).collect(),
                        capacities,
                    })
                } else {
                    Some(Basis {
                        hops: vec![Stored::Known(exact_hop(
                            &req.intent,
                            None,
                            out.requirements,
                        ))],
                        capacities: BTreeSet::from([req.capacity]),
                    })
                };
                // L0-EVAL-16: a Mandate bounds meta-actions like any other action
                let mandate = mandate(snapshot, Some(&actor));
                let missing = snapshot.missing();
                if !missing.is_empty() {
                    return Pass::Need(missing);
                }
                (basis.into_iter().collect::<Vec<_>>(), mandate)
            }
        }
    } else {
        let hops = match req.basis {
            ExerciseBasis::Anchor(a) => read::<AnchorState>(snapshot, kind::ANCHOR, &a)
                .filter(|s| s.ended.is_none())
                .and_then(|s| {
                    let terms = meta::root_requirements(&s, actor.as_ref()?)?;
                    let scope = match s.scope {
                        meta::AnchorScope::Resource(r) => Some(r),
                        _ => None,
                    };
                    Some((
                        vec![exact_hop(&req.intent, scope, terms)],
                        BTreeSet::from([Capacity::Own]),
                    ))
                })
                .map(|hops| (hops, None)),
            ExerciseBasis::Holding(h) => read::<GrantState>(snapshot, kind::GRANT, &h.grant)
                .filter(|g| {
                    // OP-141 m.20 (c), (d): a predicate holder holds from its episode start
                    let holds = match &g.content.holder {
                        access_kernel::model::SubjectSelector::Party(p) => {
                            *p == h.holder && g.since == h.since
                        }
                        access_kernel::model::SubjectSelector::Pred(_) => held == Some(h.since),
                        _ => false,
                    };
                    actor.is_some_and(|a| a.party == h.holder) && holds
                })
                .and_then(|_| lineage_hops(snapshot, &h.grant))
                .map(|hops| (hops, Some(h.grant))),
            ExerciseBasis::Public(g) => read::<GrantState>(snapshot, kind::GRANT, &g)
                .filter(|s| s.content.holder == access_kernel::model::SubjectSelector::Public)
                .and_then(|_| lineage_hops(snapshot, &g))
                .map(|hops| (hops, Some(g))),
        };
        // OP-141 m.26: every hop's budget is drawn by this intent's demand
        let hops = match hops {
            Some(((mut hops, capacities), Some(g))) => {
                match budgets(snapshot, &g, &req.intent, now, &mut hops) {
                    Some(Ok(d)) => draws = d,
                    Some(Err(r)) => return Pass::Rejected(r),
                    None => {}
                }
                Some((hops, capacities))
            }
            Some((h, None)) => Some(h),
            None => None,
        };
        let missing_counters = snapshot.missing_counters();
        if !missing_counters.is_empty() {
            return Pass::NeedCounters(missing_counters);
        }
        let mandate = mandate(snapshot, actor.as_ref());
        let missing = snapshot.missing();
        if !missing.is_empty() {
            return Pass::Need(missing);
        }
        let bases = hops
            .map(|(hops, capacities)| Basis {
                hops: hops.into_iter().map(Stored::Known).collect(),
                capacities,
            })
            .into_iter()
            .collect::<Vec<_>>();
        (bases, mandate)
    };
    // L0-EVAL-4, OP-141 m.33
    for hop in bases.iter_mut().flat_map(|b| b.hops.iter_mut()) {
        if let Stored::Known(h) = hop
            && !h.authority.constraints.conditions.is_empty()
        {
            h.conditions_hold = conditions_hold(
                snapshot,
                &h.authority.constraints.conditions,
                actor.as_ref(),
                now,
            );
        }
    }
    let missing_scans = snapshot.missing_scans();
    if !missing_scans.is_empty() {
        return Pass::NeedScans(missing_scans);
    }
    let missing = snapshot.missing();
    if !missing.is_empty() {
        return Pass::Need(missing);
    }
    // OP-141 m.27 (c): the live policies of the domain, the Anchor, the Party and the Instance
    let applicable = applicable_policies(snapshot, &req.basis, actor.as_ref());
    let missing = snapshot.missing();
    if !missing.is_empty() {
        return Pass::Need(missing);
    }
    let restrictions = match crate::restrict::results(
        &applicable,
        &req.intent,
        actor.as_ref(),
        req.capacity,
        now,
        policies,
    ) {
        Ok(r) => r,
        Err(r) => return Pass::Rejected(r),
    };
    let input = EvaluationInput {
        mode: req.mode,
        intent: &req.intent,
        intent_digest,
        now,
        actor_instance: actor.map(|a| a.instance),
        actor_is_agent: false,
        mandate: mandate.as_ref(),
        capacity: req.capacity,
        bases: &bases,
        restrictions: &restrictions,
        proofs,
        catalog,
    };
    match evaluate(&input, &mut Fuel(FUEL)) {
        Ok(decision) => {
            if decision.outcome != KernelOutcome::Allow {
                effects.clear();
                draws.clear();
                releases.clear();
            }
            Pass::Done(Evaluation {
                decision,
                effects,
                draws,
                releases,
                expansion,
                action: schema,
            })
        }
        Err(r) => Pass::Rejected(r),
    }
}
