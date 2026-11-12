//! The pure part of the commit path (§17.1.1 steps 4–8, OP-63): a snapshot of the state that
//! records what it served, and the decision for one request over it.

pub mod export;
pub mod reasons;

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
use access_kernel::receipt::AgencyLink;
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
    /// The Approval Act Statement of a `contribute` (§9.14.1 step 4): a tagged `COSE_Sign1`
    /// under the approver Instance's key, or the bare dCBOR statement an H(AAS)-bound
    /// `authentication` Claim vouches for.
    Aas(Vec<u8>),
    /// A foreign domain's PAP with what verifies it (OP-143 m.13 (c)).
    ForeignPap {
        /// The foreign domain's binding-signed Domain Metadata.
        metadata: Vec<u8>,
        /// The PAP's `COSE_Sign1`.
        pap: Vec<u8>,
        /// The key excerpt of the operational key that signed the PAP.
        excerpt: Vec<u8>,
        /// The holder's presentation for this request.
        presentation: Vec<u8>,
        /// The foreign domain's Token Status List that holds the PAP's entry, as the holder
        /// fetched it, with the excerpt of the `status-list` key that signed it (§9.15A.3,
        /// §9.12.4): the home domain's revocation reaches this domain through it.
        status: Option<(Vec<u8>, Vec<u8>)>,
    },
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
    /// The foreign PAP a bridging holding relied on (OP-143 m.13 (g)).
    pub foreign: Option<Vec<u8>>,
    /// The agency chain of an allowed Exercise made for another Party (OP-149 m.11).
    pub agency: Vec<AgencyLink>,
    /// The allow met the own terms of the break-glass Grant it used (G29, OP-157 m.19 (b)).
    pub breakglass: bool,
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

pub(crate) fn deny(class: BlockerClass, subcode: &str, resolver: Resolver) -> Decision {
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
        // OP-158 m.4 (a)
        MetaError::Restricted => BlockerClass::Restricted,
        _ => BlockerClass::NoCoveringAuthority,
    };
    deny(class, e.code(), Resolver::Root)
}

/// The answer to a commit whose basis does not resolve: not the actor's root or holding, a
/// `since` that does not match, or no such Grant. One answer for all, so existence does not
/// leak (OP-152 m.5 (a)).
fn unresolved_basis() -> Decision {
    Decision {
        outcome: KernelOutcome::Deny,
        blockers: vec![Blocker {
            class: BlockerClass::NoCoveringAuthority,
            subcode: None,
            position: Position::Hop(0),
            resolver: Resolver::Actor,
            remediation: Remediation::RouteToCoordinator,
        }],
        unmet: Vec::new(),
        relied_on: Vec::new(),
    }
}

/// Whether holding `h` names Grant `g` as its holder holds it now: the Party and episode of a
/// Party holder, the actor's episode of a predicate holder, or a bridged foreign holder
/// (OP-141 m.20 (c), (d), OP-143 m.13 (e)).
fn holding_matches(g: &GrantState, h: &meta::HoldingRef, held: Option<u64>, bridged: bool) -> bool {
    match &g.content.holder {
        access_kernel::model::SubjectSelector::Party(p) => *p == h.holder && g.since == h.since,
        access_kernel::model::SubjectSelector::Pred(_) => held == Some(h.since),
        access_kernel::model::SubjectSelector::Foreign { .. } => bridged && g.since == h.since,
        access_kernel::model::SubjectSelector::Public => false,
    }
}

/// An `authentication` term of the actor raised to the authenticator class of `tier`: a term
/// that asks for less is read as asking for the class, so a password, an OTP or a push alone
/// never meets it, CT0 included (§13.7.3, N-45, SEC10, SEC26).
fn with_tier_floors(
    mut term: access_kernel::model::RequirementTerm,
    tier: access_kernel::tier::Tier,
) -> access_kernel::model::RequirementTerm {
    let authentication = match term.proof_kind {
        access_kernel::model::ProofKind::Authentication => true,
        access_kernel::model::ProofKind::Claim => {
            term.class == access_kernel::claim::body::Class::Authentication.name()
        }
        _ => false,
    };
    if authentication {
        for (dim, floor) in access_kernel::assurance::floors(tier) {
            let level = term.assurance.entry(dim).or_insert(floor);
            *level = (*level).max(floor);
        }
    }
    term
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

/// The resources an Anchor's scope covers: a Resource Anchor its selector, a Party's
/// self-anchor its own `access.party:[hex]` subtree, the domain everything.
// E6, §7.9.2.5
fn anchor_selector(scope: &meta::AnchorScope) -> Option<ResourceSelector> {
    match scope {
        meta::AnchorScope::Resource(r) => Some(r.clone()),
        meta::AnchorScope::Party(p) => Some(ResourceSelector::Structural(Structural {
            namespace: String::from("access.party"),
            prefix: vec![hex16(p)],
            kind: None,
            attrs: BTreeMap::new(),
        })),
        meta::AnchorScope::Domain => None,
    }
}

fn hex16(id: &Id) -> String {
    use std::fmt::Write as _;
    id.0.iter().fold(String::with_capacity(32), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The lineage of a basis as Kernel hops, from the Anchor down to the basis Grant; an ended
/// Grant anywhere above makes the hops below it `Revoked` (INV-5).
pub(crate) fn lineage_hops(
    view: &Snapshot,
    grant: &access_kernel::model::Id,
) -> Option<(Vec<Hop>, BTreeSet<Capacity>)> {
    lineage_hops_at(view, grant, None)
}

/// [`lineage_hops`] at `now`: a commitment-scoped Grant whose commitment is not active now
/// is also `Lapsed` (EI-5, OP-156 m.3 (t)); without `now` only its terminal end is seen.
pub(crate) fn lineage_hops_at(
    view: &Snapshot,
    grant: &access_kernel::model::Id,
    now: Option<u64>,
) -> Option<(Vec<Hop>, BTreeSet<Capacity>)> {
    let mut chain = Vec::new();
    let mut at = *grant;
    loop {
        if chain.len() >= meta::MAX_LINEAGE {
            return None;
        }
        let g: GrantState = read(view, kind::GRANT, &at)?;
        let next = g.content.basis;
        // EI-5
        let scoped = crate::app::commitment::status(view, &at, &g, now)
            .or_else(|| crate::app::templates::support::status(view, &g, now));
        chain.push((g, scoped));
        match next {
            GrantBasis::Anchor(a) => {
                let anchor: AnchorState = read(view, kind::ANCHOR, &a)?;
                chain.reverse();
                let mut ended = anchor.ended.is_some();
                let capacities = chain.last()?.0.content.agency.clone();
                let hops = chain
                    .into_iter()
                    .map(|(g, scoped)| {
                        ended |= g.ended.is_some() || scoped == Some(HopStatus::Revoked);
                        Hop {
                            authority: g.content.authority,
                            status: if ended {
                                HopStatus::Revoked
                            } else {
                                scoped.unwrap_or(HopStatus::Active)
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

/// Puts the own terms of the break-glass Grant a meta-Exercise uses onto its hop: the
/// requirements of every Grant of its lineage, the Grant's validity and the lineage's status.
/// Implicit powers decide a meta-action, so without this a holding's approvals would never be
/// asked for; returns whether the hop now carries them (G29, TN-93, OP-157 m.19 (b)).
fn breakglass_terms(view: &Snapshot, req: &Request, now: u64, hop: &mut Hop) -> bool {
    let ExerciseBasis::Holding(h) = req.basis else {
        return false;
    };
    let Some(g) = read::<GrantState>(view, kind::GRANT, &h.grant) else {
        return false;
    };
    if crate::app::breakglass::of(req, Some(&g)).is_none() {
        return false;
    }
    hop.authority.constraints.validity = g.content.authority.constraints.validity;
    match lineage_hops_at(view, &h.grant, Some(now)) {
        Some((lineage, _)) => {
            for l in lineage {
                if hop.status == HopStatus::Active {
                    hop.status = l.status;
                }
                hop.authority.requirements.extend(l.authority.requirements);
            }
        }
        None => hop.status = HopStatus::Revoked,
    }
    true
}

/// The subcode that refuses a `projection.issue` on a holding whose lineage the application
/// has ended or lapsed at `now`: a closed case or an ended commitment anywhere above it, which
/// the Kernel's record status does not show (EI-5, OP-157 m.11, m.19 (c)).
fn projected_lapse(
    view: &Snapshot,
    payload: &Payload,
    basis: ExerciseBasis,
    now: u64,
) -> Option<&'static str> {
    let (Payload::ProjectionIssue { .. }, ExerciseBasis::Holding(h)) = (payload, basis) else {
        return None;
    };
    let (hops, _) = lineage_hops_at(view, &h.grant, Some(now))?;
    hops.iter().find_map(|hop| match hop.status {
        HopStatus::Active => None,
        HopStatus::Revoked => Some("ended/revoked"),
        HopStatus::Lapsed => Some("ended/lapsed"),
    })
}

/// `ended/lapsed` when a conditional `anchor_transfer` Grant's while-conditions do not hold now
/// (OP-157 m.13 (b), OP-158 m.3 (b), L0-META-20a).
fn transfer_lapse(
    view: &Snapshot,
    payload: &Payload,
    basis: ExerciseBasis,
    actor: &Actor,
    now: u64,
) -> Option<&'static str> {
    let (Payload::AnchorTransfer { .. }, ExerciseBasis::Holding(h)) = (payload, basis) else {
        return None;
    };
    let g = read::<GrantState>(view, kind::GRANT, &h.grant)?;
    (!conditions_hold(
        view,
        &g.content.authority.constraints.conditions,
        Some(actor),
        now,
    ))
    .then_some("ended/lapsed")
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

/// The accepted action `namespace`/`name` of `major` now, with its pinned schema digest: a live
/// `schema-definition` Acceptance of the namespace declares it and has not retired it (OP-141
/// m.35 (e), OP-151 m.20 (a)).
pub(crate) fn accepted_action(
    view: &Snapshot,
    namespace: &str,
    name: &str,
    major: u64,
    now: u64,
) -> Option<ActionRef> {
    let mut found = None;
    for spp in live_spps(view, namespace, now) {
        for (r, _) in spp.refs() {
            if r.namespace == namespace && r.name == name && r.major == major {
                if spp.retirements.contains(&r) {
                    return None;
                }
                found = Some(r);
            }
        }
    }
    found
}

/// The accepted Action Schema of `action` now, if a live `schema-definition` Acceptance of its
/// namespace declares it and has not retired it (OP-141 m.35 (e)).
pub(crate) fn accepted_schema(
    view: &Snapshot,
    action: &ActionRef,
    now: u64,
) -> Option<ActionSchema> {
    schema_catalog(view, action, now, &Catalog::default())
        .ok()
        .map(|(_, s)| s)
}

/// Whether every while-condition of a hop holds now (OP-141 m.33); what is not fetched yet is
/// noted as missing and reads as not holding.
pub(crate) fn conditions_hold(
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
    claim_held_where(view, class, who, acceptance, now, |_| true)
}

/// Whether `who` holds a current Claim of `class` that the Acceptance with digest `acceptance`
/// admits and whose statement passes `keep` (OP-141 m.33 (b), OP-156 m.3 (t)).
pub(crate) fn claim_held_where(
    view: &Snapshot,
    class: &str,
    who: &Id,
    acceptance: &Digest,
    now: u64,
    keep: impl Fn(&Statement) -> bool,
) -> bool {
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
                    && keep(&s.statement)
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

/// Whether Grant `g` is held by `party` and makes it an auditor of `domain` at `now`: it
/// names `access:audit_export`, rests on the meta-anchor or covers the whole `access.audit`
/// namespace, and every hop of its lineage is live, in its validity window and free of
/// conditions and requirements an audit read cannot satisfy (OP-141 m.38 (d), m.39 (b)).
pub(crate) fn audit_grant(view: &Snapshot, g: &Id, party: &Id, domain: &Digest, now: u64) -> bool {
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
        .any(|a| a.namespace == meta::NAMESPACE && a.name == export::EXPORT_ACTION);
    if !named || state.content.holder != SubjectSelector::Party(*party) {
        return false;
    }
    let audit = ResourceSelector::Structural(Structural {
        namespace: String::from(export::AUDIT_NAMESPACE),
        prefix: Vec::new(),
        kind: None,
        attrs: BTreeMap::new(),
    });
    let on_audit =
        access_kernel::algebra::resource_le(&audit, &state.content.authority.authority.resource);
    let on_meta = top_anchor(view, &ExerciseBasis::Public(*g)) == Some(meta::meta_anchor(domain));
    (on_meta || on_audit)
        && lineage_hops(view, g).is_some_and(|(hops, _)| {
            hops.iter().all(|h| {
                let c = &h.authority.constraints;
                h.status == HopStatus::Active
                    && c.validity.from <= now
                    && now <= c.validity.until
                    && c.conditions.is_empty()
                    && h.authority.requirements.is_empty()
            })
        })
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

/// The Grants of `basis`'s lineage and the Anchor it rests on, as far as they are stored
/// (TI-RT1, OP-158 m.3 (i)).
fn lineage_ids(view: &dyn View, basis: &ExerciseBasis) -> BTreeSet<access_kernel::model::Id> {
    let mut out = BTreeSet::new();
    let mut at = match basis {
        ExerciseBasis::Anchor(a) => {
            out.insert(*a);
            return out;
        }
        ExerciseBasis::Holding(h) => h.grant,
        ExerciseBasis::Public(g) => *g,
    };
    for _ in 0..meta::MAX_LINEAGE {
        out.insert(at);
        let Some(g) = read::<GrantState>(view, kind::GRANT, &at) else {
            break;
        };
        match g.content.basis {
            GrantBasis::Anchor(a) => {
                out.insert(a);
                break;
            }
            GrantBasis::Holding(h) => at = h.grant,
        }
    }
    out
}

/// Whether `req` uses a break-glass Grant, and the self-anchor its basis rests on, if it rests
/// on one (OP-157 m.3 (h)).
fn breakglass_facts(view: &dyn View, req: &Request) -> (bool, Option<access_kernel::model::Id>) {
    let used = match req.basis {
        ExerciseBasis::Holding(h) => {
            let g = read::<GrantState>(view, kind::GRANT, &h.grant);
            crate::app::breakglass::of(req, g.as_ref()).is_some()
        }
        _ => false,
    };
    let self_anchor = top_anchor(view, &req.basis).filter(|a| {
        read::<AnchorState>(view, kind::ANCHOR, a)
            .is_some_and(|s| matches!(s.scope, meta::AnchorScope::Party(_)))
    });
    (used, self_anchor)
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

/// The lineage commitment of a basis: the Anchor and the Grants of its lineage, root first,
/// under `access/lineage/v1` (L2-PAP-1, OP-143 m.11).
pub(crate) fn lineage_commitment(view: &Snapshot, basis: &ExerciseBasis) -> Option<Digest> {
    let ids = match basis {
        ExerciseBasis::Anchor(a) => vec![*a],
        ExerciseBasis::Holding(h) => {
            let chain = chain_ids(view, &h.grant)?;
            let first: GrantState = read(view, kind::GRANT, chain.first()?)?;
            let GrantBasis::Anchor(a) = first.content.basis else {
                return None;
            };
            core::iter::once(a).chain(chain).collect()
        }
        ExerciseBasis::Public(_) => return None,
    };
    let bytes = suiss_crypto::dcbor::encode(
        &Value::Array(ids.iter().map(Canonical::to_value).collect()),
        suiss_crypto::dcbor::Limits::CEILING,
    )
    .ok()?;
    Some(Digest(
        suiss_crypto::digest::context_digest("access/lineage/v1", &bytes).0,
    ))
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

/// Whether `basis` still stands: its Anchor, or every Grant and the Anchor of its lineage, has
/// not ended (INV-5). A record that cannot be read does not stand.
pub(crate) fn basis_live(view: &Snapshot, basis: &ExerciseBasis) -> bool {
    let grant = match basis {
        ExerciseBasis::Anchor(a) => {
            return read::<AnchorState>(view, kind::ANCHOR, a).is_some_and(|s| s.ended.is_none());
        }
        ExerciseBasis::Holding(h) => h.grant,
        ExerciseBasis::Public(g) => *g,
    };
    lineage_hops(view, &grant)
        .is_some_and(|(hops, _)| hops.iter().all(|h| h.status == HopStatus::Active))
}

/// Who delegated down a lineage and to whom its basis Grant may pass (§9.9.4, AGI-1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Delegators {
    /// The holder of each Grant above `grant` that a delegation derived from, nearest first.
    pub(crate) delegators: Vec<access_kernel::model::Id>,
    /// The one Party `grant`'s delegation terms let it pass to, while depth remains.
    pub(crate) may_pass_to: Option<access_kernel::model::Id>,
}

/// The [`Delegators`] of the lineage of `grant`, from the recorded Grants only; `None` when a
/// Grant is missing or the lineage is deeper than the Kernel walks.
pub(crate) fn delegators(view: &dyn View, grant: &access_kernel::model::Id) -> Option<Delegators> {
    let first: GrantState = read(view, kind::GRANT, grant)?;
    let terms = &first.content.authority.delegation;
    let may_pass_to = match (&terms.downstream_holder_class, terms.depth) {
        (Some(access_kernel::model::SubjectSelector::Party(p)), d) if d > 0 => Some(*p),
        _ => None,
    };
    let mut out = Delegators {
        delegators: Vec::new(),
        may_pass_to,
    };
    let mut basis = first.content.basis;
    loop {
        if out.delegators.len() >= meta::MAX_LINEAGE {
            return None;
        }
        match basis {
            GrantBasis::Anchor(_) => return Some(out),
            GrantBasis::Holding(h) => {
                out.delegators.push(h.holder);
                let g: GrantState = read(view, kind::GRANT, &h.grant)?;
                basis = g.content.basis;
            }
        }
    }
}

/// The counter of one budget term of a Grant for the window holding `now` (OP-141 m.26 (a)),
/// with the window's reset time for a rolling window.
pub(crate) fn budget_key(
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

/// The lineage budget terms an offline slice draws from, root first, with their demand:
/// `(grant, term index, term, demand)` (OP-143 m.12).
pub(crate) fn slice_terms(
    view: &Snapshot,
    grant: &access_kernel::model::Id,
    slice: &meta::SliceRequest,
) -> Option<
    Vec<(
        access_kernel::model::Id,
        usize,
        access_kernel::model::BudgetTerm,
        u64,
    )>,
> {
    let mut out = Vec::new();
    for id in chain_ids(view, grant)? {
        let g: GrantState = read(view, kind::GRANT, &id)?;
        for (i, term) in g.content.authority.constraints.budget.iter().enumerate() {
            let demand = match &term.dimension {
                BudgetDimension::Count => slice.count,
                BudgetDimension::Amount(unit) => slice.amounts.get(unit).copied(),
            };
            if let Some(d) = demand.filter(|d| *d > 0) {
                out.push((id, i, term.clone(), d));
            }
        }
    }
    Some(out)
}

/// The budget states an offline slice puts on the projection's hop and the draws its commit
/// makes; `None` while the lineage is not fetched (OP-143 m.12).
fn slice_budgets(
    view: &Snapshot,
    grant: &access_kernel::model::Id,
    slice: &meta::SliceRequest,
    now: u64,
    hop: &mut Hop,
) -> Option<Vec<DrawSpec>> {
    let mut draws = Vec::new();
    for (id, i, term, demand) in slice_terms(view, grant, slice)? {
        let (key, resets_at) = budget_key(&id, i, term.window, now);
        let used = view.counter(&key);
        let limit = term
            .capacity
            .saturating_add(view.counter(&meta::released_key(&key)));
        hop.budgets.push(BudgetState {
            window: term.window,
            remaining: limit.saturating_sub(used),
            demand,
            resets_at,
        });
        let unit = match &term.dimension {
            BudgetDimension::Amount(u) => Some(u.clone()),
            BudgetDimension::Count => None,
        };
        draws.push((key, limit, demand, unit));
    }
    Some(draws)
}

/// The PAP's offline slice entries: one per lineage budget term the slice drew from, named
/// by `access/budget-term/v1` over `[GrantID, term index]` (OP-143 m.12).
pub(crate) fn slice_entries(
    view: &Snapshot,
    grant: &access_kernel::model::Id,
    slice: &meta::SliceRequest,
) -> Option<BTreeSet<access_kernel::validity::OfflineSlice>> {
    let mut out = BTreeSet::new();
    for (id, i, term, demand) in slice_terms(view, grant, slice)? {
        let name = suiss_crypto::dcbor::encode(
            &Value::Array(vec![id.to_value(), Value::Unsigned(u64::try_from(i).ok()?)]),
            suiss_crypto::dcbor::Limits::CEILING,
        )
        .ok()?;
        out.insert(access_kernel::validity::OfflineSlice {
            budget_term: Digest(
                suiss_crypto::digest::context_digest("access/budget-term/v1", &name).0,
            ),
            amount: demand,
            unit: match term.dimension {
                BudgetDimension::Amount(u) => u,
                BudgetDimension::Count => String::from("count"),
            },
        });
    }
    Some(out)
}

/// The agency chain of an allowed Exercise (OP-149 m.11, m.14 (d)): one link from the
/// principal the actor acted for to the actor's Party, under the live Mandate of the actor
/// Instance that bounded the decision. Acting for oneself, or with no live Mandate, has none.
fn agency(
    capacity: Capacity,
    actor: Option<&Actor>,
    mandate: Option<&(Id, Mandate)>,
    allowed: bool,
) -> Vec<AgencyLink> {
    match (capacity, actor, mandate) {
        (Capacity::For(principal), Some(actor), Some((id, _))) if allowed => vec![AgencyLink {
            mandate: *id,
            principal,
            agent: actor.party,
        }],
        _ => Vec::new(),
    }
}

/// A live Mandate with its id, and the draws an allow makes on its budget terms (`None` for a
/// negative demand).
type Found = ((Id, Mandate), Option<Vec<DrawSpec>>);

/// The Instance's Mandate and its id, if it has a live one; the first by id (C14). A Mandate
/// outside its window, whose while-conditions fail or whose budget is spent is still that
/// Mandate: the Kernel sees its limits at `now` and denies, never as "no Mandate" (INV-5, C27,
/// L0-EVAL-16b). With it come the draws an allow makes on its budget terms; `None` for the
/// draws on an intent whose demand is negative.
fn mandate(
    view: &Snapshot,
    actor: Option<&Actor>,
    (intent, basis): (&IntentEnvelope, ExerciseBasis),
    now: u64,
) -> Option<Found> {
    let actor = actor?;
    let list = view.get(&meta::key(kind::MANDATES, &actor.instance))?;
    let Value::Array(ids) = list else {
        return None;
    };
    let (id, m) = ids.iter().find_map(|id| {
        let id = access_kernel::model::Id::from_value(id).ok()?;
        let m: MandateState = read(view, kind::MANDATE, &id)?;
        m.ended.is_none().then_some((id, m))
    })?;
    // C14, L0-EVAL-16c
    let pin_holds = m
        .envelope
        .pin
        .is_none_or(|pin| basis == ExerciseBasis::Holding(pin));
    let constraints = m.envelope.constraints;
    let conditions_hold = constraints.conditions.is_empty()
        || conditions_hold(view, &constraints.conditions, Some(actor), now);
    // C27
    let mut budgets = Vec::new();
    let mut draws = Some(Vec::new());
    for (i, term) in constraints.budget.iter().enumerate() {
        let Some(d) = demand(&term.dimension, intent) else {
            draws = None;
            continue;
        };
        if d == 0 {
            continue;
        }
        let (key, resets_at) = budget_key(&id, i, term.window, now);
        let used = view.counter(&key);
        let limit = term
            .capacity
            .saturating_add(view.counter(&meta::released_key(&key)));
        budgets.push(BudgetState {
            window: term.window,
            remaining: limit.saturating_sub(used),
            demand: d,
            resets_at,
        });
        let unit = match &term.dimension {
            BudgetDimension::Amount(u) => Some(u.clone()),
            BudgetDimension::Count => None,
        };
        if let Some(draws) = draws.as_mut() {
            draws.push((key, limit, d, unit));
        }
    }
    Some((
        (
            id,
            Mandate {
                origins: m.envelope.origins,
                authority: m.envelope.authority,
                requirements: m.envelope.requirements,
                validity: Some(constraints.validity),
                conditions_hold,
                budgets,
                pin_holds,
            },
        ),
        draws,
    ))
}

/// The Mandate of [`mandate`] with its draws added to `draws`; a negative demand on its budget
/// is an input rejection, as on a hop's (OP-141 m.26 (b)).
fn with_mandate(
    found: Option<Found>,
    draws: &mut Vec<DrawSpec>,
) -> Result<Option<(Id, Mandate)>, Rejection> {
    match found {
        None => Ok(None),
        Some((_, None)) => Err(Rejection::Input),
        Some((m, Some(d))) => {
            draws.extend(d);
            Ok(Some(m))
        }
    }
}

fn foreign_deny(class: BlockerClass, subcode: &str, resolver: Resolver) -> Decision {
    let mut d = deny(class, subcode, resolver);
    for b in &mut d.blockers {
        b.position = Position::Foreign;
    }
    d
}

/// Largest inflated foreign status list, in bytes (OP-150 m.7 (g)).
const MAX_FOREIGN_LIST_BYTES: usize = 4 * 1024 * 1024;

/// The counter of what this domain has drawn from one offline slice term of a foreign PAP:
/// `dCBOR(["foreign-slice", ExerciseID, budget_term])` (§9.15A.3, INV-21). The home domain
/// drew the slice when it issued the projection; this domain only spends it, never more.
#[must_use]
pub fn foreign_slice_key(exercise: &Digest, budget_term: &Digest) -> Vec<u8> {
    suiss_crypto::dcbor::encode(
        &Value::Array(vec![
            Value::text("foreign-slice"),
            exercise.to_value(),
            budget_term.to_value(),
        ]),
        suiss_crypto::dcbor::Limits::CEILING,
    )
    .unwrap_or_default()
}

/// What a verified foreign PAP lets the request do: the PAP bytes for the record and the
/// slice draws its consumption makes here.
struct Bridged {
    pap: Vec<u8>,
    draws: Vec<DrawSpec>,
}

/// The PAP payload as the holder claims it, read before verification: only to name the slice
/// counters to fetch, never to decide.
fn claimed_pap(sign1: &[u8]) -> Option<access_kernel::pap::Pap> {
    let payload = access_kernel::verify::cose::parse_sign1(sign1)
        .ok()?
        .payload?;
    access_kernel::pap::Pap::from_bytes(&payload).ok()
}

/// The home domain's revocation at this domain (§9.15A.3, §9.12.4, 2494): a PAP whose contract
/// names a status entry is used only with a fresh list of the home domain, signed by its
/// `status-list` key, in which the entry is not set. No list, a stale list or an unreadable one
/// is `foreign-status`: the foreign status is unknown and the use is denied, never allowed on
/// the strength of the PAP alone. A set entry is `foreign-revoked`.
fn foreign_status(
    pap: &access_kernel::pap::Pap,
    metadata: &access_kernel::verify::key_scope::DomainMetadata,
    status: Option<&(Vec<u8>, Vec<u8>)>,
    now: u64,
) -> Result<(), &'static str> {
    use access_kernel::status::{CWT_CONTENT_TYPE, ListToken, lookup};
    use access_kernel::verify::PureBackend;
    use access_kernel::verify::cose::{parse_sign1, verify_sign1};
    use access_kernel::verify::key_scope::{KeyUsage, operational_key};
    let Some(reference) = &pap.validity.status else {
        return Ok(());
    };
    let (sign1, excerpt) = status.ok_or("foreign-status")?;
    let payload = parse_sign1(sign1)
        .ok()
        .and_then(|s| s.payload)
        .ok_or("foreign-status")?;
    let claimed = ListToken::from_bytes(&payload).map_err(|_| "foreign-status")?;
    let iat = claimed.iat.checked_mul(1_000).ok_or("foreign-status")?;
    let key = operational_key(
        &PureBackend,
        metadata,
        &metadata.domain,
        excerpt,
        KeyUsage::StatusList,
        iat,
        None,
    )
    .map_err(|_| "foreign-status")?;
    let verified = verify_sign1(&PureBackend, sign1, &key.key_set(), CWT_CONTENT_TYPE)
        .map_err(|_| "foreign-status")?;
    let token = ListToken::from_bytes(&verified.payload).map_err(|_| "foreign-status")?;
    let iat = token.iat.checked_mul(1_000).ok_or("foreign-status")?;
    // TI-RT5
    if iat.saturating_add(access_kernel::foreign::FRESHNESS_MS) < now {
        return Err("foreign-status");
    }
    let bits =
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&token.lst, MAX_FOREIGN_LIST_BYTES)
            .map_err(|_| "foreign-status")?;
    match lookup(&token, &bits, reference) {
        Ok(false) => Ok(()),
        Ok(true) => Err("foreign-revoked"),
        Err(_) => Err("foreign-status"),
    }
}

/// The draws one use of `intent` makes on the slice terms of the foreign `pap` here, each
/// bounded by the slice amount (§9.15A.3); `None` when the intent's demand does not fit a term.
fn slice_draws(pap: &access_kernel::pap::Pap, intent: &IntentEnvelope) -> Option<Vec<DrawSpec>> {
    let mut draws = Vec::new();
    for s in &pap.validity.offline_slice {
        let demand = access_kernel::pap::demand(&s.unit, intent)?;
        if demand == 0 {
            continue;
        }
        let unit = (s.unit != "count").then(|| s.unit.clone());
        draws.push((
            foreign_slice_key(&pap.projection_exercise, &s.budget_term),
            s.amount,
            demand,
            unit,
        ));
    }
    Some(draws)
}

/// One foreign PAP proof against the open gates for `used` (OP-143 m.13 (d)–(f), §9.15A.3):
/// the PAP bytes and the slice draws when a gate admits it, else the last gate's refusal.
fn bridge_proof(
    proof: &ProofRef,
    gates: &[access_kernel::foreign::ForeignGate],
    used: &access_kernel::foreign::Use<'_>,
    consumption: bool,
) -> Result<Bridged, &'static str> {
    use access_kernel::foreign::{self, Presented};
    let ProofRef::ForeignPap {
        metadata,
        pap,
        excerpt,
        presentation,
        status,
    } = proof
    else {
        return Err("foreign-pap-missing");
    };
    let presented = Presented {
        metadata,
        pap,
        excerpt,
        presentation,
    };
    let mut refusal = "foreign-pap-missing";
    for g in gates {
        let (verified, metadata) =
            match foreign::verify(&access_kernel::verify::PureBackend, g, &presented, used) {
                Ok(v) => v,
                Err(e) => {
                    refusal = e.code();
                    continue;
                }
            };
        if let Err(code) = foreign_status(&verified, &metadata, status.as_ref(), used.now) {
            refusal = code;
            continue;
        }
        // OP-143 m.13 (f), §9.15A.3
        if consumption && verified.validity.offline_slice.is_empty() {
            refusal = "foreign-consumption";
            continue;
        }
        let Some(draws) = slice_draws(&verified, used.intent) else {
            refusal = "pap-slice";
            continue;
        };
        return Ok(Bridged {
            pap: pap.clone(),
            draws,
        });
    }
    Err(refusal)
}

/// Whether the actor holds a bridging Grant whose holder is `ForeignAuthority(domain, class)`:
/// a live `foreign-authority` Acceptance covers the class, and a foreign PAP of the request
/// verifies under it for this intent (OP-143 m.13 (d)–(f), (h)). A consumption-bearing action
/// is covered only by a PAP that carries the home domain's offline slice, and what this domain
/// has drawn from the slice is counted here (§9.15A.3, INV-21). `Ok(None)` while a key or a
/// counter is still to be fetched; the PAP bytes and the slice draws on success; the DENY
/// otherwise.
fn bridge(
    req: &Request,
    view: &Snapshot,
    actor: Option<&Actor>,
    now: u64,
    catalog: &Catalog,
    schema: Option<&ActionSchema>,
    (domain, class): (&Digest, &str),
) -> Result<Option<Bridged>, Decision> {
    use access_kernel::foreign::{self, ForeignGate, Use};
    let Some(actor) = actor else {
        return Err(foreign_deny(
            BlockerClass::NoCoveringAuthority,
            "foreign-anonymous",
            Resolver::Actor,
        ));
    };
    let consumption = schema.is_some_and(|s| s.consumption_bearing);
    let key = read::<InstanceState>(view, kind::INSTANCE, &actor.instance)
        .filter(|i| i.ended.is_none())
        .map(|i| i.key);
    let gates: Vec<ForeignGate> = match view.get(&foreign::index_key(domain)) {
        Some(Value::Array(ids)) => ids
            .iter()
            .filter_map(|id| Id::from_value(id).ok())
            .filter_map(|id| read::<ContentState>(view, kind::ACCEPTANCE, &id))
            .filter(|a| a.ended.is_none())
            .filter_map(|a| ForeignGate::of(&a.content).ok().flatten())
            .filter(|g| g.opens(domain, class, now))
            .collect(),
        _ => Vec::new(),
    };
    if !view.missing().is_empty() {
        return Ok(None);
    }
    if gates.is_empty() {
        return Err(foreign_deny(
            BlockerClass::SourceNotAccepted,
            "foreign-not-accepted",
            Resolver::Root,
        ));
    }
    let Some(actor_key) = key else {
        return Err(foreign_deny(
            BlockerClass::NoCoveringAuthority,
            "foreign-actor",
            Resolver::Actor,
        ));
    };
    let mut refusal = "foreign-pap-missing";
    for p in &req.proofs {
        let ProofRef::ForeignPap { pap, .. } = p else {
            continue;
        };
        if foreign::claimed_domain(pap).as_ref() != Some(domain) {
            continue;
        }
        // §9.15A.3
        let mut remaining = BTreeMap::new();
        if let Some(claimed) = claimed_pap(pap) {
            for s in &claimed.validity.offline_slice {
                let used = view.counter(&foreign_slice_key(
                    &claimed.projection_exercise,
                    &s.budget_term,
                ));
                remaining.insert(s.budget_term, s.amount.saturating_sub(used));
            }
        }
        if !view.missing_counters().is_empty() {
            return Ok(None);
        }
        let used = Use {
            domain: &req.domain,
            intent: &req.intent,
            nonce: &req.nonce,
            now,
            catalog,
            actor_key: &actor_key,
            class,
            remaining: &remaining,
        };
        match bridge_proof(p, &gates, &used, consumption) {
            Ok(b) => return Ok(Some(b)),
            Err(code) => refusal = code,
        }
    }
    let class = match refusal {
        "foreign-stale" | "foreign-status" => BlockerClass::ForeignStatusUnavailable,
        "foreign-pap-missing" => BlockerClass::SourceNotAccepted,
        "foreign-consumption" => BlockerClass::BudgetExhausted,
        _ => BlockerClass::NoCoveringAuthority,
    };
    Err(foreign_deny(class, refusal, Resolver::Actor))
}

/// Whether one candidate basis covers `intent` without any mapping: every hop it holds, and the
/// Mandate if there is one (§9.13.4, SEC16).
fn covered_directly(
    bases: &[Basis],
    mandate: Option<&(Id, Mandate)>,
    intent: &IntentEnvelope,
    catalog: &Catalog,
) -> bool {
    let mandate_ok =
        mandate.is_none_or(|(_, m)| access_kernel::intent::covers(&m.authority, intent, catalog));
    mandate_ok
        && bases.iter().any(|b| {
            b.hops.iter().all(|h| match h {
                Stored::Known(h) => {
                    access_kernel::intent::covers(&h.authority.authority, intent, catalog)
                }
                Stored::NotUnderstood => false,
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
    /// The DENY overlay that covers the actor, by its subcode: a `party_compromise` (OP-141
    /// m.31), a narrowing account status or a regime overlay (§9.13, E5).
    pub compromised: Option<&'static str>,
    /// The accepted external signals the restriction context reads (OP-156 m.3 (r)).
    pub signals: &'a crate::restrict::Signals,
    /// The `derived.*` values the restriction context reads (§16.5, OP-157 m.3 (o)).
    pub derived: &'a crate::restrict::derived::Derived,
    /// The control-plane analysis raised this `policy.set` to expansion (OP-157 m.3 (n)).
    pub widened: bool,
    /// The mappings pinned for the intent's action when the request began; only those a live
    /// Acceptance still pins in the snapshot apply (OP-157 m.3 (r)).
    pub mappings: &'a [crate::app::compat::Pinned],
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
        signals,
        derived,
        widened,
        mappings,
    } = *frame;
    snapshot.restart();
    // SEC12, OP-141 m.31 (c), (d)
    if let Some(code) = compromised
        && !matches!(req.payload, Some(Payload::InstanceTerminate { .. }))
    {
        return Pass::Done(Evaluation {
            decision: deny(BlockerClass::Restricted, code, Resolver::Root),
            effects: Vec::new(),
            draws: Vec::new(),
            releases: Vec::new(),
            expansion: false,
            action: None,
            foreign: None,
            agency: Vec::new(),
            breakglass: false,
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
                    foreign: None,
                    agency: Vec::new(),
                    breakglass: false,
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
    let mut own_terms = matches!(req.basis, ExerciseBasis::Holding(_));
    // L0-META-30
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
                foreign: None,
                agency: Vec::new(),
                breakglass: false,
            });
        };
        let ctx = meta::Context {
            domain: req.domain,
            exercise,
            pos,
            now,
            actor,
            basis: req.basis,
            capacity: req.capacity,
            catalog,
        };
        let applied = meta::apply(&ctx, payload, snapshot);
        // L0-EVAL-26a
        let missing = snapshot.missing();
        if !missing.is_empty() {
            return Pass::Need(missing);
        }
        match applied {
            Ok(out) => effects = out.effects,
            Err(e) => {
                return Pass::Done(Evaluation {
                    decision: meta_denial(e),
                    effects: Vec::new(),
                    draws: Vec::new(),
                    releases: Vec::new(),
                    expansion: false,
                    action: None,
                    foreign: None,
                    agency: Vec::new(),
                    breakglass: false,
                });
            }
        }
    }
    // OP-143 m.13 (e)
    let mut foreign_pap = None;
    if (req.payload.is_none() || contribute)
        && let ExerciseBasis::Holding(h) = req.basis
        && let Some(g) = read::<GrantState>(snapshot, kind::GRANT, &h.grant)
        && let SubjectSelector::Foreign { domain, class } = &g.content.holder
    {
        match bridge(
            req,
            snapshot,
            actor.as_ref(),
            now,
            catalog,
            schema.as_deref(),
            (domain, class),
        ) {
            Ok(None) => {
                let missing_counters = snapshot.missing_counters();
                if !missing_counters.is_empty() {
                    return Pass::NeedCounters(missing_counters);
                }
                return Pass::Need(snapshot.missing());
            }
            Ok(Some(b)) => {
                foreign_pap = Some(b.pap);
                draws.extend(b.draws);
            }
            Err(decision) => {
                return Pass::Done(Evaluation {
                    decision,
                    effects: Vec::new(),
                    draws: Vec::new(),
                    releases: Vec::new(),
                    expansion: false,
                    action: None,
                    foreign: None,
                    agency: Vec::new(),
                    breakglass: false,
                });
            }
        }
    }
    let (mut bases, mut mandate) = if let Some(payload) =
        req.payload.as_ref().filter(|_| !contribute)
    {
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
                foreign: None,
                agency: Vec::new(),
                breakglass: false,
            });
        };
        let ctx = meta::Context {
            domain: req.domain,
            exercise,
            pos,
            now,
            actor,
            basis: req.basis,
            capacity: req.capacity,
            catalog,
        };
        let mut out = meta::apply(&ctx, payload, snapshot);
        // OP-157 m.3 (n)
        if widened && let Ok(o) = out.as_mut() {
            meta::widen(&ctx, payload, snapshot, o);
        }
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
                    foreign: None,
                    agency: Vec::new(),
                    breakglass: false,
                });
            }
            Ok(out) => {
                // EI-5, OP-156 m.3 (t)
                let admissible = crate::app::commitment::admissible(snapshot, &req.intent, payload);
                // MD-9, TN-71, OP-157 m.3 (c)
                let support =
                    crate::app::templates::support::admissible(snapshot, payload, req.basis, now);
                // EI-5, OP-157 m.11, m.19 (c)
                let lapsed = projected_lapse(snapshot, payload, req.basis, now)
                    .or_else(|| transfer_lapse(snapshot, payload, req.basis, &actor, now));
                let missing_scans = snapshot.missing_scans();
                if !missing_scans.is_empty() {
                    return Pass::NeedScans(missing_scans);
                }
                let missing = snapshot.missing();
                if !missing.is_empty() {
                    return Pass::Need(missing);
                }
                if let Err(reason) = support {
                    let class = if reason == crate::app::templates::support::PROTECTED_ACTION {
                        BlockerClass::Restricted
                    } else {
                        BlockerClass::NoCoveringAuthority
                    };
                    return Pass::Done(Evaluation {
                        decision: deny(class, reason, Resolver::Actor),
                        effects: Vec::new(),
                        draws: Vec::new(),
                        releases: Vec::new(),
                        expansion: false,
                        action: None,
                        foreign: None,
                        agency: Vec::new(),
                        breakglass: false,
                    });
                }
                if let Some(subcode) = lapsed {
                    return Pass::Done(Evaluation {
                        decision: deny(BlockerClass::Ended, subcode, Resolver::Root),
                        effects: Vec::new(),
                        draws: Vec::new(),
                        releases: Vec::new(),
                        expansion: false,
                        action: None,
                        foreign: None,
                        agency: Vec::new(),
                        breakglass: false,
                    });
                }
                if !admissible {
                    return Pass::Done(Evaluation {
                        decision: deny(
                            BlockerClass::NoCoveringAuthority,
                            "commitment-ref",
                            Resolver::Actor,
                        ),
                        effects: Vec::new(),
                        draws: Vec::new(),
                        releases: Vec::new(),
                        expansion: false,
                        action: None,
                        foreign: None,
                        agency: Vec::new(),
                        breakglass: false,
                    });
                }
                // OP-153 m.10 (e), OP-152 m.5 (a)
                if let ExerciseBasis::Holding(h) = req.basis {
                    let resolves =
                        read::<GrantState>(snapshot, kind::GRANT, &h.grant).is_some_and(|g| {
                            actor.party == h.holder && holding_matches(&g, &h, held, false)
                        });
                    let missing = snapshot.missing();
                    if !missing.is_empty() {
                        return Pass::Need(missing);
                    }
                    if !resolves {
                        return Pass::Done(Evaluation {
                            decision: unresolved_basis(),
                            effects: Vec::new(),
                            draws: Vec::new(),
                            releases: Vec::new(),
                            expansion: false,
                            action: None,
                            foreign: None,
                            agency: Vec::new(),
                            breakglass: false,
                        });
                    }
                }
                effects = out.effects;
                releases = out.releases;
                expansion = out.expansion;
                // L0-META-13
                let basis = if let ExerciseBasis::Public(g) = req.basis {
                    let public = read::<GrantState>(snapshot, kind::GRANT, &g)
                        .filter(|s| {
                            s.content.holder == access_kernel::model::SubjectSelector::Public
                        })
                        .and_then(|_| lineage_hops_at(snapshot, &g, Some(now)));
                    let missing = snapshot.missing();
                    if !missing.is_empty() {
                        return Pass::Need(missing);
                    }
                    public.map(|(hops, capacities)| Basis {
                        hops: hops.into_iter().map(Stored::Known).collect(),
                        capacities,
                    })
                } else {
                    let mut hop = exact_hop(&req.intent, None, out.requirements);
                    // G29, TN-93, OP-157 m.19 (b)
                    own_terms = breakglass_terms(snapshot, req, now, &mut hop);
                    // OP-143 m.12
                    if let (
                        Some(Payload::ProjectionIssue {
                            offline_slice: Some(slice),
                            ..
                        }),
                        ExerciseBasis::Holding(h),
                    ) = (&req.payload, req.basis)
                    {
                        let Some(d) = slice_budgets(snapshot, &h.grant, slice, now, &mut hop)
                        else {
                            return Pass::Need(snapshot.missing());
                        };
                        draws = d;
                        let missing_counters = snapshot.missing_counters();
                        if !missing_counters.is_empty() {
                            return Pass::NeedCounters(missing_counters);
                        }
                    }
                    Some(Basis {
                        hops: vec![Stored::Known(hop)],
                        capacities: BTreeSet::from([req.capacity]),
                    })
                };
                // L0-EVAL-16, L0-EVAL-16b
                let found = mandate(snapshot, Some(&actor), (&req.intent, req.basis), now);
                let missing = snapshot.missing();
                if !missing.is_empty() {
                    return Pass::Need(missing);
                }
                let missing_counters = snapshot.missing_counters();
                if !missing_counters.is_empty() {
                    return Pass::NeedCounters(missing_counters);
                }
                let mandate = match with_mandate(found, &mut draws) {
                    Ok(m) => m,
                    Err(r) => return Pass::Rejected(r),
                };
                (basis.into_iter().collect::<Vec<_>>(), mandate)
            }
        }
    } else {
        let hops = match req.basis {
                ExerciseBasis::Anchor(a) => read::<AnchorState>(snapshot, kind::ANCHOR, &a)
                    .filter(|s| s.ended.is_none())
                    .and_then(|s| {
                        let a = actor.as_ref()?;
                        let terms = meta::root_requirements(&s, a)?;
                        // L0-META-30, TN-91
                        let own = matches!(&req.payload, Some(Payload::Contribute { class, .. })
                            if access_kernel::contribution::self_authorized(class, &s.scope, &a.party));
                        let selector = if own {
                            None
                        } else {
                            anchor_selector(&s.scope)
                        };
                        Some((
                            vec![exact_hop(&req.intent, selector, terms)],
                            BTreeSet::from([Capacity::Own]),
                        ))
                    })
                    .map(|hops| (hops, None)),
                ExerciseBasis::Holding(h) => read::<GrantState>(snapshot, kind::GRANT, &h.grant)
                    .filter(|g| {
                        actor.is_some_and(|a| a.party == h.holder)
                            && holding_matches(g, &h, held, foreign_pap.is_some())
                    })
                    .and_then(|_| lineage_hops_at(snapshot, &h.grant, Some(now)))
                    .map(|hops| (hops, Some(h.grant))),
                ExerciseBasis::Public(g) => read::<GrantState>(snapshot, kind::GRANT, &g)
                    .filter(|s| s.content.holder == access_kernel::model::SubjectSelector::Public)
                    .and_then(|_| lineage_hops_at(snapshot, &g, Some(now)))
                    .map(|hops| (hops, Some(g))),
            };
        // OP-141 m.26
        // §9
        let hops = match hops {
            Some(((mut hops, capacities), Some(g))) => {
                match budgets(snapshot, &g, &req.intent, now, &mut hops) {
                    Some(Ok(d)) => draws.extend(d),
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
        // L0-EVAL-16b
        let found = mandate(snapshot, actor.as_ref(), (&req.intent, req.basis), now);
        let missing = snapshot.missing();
        if !missing.is_empty() {
            return Pass::Need(missing);
        }
        let missing_counters = snapshot.missing_counters();
        if !missing_counters.is_empty() {
            return Pass::NeedCounters(missing_counters);
        }
        let mandate = match with_mandate(found, &mut draws) {
            Ok(m) => m,
            Err(r) => return Pass::Rejected(r),
        };
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
    // OP-141 m.27 (c)
    let mut applicable = applicable_policies(snapshot, &req.basis, actor.as_ref());
    let missing = snapshot.missing();
    if !missing.is_empty() {
        return Pass::Need(missing);
    }
    // PI-19, OP-157 m.3 (r)
    let live_pins = if mappings.is_empty() {
        BTreeMap::new()
    } else {
        crate::app::compat::pins(snapshot, &req.intent.action.namespace, now)
    };
    let missing = snapshot.missing();
    if !missing.is_empty() {
        return Pass::Need(missing);
    }
    let mappings: Vec<access_kernel::compat::Mapping> = mappings
        .iter()
        .filter(|p| live_pins.contains_key(&p.digest))
        .map(|p| p.mapping.clone())
        .collect();
    let mut derived = derived.clone();
    // SEC16, OP-157 m.3 (r)
    if mappings.is_empty() || covered_directly(&bases, mandate.as_ref(), &req.intent, catalog) {
        derived.mapping_pin_age_s = crate::restrict::derived::NONE;
    }
    if derived.mapping_pin_age_s >= 0
        && let Some(probation) = crate::restrict::patterns::mapping_probation()
    {
        applicable.push((
            meta::object_id(
                &req.domain,
                kind::POLICY,
                crate::restrict::patterns::PROBATION_SEQ,
            ),
            ContentState {
                content: probation,
                since: 0,
                widened: None,
                ended: None,
            },
        ));
    }
    // OP-149 m.8
    let actor_is_agent = actor
        .as_ref()
        .is_some_and(|a| meta::actor_is_agent(snapshot, &a.party));
    let missing = snapshot.missing();
    if !missing.is_empty() {
        return Pass::Need(missing);
    }
    // E9, §13.7.3, N-45, SEC10, SEC26, SEC30
    let tier = crate::requirements::tier_of(
        &req.intent,
        req.payload.as_ref(),
        expansion,
        schema.as_deref(),
        derived.payee_seen > 0,
    );
    // G29, TN-93, TN-71
    let (breakglass, self_anchor) = breakglass_facts(snapshot, req);
    // TI-RT1, OP-158 m.3 (i)
    let lineage = lineage_ids(snapshot, &req.basis);
    let missing = snapshot.missing();
    if !missing.is_empty() {
        return Pass::Need(missing);
    }
    // E54 (1), §11.19
    let facts = crate::restrict::Facts {
        agent: actor_is_agent,
        tier: crate::app::approval::tier_code(tier),
        signals: signals.clone(),
        derived,
        breakglass,
        self_anchor,
        basis: lineage,
    };
    let mut restrictions = match crate::restrict::results_with(
        &applicable,
        &req.intent,
        (actor.as_ref(), req.capacity),
        &facts,
        now,
        policies,
    ) {
        Ok(r) => r,
        Err(r) => return Pass::Rejected(r),
    };
    // OP-152 m.5 (a)
    if bases.is_empty() && req.mode != Mode::Check {
        return Pass::Done(Evaluation {
            decision: unresolved_basis(),
            effects: Vec::new(),
            draws: Vec::new(),
            releases: Vec::new(),
            expansion: false,
            action: schema,
            foreign: None,
            agency: Vec::new(),
            breakglass: false,
        });
    }
    // E49, OP-154 m.3 (x)
    let floors = crate::requirements::ceiling(tier, schema.as_deref(), mandate.is_some());
    let terms = bases
        .iter_mut()
        .flat_map(|b| b.hops.iter_mut())
        .filter_map(|h| match h {
            Stored::Known(h) => Some(&mut h.authority.requirements),
            Stored::NotUnderstood => None,
        })
        .chain(mandate.as_mut().map(|(_, m)| &mut m.requirements));
    for t in terms {
        *t = core::mem::take(t)
            .into_iter()
            .map(|term| crate::requirements::with_ceiling(with_tier_floors(term, tier), &floors))
            .collect();
    }
    for r in &mut restrictions {
        if let access_kernel::restriction::RestrictionOutcome::Require(t) = &mut r.outcome {
            *t = core::mem::take(t)
                .into_iter()
                .map(|term| crate::requirements::with_ceiling(term, &floors))
                .collect();
        }
    }
    // AGI-4, AGI-8
    let proofs =
        crate::requirements::admissible(proofs, actor.as_ref(), actor_is_agent, tier, snapshot);
    let missing = snapshot.missing();
    if !missing.is_empty() {
        return Pass::Need(missing);
    }
    let input = EvaluationInput {
        mode: req.mode,
        intent: &req.intent,
        intent_digest,
        now,
        actor_instance: actor.map(|a| a.instance),
        actor_party: actor.map(|a| a.party),
        actor_is_agent,
        mandate: mandate.as_ref().map(|(_, m)| m),
        capacity: req.capacity,
        bases: &bases,
        restrictions: &restrictions,
        proofs: &proofs,
        catalog,
        // OP-157 m.3 (r)
        mappings: &mappings,
    };
    match evaluate(&input, &mut Fuel(FUEL)) {
        Ok(decision) => {
            let allowed = decision.outcome == KernelOutcome::Allow;
            if !allowed {
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
                foreign: foreign_pap,
                agency: agency(req.capacity, actor.as_ref(), mandate.as_ref(), allowed),
                breakglass: allowed && breakglass && own_terms,
            })
        }
        Err(r) => Pass::Rejected(r),
    }
}
