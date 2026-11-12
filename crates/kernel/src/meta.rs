//! Core meta-actions: who may run each one and the state it changes (C3, INV-2, OP-141, L2-META).
//!
//! A meta-action is an Exercise whose intent action is in the `access` namespace and whose body
//! is a [`Payload`]. Its authority is either one of the three implicit powers of OP-141 m.3
//! (root, holding, own Instance) or an ordinary Grant over the core action; this module decides
//! the implicit powers and the payload's own rules, and returns the effects of an ALLOW.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

use crate::algebra::{Catalog, child_within_parent, resource_le, subsumes};
use crate::codec::{Canonical, Fields, ModelError, map, set_of, set_value, single, tagged, uint};
use crate::combinator::Capacity;
use crate::digest::Digest;
use crate::fold::Effect;
use crate::model::{
    ActionRef, AuthoritySet, CanonicalAuthority, ConstraintSet, EqValue, Id, RequirementTerm,
    ResourceSelector, SubjectSelector, Window,
};
use crate::schema::{ActionSchema, EffectClass, action_digest};
use crate::validity::{CLASSES, ProfileClass, ProfileVariant, VARIANTS, word, word_of};
use crate::verify::cose::PublicKey;
use suiss_crypto::digest::context_digest as context_label;

mod polarity;

pub use polarity::{is_forbid, policy_narrows, statements};

/// Namespace of the core meta-actions.
pub const NAMESPACE: &str = "access";

/// The intent `opaque` member that carries the meta payload's digest (OP-141 m.13).
pub const PAYLOAD_PARAM: &str = "payload";

/// Longest lineage walked (OP-108 m.10).
pub const MAX_LINEAGE: usize = 16;

/// The reference of the core meta-action `name` (L0-META-1): the `access` namespace, major 1,
/// the schema of a reversible action without parameters, so every plane and product pins the
/// same digest.
#[must_use]
pub fn core_action(name: &str) -> ActionRef {
    let schema = ActionSchema {
        reversibility: None,
        name: String::from(name),
        major: 1,
        effect: EffectClass::Reversible,
        reserved: false,
        consumption_bearing: false,
        params: BTreeMap::new(),
        resource_types: BTreeSet::new(),
        render: None,
    };
    ActionRef {
        namespace: String::from(NAMESPACE),
        name: String::from(name),
        major: 1,
        schema: action_digest(&schema),
    }
}

/// A root value (C9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Root {
    /// One Party.
    Sole(Id),
    /// `k` of these Parties.
    Joint {
        /// The Parties.
        parties: BTreeSet<Id>,
        /// How many must act.
        k: u64,
    },
}

/// What an Anchor covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorScope {
    /// Resources.
    Resource(ResourceSelector),
    /// A Party's self-anchor (§7.9.2.3).
    Party(Id),
    /// The whole domain: the meta-anchor.
    Domain,
}

/// A holding episode (§5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HoldingRef {
    /// The Grant.
    pub grant: Id,
    /// The holder.
    pub holder: Id,
    /// Position that opened the episode.
    pub since: u64,
}

/// The basis a Grant derives from (C11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantBasis {
    /// An Anchor's root.
    Anchor(Id),
    /// A holding.
    Holding(HoldingRef),
}

/// The basis an Exercise names (INV-4, OP-141 m.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExerciseBasis {
    /// An Anchor's root.
    Anchor(Id),
    /// A holding.
    Holding(HoldingRef),
    /// A Grant held by `Public`.
    Public(Id),
}

/// Content of a Grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantContent {
    /// Where it derives from.
    pub basis: GrantBasis,
    /// Who holds it.
    pub holder: SubjectSelector,
    /// What, when, to whom and with what requirements.
    pub authority: CanonicalAuthority,
    /// Capacities the holder may exercise it in; absent is `{own}` (INV-4).
    pub agency: BTreeSet<Capacity>,
    /// The Named `AuthoritySet` version it pins, as `(name, version, digest)`.
    pub named: Option<NamedPin>,
}

/// A Mandate's envelope (C14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MandateEnvelope {
    /// What may be exercised.
    pub authority: AuthoritySet,
    /// When and how much.
    pub constraints: ConstraintSet,
    /// What must be presented.
    pub requirements: BTreeSet<RequirementTerm>,
    /// The holding it is pinned to.
    pub pin: Option<HoldingRef>,
    /// The origins the task may read and write (E54 (4)).
    pub origins: crate::combinator::Origins,
}

/// What happens to a dependent Grant (C10, E6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// It stays.
    Keep,
    /// It is revoked.
    Revoke,
}

/// The witness and replica sets of an Anchor's root terms (OP-158 m.11 5984, OP-159 m.3 (j)):
/// only a witness or replica the canonical state names counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RootSets {
    /// The witnesses, with their keys, operators, independence and algorithms.
    pub witnesses: Vec<crate::verify::key_scope::Witness>,
    /// The replicas.
    pub replicas: Vec<crate::verify::key_scope::Replica>,
}

impl RootSets {
    /// The sets `witnesses` and `replicas`.
    #[must_use]
    pub const fn new(
        witnesses: Vec<crate::verify::key_scope::Witness>,
        replicas: Vec<crate::verify::key_scope::Replica>,
    ) -> Self {
        Self {
            witnesses,
            replicas,
        }
    }

    /// Whether neither set names anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty() && self.replicas.is_empty()
    }
}

fn root_sets_value(s: &RootSets) -> Value {
    use crate::verify::key_scope::{replica_value, witness_value};
    map([
        (
            "witnesses",
            (!s.witnesses.is_empty()).then(|| set_value(s.witnesses.iter().map(witness_value))),
        ),
        (
            "replicas",
            (!s.replicas.is_empty()).then(|| set_value(s.replicas.iter().map(replica_value))),
        ),
    ])
}

fn root_sets(v: &Value) -> Result<RootSets, ModelError> {
    use crate::verify::key_scope::{replica, set_of_vec, witness};
    let mut f = Fields::of(v)?;
    let out = RootSets {
        witnesses: f
            .opt("witnesses")
            .map(|w| set_of_vec(w, true, witness))
            .transpose()?
            .unwrap_or_default(),
        replicas: f
            .opt("replicas")
            .map(|r| set_of_vec(r, true, replica))
            .transpose()?
            .unwrap_or_default(),
    };
    f.done()?;
    Ok(out)
}

/// The body of a core meta-action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    /// `anchor_create`.
    AnchorCreate {
        /// Scope.
        scope: AnchorScope,
        /// Root.
        root: Root,
        /// Root terms.
        root_terms: BTreeSet<RequirementTerm>,
        /// The root terms' witness and replica sets (OP-159 m.3 (j)).
        sets: RootSets,
    },
    /// `anchor_transfer`.
    AnchorTransfer {
        /// Anchor.
        anchor: Id,
        /// New root.
        root: Root,
        /// Dependent Grants.
        disposition: BTreeMap<Id, Disposition>,
    },
    /// `anchor_amend`.
    AnchorAmend {
        /// Anchor.
        anchor: Id,
        /// New root, if it changes.
        root: Option<Root>,
        /// New root terms, if they change.
        root_terms: Option<BTreeSet<RequirementTerm>>,
        /// New witness and replica sets, if they change (OP-159 m.3 (j)).
        sets: Option<RootSets>,
    },
    /// `anchor_retire`.
    AnchorRetire {
        /// Anchor.
        anchor: Id,
        /// Dependent Grants.
        disposition: BTreeMap<Id, Disposition>,
    },
    /// `party_register`, with its self-anchor.
    PartyRegister {
        /// The Party.
        party: Id,
        /// Root of its self-anchor.
        root: Root,
        /// What kind of actor it is; fixed for its life.
        actor_kind: ActorKind,
    },
    /// `party_depart`.
    PartyDepart {
        /// The Party.
        party: Id,
        /// Grants on its self-anchor.
        disposition: BTreeMap<Id, Disposition>,
    },
    /// `instance_create`, with an optional first Mandate.
    InstanceCreate {
        /// The Party.
        party: Id,
        /// Its key.
        key: PublicKey,
        /// First Mandate.
        mandate: Option<MandateEnvelope>,
    },
    /// `instance_rekey`.
    InstanceRekey {
        /// Instance.
        instance: Id,
        /// New key.
        key: PublicKey,
    },
    /// `instance_terminate`.
    InstanceTerminate {
        /// Instance.
        instance: Id,
    },
    /// `instance_recover`.
    InstanceRecover {
        /// Instance.
        instance: Id,
        /// The successor's key.
        key: PublicKey,
    },
    /// `mandate_bind`.
    MandateBind {
        /// Instance.
        instance: Id,
        /// Envelope.
        envelope: MandateEnvelope,
    },
    /// `mandate_rebind`.
    MandateRebind {
        /// Mandate.
        mandate: Id,
        /// New envelope.
        envelope: MandateEnvelope,
    },
    /// `mandate_revoke`.
    MandateRevoke {
        /// Mandate.
        mandate: Id,
    },
    /// `grant_issue`.
    GrantIssue(GrantContent),
    /// `grant_amend`.
    GrantAmend {
        /// Grant.
        grant: Id,
        /// New authority.
        authority: CanonicalAuthority,
        /// New agency.
        agency: BTreeSet<Capacity>,
        /// A new named `AuthoritySet` pin (OP-141 m.32 (d)).
        named: Option<NamedPin>,
    },
    /// `grant_revoke`.
    GrantRevoke {
        /// Grant.
        grant: Id,
    },
    /// `grant_renounce`.
    GrantRenounce {
        /// Grant.
        grant: Id,
    },
    /// `acceptance_establish`; the content is kept as given.
    AcceptanceEstablish(Value),
    /// `acceptance_amend`.
    AcceptanceAmend {
        /// Acceptance.
        acceptance: Id,
        /// New content.
        content: Value,
    },
    /// `acceptance_revoke`.
    AcceptanceRevoke {
        /// Acceptance.
        acceptance: Id,
    },
    /// `policy_set`.
    PolicySet {
        /// Policy, absent for a new one.
        policy: Option<Id>,
        /// Content.
        content: Value,
        /// Policy defaults (OP-157 m.3 (n)); absent in 0.4.0 payloads.
        defaults: Option<PolicyDefaults>,
    },
    /// `policy_retire`.
    PolicyRetire {
        /// Policy.
        policy: Id,
    },
    /// `claim_issue`.
    ClaimIssue {
        /// Subject.
        subject: Id,
        /// Class.
        class: String,
        /// Value.
        value: EqValue,
        /// Validity.
        validity: Option<Window>,
        /// The intent it is bound to (OP-141 m.28 (i)).
        bound_intent: Option<Digest>,
        /// The Claim it replaces (OP-141 m.30 (a)).
        supersedes: Option<Id>,
    },
    /// `contribute` (L0-META-30).
    Contribute {
        /// Digest of the intent contributed to.
        target: Digest,
        /// Contribution class.
        class: String,
    },
    /// `authority_set_define` (OP-141 m.32 (a)).
    AuthoritySetDefine {
        /// Name.
        name: String,
        /// The authority-set of the new version.
        authority: AuthoritySet,
    },
    /// `consumption_release` (OP-141 m.28).
    ConsumptionRelease {
        /// The Exercise whose draws are released.
        exercise: Digest,
        /// The grounding Claims.
        grounds: BTreeSet<Id>,
    },
    /// `projection_issue` (OP-143 m.7); the holder is the actor Instance.
    ProjectionIssue {
        /// What the projection allows; its validity ends at the horizon.
        bounds: CanonicalAuthority,
        /// The verifiers it is for.
        audience: BTreeSet<String>,
        /// Connectivity profile class.
        class: ProfileClass,
        /// Connectivity profile variant.
        variant: ProfileVariant,
        /// Δ for `bounded-staleness`.
        max_staleness_ms: Option<u64>,
        /// The offline slice drawn in advance from the lineage's budgets (OP-143 m.12).
        offline_slice: Option<SliceRequest>,
    },
    /// `domain_handover` (§9.15, §16.6, OP-158 m.3 (b), (l)).
    DomainHandover(crate::recovery::HandoverInput),
    /// `domain_recover` (§13.6, SEC21, SEC22, OP-158 m.3 (b), (m)).
    DomainRecover(crate::recovery::RecoverInput),
    /// `version_activate`: the activation record that raises the domain's minimum versions
    /// (OP-56, SI-18, OP-158 m.3 (b)).
    VersionActivate {
        /// The new minimum versions.
        versions: crate::verify::key_scope::SpecVersions,
    },
    /// `algorithm_retire`: the domain declares an algorithm broken and narrows its allowlist
    /// (§15.16, OP-158 m.3 (b)).
    AlgorithmRetire {
        /// The algorithm.
        algorithm: crate::verify::cose::Algorithm,
    },
}

/// What an offline slice asks of each lineage budget: a count, and an amount per unit
/// (OP-143 m.12). At least one is non-zero.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SliceRequest {
    /// Uses drawn from count budgets.
    pub count: Option<u64>,
    /// Amounts drawn from amount budgets, by unit.
    pub amounts: BTreeMap<String, u64>,
}

impl SliceRequest {
    fn to_value(&self) -> Value {
        map([
            ("count", self.count.map(Value::Unsigned)),
            (
                "amounts",
                (!self.amounts.is_empty()).then(|| {
                    Value::Map(
                        self.amounts
                            .iter()
                            .map(|(u, a)| (Value::text(u), Value::Unsigned(*a)))
                            .collect(),
                    )
                }),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let count = f.opt("count").map(uint).transpose()?;
        let mut amounts = BTreeMap::new();
        if let Some(m) = f.opt("amounts") {
            let Value::Map(entries) = m else {
                return Err(ModelError::Shape);
            };
            if entries.is_empty() {
                return Err(ModelError::Shape);
            }
            for (k, a) in entries {
                let a = uint(a)?;
                if a == 0 {
                    return Err(ModelError::Range);
                }
                amounts.insert(crate::codec::unit(k)?, a);
            }
        }
        f.done()?;
        if count == Some(0) || (count.is_none() && amounts.is_empty()) {
            return Err(ModelError::Range);
        }
        Ok(Self { count, amounts })
    }
}

const NAMES: [&str; 31] = [
    "anchor_create",
    "anchor_transfer",
    "anchor_amend",
    "anchor_retire",
    "party_register",
    "party_depart",
    "instance_create",
    "instance_rekey",
    "instance_terminate",
    "instance_recover",
    "mandate_bind",
    "mandate_rebind",
    "mandate_revoke",
    "grant_issue",
    "grant_amend",
    "grant_revoke",
    "grant_renounce",
    "acceptance_establish",
    "acceptance_amend",
    "acceptance_revoke",
    "policy_set",
    "policy_retire",
    "claim_issue",
    "contribute",
    "consumption_release",
    "authority_set_define",
    "projection_issue",
    // OP-158 m.3 (b)
    "domain_handover",
    "domain_recover",
    "version_activate",
    "algorithm_retire",
];

/// The Access-internal read actions: they change no authority state (§9.13.7, OP-141 m.39 (a),
/// OP-159 m.3 (l)).
pub const READS: [&str; 2] = ["read", "audit_export"];

/// Whether `name` is an Access-internal read action.
#[must_use]
pub fn is_read(namespace: &str, name: &str) -> bool {
    namespace == NAMESPACE && READS.contains(&name)
}

/// Whether `name` is a core meta-action.
#[must_use]
pub fn is_meta(namespace: &str, name: &str) -> bool {
    namespace == NAMESPACE && NAMES.contains(&name)
}

/// Why a meta-action is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MetaError {
    /// The payload is not a meta-payload.
    #[error("malformed payload: {0}")]
    Malformed(ModelError),
    /// The intent's action does not match the payload.
    #[error("action does not match the payload")]
    Action,
    /// An object it names does not exist.
    #[error("unknown object")]
    Unknown,
    /// An object it names has ended.
    #[error("object has ended")]
    Ended,
    /// The actor has none of the powers this meta-action needs.
    #[error("no authority")]
    NotAuthorized,
    /// The new authority is not within its parent (C15, INV-3).
    #[error("not within the parent")]
    NotWithin,
    /// Agency continuity is broken (INV-4).
    #[error("agency not continuous")]
    Agency,
    /// The disposition does not name exactly the dependent Grants (C10).
    #[error("disposition does not cover the dependent grants")]
    Disposition,
    /// The basis declared for the Exercise does not fit the payload.
    #[error("basis does not fit")]
    Basis,
    /// The lineage is longer than [`MAX_LINEAGE`].
    #[error("lineage too deep")]
    Depth,
    /// Stored state does not decode.
    #[error("corrupt state")]
    Corrupt,
    /// A release would exceed the draw or reuses a ground (TI-RT8, OP-141 m.28 (f)).
    #[error("release exceeds draw")]
    ReleaseExceedsDraw,
    /// A policy default this Kernel does not apply (OP-157 m.3 (n)).
    #[error("policy default unknown")]
    DefaultUnknown,
    /// A meta-action this Kernel declares but does not decide yet; it is refused as restricted,
    /// never allowed (OP-158 m.4 (a)).
    #[error("restricted")]
    Restricted,
    /// A recovery cites a checkpoint below R* (SEC22).
    #[error("rollback guard")]
    RollbackGuard,
    /// A Holding-based meta-Exercise whose holding's terms are not met (L0-META-13, OP-159
    /// m.3 (k)).
    #[error("holding terms")]
    HoldingTerms,
    /// ML-DSA cannot join the allowlist of a domain that declares the FIPS profile (CR-44,
    /// OP-159 m.3 (r)).
    #[error("algorithm profile conflict")]
    AlgorithmProfileConflict,
}

impl MetaError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed(_) => "meta-malformed",
            Self::Action => "meta-action",
            Self::Unknown => "meta-unknown",
            Self::Ended => "meta-ended",
            Self::NotAuthorized => "meta-not-authorized",
            Self::NotWithin => "meta-not-within",
            Self::Agency => "meta-agency",
            Self::Disposition => "meta-disposition",
            Self::Basis => "meta-basis",
            Self::Depth => "meta-depth",
            Self::Corrupt => "meta-corrupt",
            Self::ReleaseExceedsDraw => "meta-release-exceeds-draw",
            Self::DefaultUnknown => "policy-default-unknown",
            Self::Restricted => "meta-restricted",
            Self::RollbackGuard => "rollback-guard",
            Self::HoldingTerms => "holding-terms",
            Self::AlgorithmProfileConflict => "algorithm-profile-conflict",
        }
    }
}

impl From<ModelError> for MetaError {
    fn from(e: ModelError) -> Self {
        Self::Malformed(e)
    }
}

fn id(v: &Value) -> Result<Id, ModelError> {
    Id::from_value(v)
}

fn root_value(r: &Root) -> Value {
    match r {
        Root::Sole(p) => tagged("sole", p.to_value()),
        Root::Joint { parties, k } => tagged(
            "joint",
            map([
                (
                    "parties",
                    Some(set_value(parties.iter().map(Canonical::to_value))),
                ),
                ("k", Some(Value::Unsigned(*k))),
            ]),
        ),
    }
}

fn root(value: &Value) -> Result<Root, ModelError> {
    match single(value)? {
        ("sole", party) => Ok(Root::Sole(id(party)?)),
        ("joint", joint) => {
            let mut f = Fields::of(joint)?;
            let parties = set_of(f.req("parties")?, true, id)?;
            let k = uint(f.req("k")?)?;
            f.done()?;
            let n = u64::try_from(parties.len()).map_err(|_| ModelError::Range)?;
            if parties.len() < 2 || k == 0 || k > n {
                return Err(ModelError::Range);
            }
            Ok(Root::Joint { parties, k })
        }
        _ => Err(ModelError::Unknown),
    }
}

fn scope_value(s: &AnchorScope) -> Value {
    match s {
        AnchorScope::Resource(r) => tagged("resource", r.to_value()),
        AnchorScope::Party(p) => tagged("party", p.to_value()),
        AnchorScope::Domain => Value::text("domain"),
    }
}

fn scope(v: &Value) -> Result<AnchorScope, ModelError> {
    if matches!(v, Value::Text(t) if t == "domain") {
        return Ok(AnchorScope::Domain);
    }
    match single(v)? {
        ("resource", r) => Ok(AnchorScope::Resource(ResourceSelector::from_value(r)?)),
        ("party", p) => Ok(AnchorScope::Party(id(p)?)),
        _ => Err(ModelError::Unknown),
    }
}

fn holding_value(h: &HoldingRef) -> Value {
    Value::Array(alloc::vec![
        h.grant.to_value(),
        h.holder.to_value(),
        Value::Unsigned(h.since)
    ])
}

fn holding(v: &Value) -> Result<HoldingRef, ModelError> {
    match v {
        Value::Array(items) => match items.as_slice() {
            [g, h, s] => Ok(HoldingRef {
                grant: id(g)?,
                holder: id(h)?,
                since: uint(s)?,
            }),
            _ => Err(ModelError::Shape),
        },
        _ => Err(ModelError::Shape),
    }
}

/// The CBOR form of an Exercise basis.
#[must_use]
pub fn basis_value(b: &ExerciseBasis) -> Value {
    match b {
        ExerciseBasis::Anchor(a) => tagged("anchor", a.to_value()),
        ExerciseBasis::Holding(h) => tagged("holding", holding_value(h)),
        ExerciseBasis::Public(g) => tagged("public", g.to_value()),
    }
}

/// Reads an Exercise basis.
///
/// # Errors
/// [`ModelError`].
pub fn exercise_basis(v: &Value) -> Result<ExerciseBasis, ModelError> {
    match single(v)? {
        ("anchor", a) => Ok(ExerciseBasis::Anchor(id(a)?)),
        ("holding", h) => Ok(ExerciseBasis::Holding(holding(h)?)),
        ("public", g) => Ok(ExerciseBasis::Public(id(g)?)),
        _ => Err(ModelError::Unknown),
    }
}

fn grant_basis_value(b: &GrantBasis) -> Value {
    match b {
        GrantBasis::Anchor(a) => tagged("anchor", a.to_value()),
        GrantBasis::Holding(h) => tagged("holding", holding_value(h)),
    }
}

fn grant_basis(v: &Value) -> Result<GrantBasis, ModelError> {
    match exercise_basis(v)? {
        ExerciseBasis::Anchor(a) => Ok(GrantBasis::Anchor(a)),
        ExerciseBasis::Holding(h) => Ok(GrantBasis::Holding(h)),
        ExerciseBasis::Public(_) => Err(ModelError::Unknown),
    }
}

/// The CBOR form of a capacity.
#[must_use]
pub fn capacity_value(c: Capacity) -> Value {
    match c {
        Capacity::Own => Value::text("own"),
        Capacity::For(p) => tagged("for", p.to_value()),
    }
}

/// Reads a capacity.
///
/// # Errors
/// [`ModelError`].
pub fn capacity(v: &Value) -> Result<Capacity, ModelError> {
    if matches!(v, Value::Text(t) if t == "own") {
        return Ok(Capacity::Own);
    }
    match single(v)? {
        ("for", p) => Ok(Capacity::For(id(p)?)),
        _ => Err(ModelError::Unknown),
    }
}

fn agency(v: Option<&Value>) -> Result<BTreeSet<Capacity>, ModelError> {
    match v {
        None => Ok(BTreeSet::from([Capacity::Own])),
        Some(v) => set_of(v, true, capacity),
    }
}

fn agency_value(a: &BTreeSet<Capacity>) -> Option<Value> {
    (a != &BTreeSet::from([Capacity::Own]))
        .then(|| set_value(a.iter().copied().map(capacity_value)))
}

fn requirements(v: Option<&Value>) -> Result<BTreeSet<RequirementTerm>, ModelError> {
    v.map_or_else(
        || Ok(BTreeSet::new()),
        |v| set_of(v, false, RequirementTerm::from_value),
    )
}

fn requirements_value(r: &BTreeSet<RequirementTerm>) -> Option<Value> {
    (!r.is_empty()).then(|| set_value(r.iter().map(Canonical::to_value)))
}

impl Canonical for GrantContent {
    fn to_value(&self) -> Value {
        map([
            ("basis", Some(grant_basis_value(&self.basis))),
            ("holder", Some(self.holder.to_value())),
            ("authority", Some(self.authority.to_value())),
            ("agency", agency_value(&self.agency)),
            ("named", self.named.as_ref().map(named_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let named = f.opt("named").map(named_pin).transpose()?;
        let c = Self {
            basis: grant_basis(f.req("basis")?)?,
            holder: SubjectSelector::from_value(f.req("holder")?)?,
            authority: CanonicalAuthority::from_value(f.req("authority")?)?,
            agency: agency(f.opt("agency"))?,
            named,
        };
        f.done()?;
        Ok(c)
    }
}

impl Canonical for MandateEnvelope {
    fn to_value(&self) -> Value {
        map([
            ("authority", Some(self.authority.to_value())),
            ("constraints", Some(self.constraints.to_value())),
            ("requirements", requirements_value(&self.requirements)),
            ("pin", self.pin.as_ref().map(holding_value)),
            (
                "origins",
                (!self.origins.is_empty()).then(|| self.origins.to_value()),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let m = Self {
            authority: AuthoritySet::from_value(f.req("authority")?)?,
            constraints: ConstraintSet::from_value(f.req("constraints")?)?,
            requirements: requirements(f.opt("requirements"))?,
            pin: f.opt("pin").map(holding).transpose()?,
            origins: f
                .opt("origins")
                .map(crate::combinator::Origins::from_value)
                .transpose()?
                .unwrap_or_default(),
        };
        f.done()?;
        Ok(m)
    }
}

fn disposition(v: &Value) -> Result<BTreeMap<Id, Disposition>, ModelError> {
    let Value::Array(items) = v else {
        return Err(ModelError::Shape);
    };
    let mut out = BTreeMap::new();
    for item in items {
        let Value::Array(pair) = item else {
            return Err(ModelError::Shape);
        };
        let [g, d] = pair.as_slice() else {
            return Err(ModelError::Shape);
        };
        let d = match d {
            Value::Text(t) if t == "keep" => Disposition::Keep,
            Value::Text(t) if t == "revoke" => Disposition::Revoke,
            _ => return Err(ModelError::Unknown),
        };
        if out.insert(id(g)?, d).is_some() {
            return Err(ModelError::SetOrder);
        }
    }
    Ok(out)
}

fn disposition_value(d: &BTreeMap<Id, Disposition>) -> Value {
    Value::Array(
        d.iter()
            .map(|(g, d)| {
                Value::Array(alloc::vec![
                    g.to_value(),
                    Value::text(match d {
                        Disposition::Keep => "keep",
                        Disposition::Revoke => "revoke",
                    })
                ])
            })
            .collect(),
    )
}

impl Canonical for Payload {
    #[allow(
        clippy::too_many_lines,
        reason = "one arm per meta-action of the closed list"
    )]
    fn to_value(&self) -> Value {
        let (name, body) = match self {
            Self::AnchorCreate {
                scope,
                root,
                root_terms,
                sets,
            } => (
                "anchor_create",
                map([
                    ("scope", Some(scope_value(scope))),
                    ("root", Some(root_value(root))),
                    ("root_terms", requirements_value(root_terms)),
                    ("sets", (!sets.is_empty()).then(|| root_sets_value(sets))),
                ]),
            ),
            Self::AnchorTransfer {
                anchor,
                root,
                disposition,
            } => (
                "anchor_transfer",
                map([
                    ("anchor", Some(anchor.to_value())),
                    ("root", Some(root_value(root))),
                    ("disposition", Some(disposition_value(disposition))),
                ]),
            ),
            Self::AnchorAmend {
                anchor,
                root,
                root_terms,
                sets,
            } => (
                "anchor_amend",
                map([
                    ("anchor", Some(anchor.to_value())),
                    ("root", root.as_ref().map(root_value)),
                    (
                        "root_terms",
                        root_terms
                            .as_ref()
                            .map(|r| set_value(r.iter().map(Canonical::to_value))),
                    ),
                    ("sets", sets.as_ref().map(root_sets_value)),
                ]),
            ),
            Self::AnchorRetire {
                anchor,
                disposition,
            } => (
                "anchor_retire",
                map([
                    ("anchor", Some(anchor.to_value())),
                    ("disposition", Some(disposition_value(disposition))),
                ]),
            ),
            Self::PartyRegister {
                party,
                root,
                actor_kind,
            } => (
                "party_register",
                map([
                    ("party", Some(party.to_value())),
                    ("root", Some(root_value(root))),
                    (
                        "actor_kind",
                        Some(crate::codec::word_of(*actor_kind, &ACTOR_KINDS)),
                    ),
                ]),
            ),
            Self::PartyDepart { party, disposition } => (
                "party_depart",
                map([
                    ("party", Some(party.to_value())),
                    ("disposition", Some(disposition_value(disposition))),
                ]),
            ),
            Self::InstanceCreate {
                party,
                key,
                mandate,
            } => (
                "instance_create",
                map([
                    ("party", Some(party.to_value())),
                    ("key", Some(key.to_value())),
                    ("mandate", mandate.as_ref().map(Canonical::to_value)),
                ]),
            ),
            Self::InstanceRekey { instance, key } => (
                "instance_rekey",
                map([
                    ("instance", Some(instance.to_value())),
                    ("key", Some(key.to_value())),
                ]),
            ),
            Self::InstanceTerminate { instance } => (
                "instance_terminate",
                map([("instance", Some(instance.to_value()))]),
            ),
            Self::InstanceRecover { instance, key } => (
                "instance_recover",
                map([
                    ("instance", Some(instance.to_value())),
                    ("key", Some(key.to_value())),
                ]),
            ),
            Self::MandateBind { instance, envelope } => (
                "mandate_bind",
                map([
                    ("instance", Some(instance.to_value())),
                    ("envelope", Some(envelope.to_value())),
                ]),
            ),
            Self::MandateRebind { mandate, envelope } => (
                "mandate_rebind",
                map([
                    ("mandate", Some(mandate.to_value())),
                    ("envelope", Some(envelope.to_value())),
                ]),
            ),
            Self::MandateRevoke { mandate } => (
                "mandate_revoke",
                map([("mandate", Some(mandate.to_value()))]),
            ),
            Self::GrantIssue(c) => ("grant_issue", c.to_value()),
            Self::GrantAmend {
                grant,
                authority,
                agency,
                named,
            } => (
                "grant_amend",
                map([
                    ("grant", Some(grant.to_value())),
                    ("authority", Some(authority.to_value())),
                    ("agency", agency_value(agency)),
                    ("named", named.as_ref().map(named_value)),
                ]),
            ),
            Self::AuthoritySetDefine { name, authority } => (
                "authority_set_define",
                map([
                    ("name", Some(Value::text(name))),
                    ("authority", Some(authority.to_value())),
                ]),
            ),
            Self::GrantRevoke { grant } => {
                ("grant_revoke", map([("grant", Some(grant.to_value()))]))
            }
            Self::GrantRenounce { grant } => {
                ("grant_renounce", map([("grant", Some(grant.to_value()))]))
            }
            Self::AcceptanceEstablish(c) => ("acceptance_establish", c.clone()),
            Self::AcceptanceAmend {
                acceptance,
                content,
            } => (
                "acceptance_amend",
                map([
                    ("acceptance", Some(acceptance.to_value())),
                    ("content", Some(content.clone())),
                ]),
            ),
            Self::AcceptanceRevoke { acceptance } => (
                "acceptance_revoke",
                map([("acceptance", Some(acceptance.to_value()))]),
            ),
            Self::PolicySet {
                policy,
                content,
                defaults,
            } => (
                "policy_set",
                map([
                    ("policy", policy.as_ref().map(Canonical::to_value)),
                    ("content", Some(content.clone())),
                    ("defaults", defaults.as_ref().map(PolicyDefaults::to_value)),
                ]),
            ),
            Self::PolicyRetire { policy } => {
                ("policy_retire", map([("policy", Some(policy.to_value()))]))
            }
            Self::ClaimIssue {
                subject,
                class,
                value,
                validity,
                bound_intent,
                supersedes,
            } => (
                "claim_issue",
                map([
                    ("subject", Some(subject.to_value())),
                    ("class", Some(Value::text(class))),
                    ("value", Some(value.to_value())),
                    ("validity", validity.as_ref().map(Canonical::to_value)),
                    (
                        "bound_intent",
                        bound_intent.as_ref().map(Canonical::to_value),
                    ),
                    ("supersedes", supersedes.as_ref().map(Canonical::to_value)),
                ]),
            ),
            Self::Contribute { target, class } => (
                "contribute",
                map([
                    ("target", Some(target.to_value())),
                    ("class", Some(Value::text(class))),
                ]),
            ),
            Self::ConsumptionRelease { exercise, grounds } => (
                "consumption_release",
                map([
                    ("exercise", Some(exercise.to_value())),
                    ("grounds", Some(ids_value(grounds))),
                ]),
            ),
            Self::ProjectionIssue {
                bounds,
                audience,
                class,
                variant,
                max_staleness_ms,
                offline_slice,
            } => (
                "projection_issue",
                map([
                    ("bounds", Some(bounds.to_value())),
                    ("audience", Some(texts_value(audience))),
                    (
                        "profile",
                        Some(map([
                            ("class", Some(word_of(*class, &CLASSES))),
                            ("variant", Some(word_of(*variant, &VARIANTS))),
                        ])),
                    ),
                    ("max_staleness_ms", max_staleness_ms.map(Value::Unsigned)),
                    (
                        "offline_slice",
                        offline_slice.as_ref().map(SliceRequest::to_value),
                    ),
                ]),
            ),
            Self::DomainHandover(h) => ("domain_handover", h.to_value()),
            Self::DomainRecover(r) => ("domain_recover", r.to_value()),
            Self::VersionActivate { versions } => (
                "version_activate",
                map([("versions", Some(versions.to_value()))]),
            ),
            Self::AlgorithmRetire { algorithm } => (
                "algorithm_retire",
                map([("algorithm", Some(Value::int(algorithm.cose())))]),
            ),
        };
        tagged(name, body)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one arm per meta-action of the closed list"
    )]
    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let (name, body) = single(v)?;
        if name == "grant_issue" {
            return Ok(Self::GrantIssue(GrantContent::from_value(body)?));
        }
        if name == "acceptance_establish" {
            return Ok(Self::AcceptanceEstablish(acceptance_content(body)?));
        }
        // OP-158 m.3 (b)
        if name == "domain_handover" {
            return Ok(Self::DomainHandover(
                crate::recovery::HandoverInput::from_value(body)?,
            ));
        }
        if name == "domain_recover" {
            return Ok(Self::DomainRecover(
                crate::recovery::RecoverInput::from_value(body)?,
            ));
        }
        let mut f = Fields::of(body)?;
        let p = match name {
            "anchor_create" => Self::AnchorCreate {
                scope: scope(f.req("scope")?)?,
                root: root(f.req("root")?)?,
                root_terms: requirements(f.opt("root_terms"))?,
                sets: f
                    .opt("sets")
                    .map(root_sets)
                    .transpose()?
                    .unwrap_or_default(),
            },
            "anchor_transfer" => Self::AnchorTransfer {
                anchor: id(f.req("anchor")?)?,
                root: root(f.req("root")?)?,
                disposition: disposition(f.req("disposition")?)?,
            },
            "anchor_amend" => Self::AnchorAmend {
                anchor: id(f.req("anchor")?)?,
                root: f.opt("root").map(root).transpose()?,
                root_terms: f
                    .opt("root_terms")
                    .map(|r| set_of(r, false, RequirementTerm::from_value))
                    .transpose()?,
                sets: f.opt("sets").map(root_sets).transpose()?,
            },
            "anchor_retire" => Self::AnchorRetire {
                anchor: id(f.req("anchor")?)?,
                disposition: disposition(f.req("disposition")?)?,
            },
            "party_register" => Self::PartyRegister {
                party: id(f.req("party")?)?,
                root: root(f.req("root")?)?,
                actor_kind: crate::codec::word(f.req("actor_kind")?, &ACTOR_KINDS)?,
            },
            "party_depart" => Self::PartyDepart {
                party: id(f.req("party")?)?,
                disposition: disposition(f.req("disposition")?)?,
            },
            "instance_create" => Self::InstanceCreate {
                party: id(f.req("party")?)?,
                key: instance_key(f.req("key")?)?,
                mandate: f
                    .opt("mandate")
                    .map(MandateEnvelope::from_value)
                    .transpose()?,
            },
            "instance_rekey" => Self::InstanceRekey {
                instance: id(f.req("instance")?)?,
                key: instance_key(f.req("key")?)?,
            },
            "instance_terminate" => Self::InstanceTerminate {
                instance: id(f.req("instance")?)?,
            },
            "instance_recover" => Self::InstanceRecover {
                instance: id(f.req("instance")?)?,
                key: instance_key(f.req("key")?)?,
            },
            "mandate_bind" => Self::MandateBind {
                instance: id(f.req("instance")?)?,
                envelope: MandateEnvelope::from_value(f.req("envelope")?)?,
            },
            "mandate_rebind" => Self::MandateRebind {
                mandate: id(f.req("mandate")?)?,
                envelope: MandateEnvelope::from_value(f.req("envelope")?)?,
            },
            "mandate_revoke" => Self::MandateRevoke {
                mandate: id(f.req("mandate")?)?,
            },
            "grant_amend" => Self::GrantAmend {
                grant: id(f.req("grant")?)?,
                authority: CanonicalAuthority::from_value(f.req("authority")?)?,
                agency: agency(f.opt("agency"))?,
                named: f.opt("named").map(named_pin).transpose()?,
            },
            "authority_set_define" => Self::AuthoritySetDefine {
                name: crate::codec::ident(f.req("name")?)?,
                authority: AuthoritySet::from_value(f.req("authority")?)?,
            },
            "grant_revoke" => Self::GrantRevoke {
                grant: id(f.req("grant")?)?,
            },
            "grant_renounce" => Self::GrantRenounce {
                grant: id(f.req("grant")?)?,
            },
            "acceptance_amend" => Self::AcceptanceAmend {
                acceptance: id(f.req("acceptance")?)?,
                content: acceptance_content(f.req("content")?)?,
            },
            "acceptance_revoke" => Self::AcceptanceRevoke {
                acceptance: id(f.req("acceptance")?)?,
            },
            "policy_set" => Self::PolicySet {
                policy: f.opt("policy").map(id).transpose()?,
                content: policy_content(f.req("content")?)?,
                defaults: f
                    .opt("defaults")
                    .map(PolicyDefaults::from_value)
                    .transpose()?,
            },
            "policy_retire" => Self::PolicyRetire {
                policy: id(f.req("policy")?)?,
            },
            "claim_issue" => Self::ClaimIssue {
                subject: id(f.req("subject")?)?,
                class: crate::codec::ident(f.req("class")?)?,
                value: EqValue::from_value(f.req("value")?)?,
                validity: f.opt("validity").map(Window::from_value).transpose()?,
                bound_intent: f
                    .opt("bound_intent")
                    .map(|v| Digest::from_value(v).ok_or(ModelError::Shape))
                    .transpose()?,
                supersedes: f.opt("supersedes").map(id).transpose()?,
            },
            "contribute" => Self::Contribute {
                target: Digest::from_value(f.req("target")?).ok_or(ModelError::Shape)?,
                class: crate::codec::ident(f.req("class")?)?,
            },
            "consumption_release" => Self::ConsumptionRelease {
                exercise: Digest::from_value(f.req("exercise")?).ok_or(ModelError::Shape)?,
                grounds: set_of(f.req("grounds")?, true, id)?,
            },
            "projection_issue" => {
                let mut p = Fields::of(f.req("profile")?)?;
                let class = word(p.req("class")?, &CLASSES)?;
                let variant = word(p.req("variant")?, &VARIANTS)?;
                p.done()?;
                if variant.class() != class {
                    return Err(ModelError::Range);
                }
                Self::ProjectionIssue {
                    bounds: CanonicalAuthority::from_value(f.req("bounds")?)?,
                    audience: set_of(f.req("audience")?, true, audience_id)?,
                    class,
                    variant,
                    max_staleness_ms: f.opt("max_staleness_ms").map(uint).transpose()?,
                    offline_slice: f
                        .opt("offline_slice")
                        .map(SliceRequest::from_value)
                        .transpose()?,
                }
            }
            "version_activate" => Self::VersionActivate {
                versions: crate::verify::key_scope::SpecVersions::from_value(f.req("versions")?)?,
            },
            "algorithm_retire" => Self::AlgorithmRetire {
                algorithm: crate::verify::cose::Algorithm::from_cose(crate::codec::int(
                    f.req("algorithm")?,
                )?)
                .ok_or(ModelError::Unknown)?,
            },
            _ => return Err(ModelError::Unknown),
        };
        f.done()?;
        Ok(p)
    }
}

fn texts_value(s: &BTreeSet<String>) -> Value {
    set_value(s.iter().map(|t| Value::text(t)))
}

fn audience_id(v: &Value) -> Result<String, ModelError> {
    let t = crate::codec::text(v)?;
    if (1..=255).contains(&t.len()) {
        Ok(String::from(t))
    } else {
        Err(ModelError::Range)
    }
}

const USES: [&str; 5] = [
    "actor-binding",
    "predicate-input",
    "subject-selection",
    "foreign-authority",
    "schema-definition",
];

fn acceptance_content(v: &Value) -> Result<Value, ModelError> {
    let mut f = Fields::of(v)?;
    let foreign = match f.req("issuer")? {
        Value::Bytes(_) => {
            id(f.req("issuer")?)?;
            false
        }
        other => {
            let (k, inner) = single(other)?;
            if k != crate::foreign::INDEX {
                return Err(ModelError::Unknown);
            }
            crate::foreign::ForeignIssuer::from_value(inner)?;
            true
        }
    };
    let schema = match f.req("use")? {
        Value::Text(u) if USES.contains(&u.as_str()) => {
            // OP-143 m.13 (a)
            if (u == crate::foreign::USE) != foreign {
                return Err(ModelError::Shape);
            }
            u == "schema-definition"
        }
        _ => return Err(ModelError::Unknown),
    };
    // OP-141 m.35 (a)
    match (schema, f.opt("spp")) {
        (true, Some(spp)) => {
            let spp = crate::schema::Spp::from_value(spp)?;
            if v.get("issuer") != Some(&spp.publisher.to_value()) {
                return Err(ModelError::Shape);
            }
        }
        (false, None) => {}
        _ => return Err(ModelError::Shape),
    }
    set_of(f.req("classes")?, true, crate::codec::ident)?;
    SubjectSelector::from_value(f.req("subject")?)?;
    f.opt("anchor").map(id).transpose()?;
    // OP-150
    if let Some(p) = f.opt("pinned") {
        if foreign {
            return Err(ModelError::Shape);
        }
        crate::claim::check_pinned(p)?;
    }
    // OP-157 m.3 (b), (r)
    if let Some(m) = f.opt("mappings") {
        if !schema {
            return Err(ModelError::Shape);
        }
        set_of(m, true, <Digest as Canonical>::from_value)?;
    }
    crate::codec::assurance(f.opt("assurance_floor"))?;
    Window::from_value(f.req("validity")?)?;
    f.opt("ingest_until").map(uint).transpose()?;
    f.opt("issued_until").map(uint).transpose()?;
    if let Some(q) = f.opt("quota") {
        let mut qf = Fields::of(q)?;
        if uint(qf.req("count")?)? == 0 || uint(qf.req("window_s")?)? == 0 {
            return Err(ModelError::Range);
        }
        qf.done()?;
    }
    f.done()?;
    Ok(v.clone())
}

/// Policy defaults carried by `policy_set` (OP-157 m.3 (n)). Each key has one tightening
/// direction; an unknown key does not decode (OP-108 m.4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyDefaults {
    /// CT3 effect delay in seconds; larger is tighter.
    pub ct3_delay_s: Option<u64>,
    /// Mapping probation in days; larger is tighter.
    pub mapping_probation_days: Option<u64>,
    /// Accepted approval surface profiles; smaller is tighter.
    pub approval_surfaces: Option<BTreeSet<String>>,
    /// Break-glass review deadline in hours; smaller is tighter.
    pub breakglass_review_h: Option<u64>,
    /// Longest support access in minutes; smaller is tighter.
    pub support_max_min: Option<u64>,
}

/// The policy default keys this version defines (OP-157 m.3 (n)).
pub const POLICY_DEFAULT_KEYS: [&str; 5] = [
    "approval_surfaces",
    "breakglass_review_h",
    "ct3_delay_s",
    "mapping_probation_days",
    "support_max_min",
];

impl Canonical for PolicyDefaults {
    fn to_value(&self) -> Value {
        map([
            (
                "approval_surfaces",
                self.approval_surfaces
                    .as_ref()
                    .map(|s| set_value(s.iter().map(|t| Value::text(t)))),
            ),
            (
                "breakglass_review_h",
                self.breakglass_review_h.map(Value::Unsigned),
            ),
            ("ct3_delay_s", self.ct3_delay_s.map(Value::Unsigned)),
            (
                "mapping_probation_days",
                self.mapping_probation_days.map(Value::Unsigned),
            ),
            ("support_max_min", self.support_max_min.map(Value::Unsigned)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        if f.is_empty() {
            return Err(ModelError::Range);
        }
        let d = Self {
            approval_surfaces: f
                .opt("approval_surfaces")
                .map(|s| {
                    set_of(s, true, |x| {
                        let t = crate::codec::text(x)?;
                        if t.is_empty() {
                            return Err(ModelError::Range);
                        }
                        Ok(String::from(t))
                    })
                })
                .transpose()?,
            breakglass_review_h: f.opt("breakglass_review_h").map(uint).transpose()?,
            ct3_delay_s: f.opt("ct3_delay_s").map(uint).transpose()?,
            mapping_probation_days: f.opt("mapping_probation_days").map(uint).transpose()?,
            support_max_min: f.opt("support_max_min").map(uint).transpose()?,
        };
        f.done()?;
        Ok(d)
    }
}

/// The mapping probation when no domain set one: 14 days (OP-157 m.3 (r), PD).
pub const MAPPING_PROBATION_DEFAULT_DAYS: u64 = 14;

/// The break-glass review deadline when no domain set one: 72 hours (OP-157 m.3 (h), PD).
pub const BREAKGLASS_REVIEW_DEFAULT_H: u64 = 72;

/// The approval surfaces a domain accepts when it set none (OP-157 m.3 (m)).
pub const APPROVAL_SURFACES_DEFAULT: [&str; 2] = ["suiss-approval-surface", "suiss-approver-sdk"];

fn current_uint(view: &dyn View, name: &str) -> Option<u64> {
    match view.get(&policy_default_key(name)) {
        Some(Value::Unsigned(n)) => Some(n),
        _ => None,
    }
}

/// The effects of `d` and whether any of its values loosens the one in force (SI-18, SEC8,
/// OP-157 m.3 (n)): a larger `ct3_delay_s` or `mapping_probation_days`, a smaller
/// `breakglass_review_h` or `support_max_min` and a subset of `approval_surfaces` tighten;
/// anything else loosens. A value never set compares with its default; `support_max_min` has
/// none, so its first value tightens.
fn defaults_effects(view: &dyn View, d: &PolicyDefaults) -> (Vec<Effect>, bool) {
    let mut out = Vec::new();
    let mut loosens = false;
    let mut set = |name: &str, v: Value| out.push((policy_default_key(name), Some(v)));
    if let Some(n) = d.ct3_delay_s {
        loosens |= n < current_uint(view, CT3_DELAY).unwrap_or(CT3_DELAY_DEFAULT_S);
        set(CT3_DELAY, Value::Unsigned(n));
    }
    if let Some(n) = d.mapping_probation_days {
        loosens |= n < current_uint(view, "mapping_probation_days")
            .unwrap_or(MAPPING_PROBATION_DEFAULT_DAYS);
        set("mapping_probation_days", Value::Unsigned(n));
    }
    if let Some(n) = d.breakglass_review_h {
        loosens |=
            n > current_uint(view, "breakglass_review_h").unwrap_or(BREAKGLASS_REVIEW_DEFAULT_H);
        set("breakglass_review_h", Value::Unsigned(n));
    }
    if let Some(n) = d.support_max_min {
        loosens |= current_uint(view, "support_max_min").is_some_and(|c| n > c);
        set("support_max_min", Value::Unsigned(n));
    }
    if let Some(new) = &d.approval_surfaces {
        let current: BTreeSet<String> = match view.get(&policy_default_key("approval_surfaces")) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|v| match v {
                    Value::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect(),
            _ => APPROVAL_SURFACES_DEFAULT
                .iter()
                .map(|s| String::from(*s))
                .collect(),
        };
        loosens |= !new.is_subset(&current);
        set(
            "approval_surfaces",
            set_value(new.iter().map(|t| Value::text(t))),
        );
    }
    (out, loosens)
}

/// The one restriction schema of this version (OP-141 m.27 (a)).
pub const RESTRICTION_SCHEMA: &str = "access/restriction/v1";

fn policy_content(v: &Value) -> Result<Value, ModelError> {
    let mut f = Fields::of(v)?;
    if crate::codec::text(f.req("schema")?)? != RESTRICTION_SCHEMA {
        return Err(ModelError::Unknown);
    }
    crate::codec::text(f.req("source")?)?;
    // OP-141 m.27 (b)
    if let Some(Value::Map(refs)) = f.opt("requirements") {
        for (k, terms) in refs {
            if crate::codec::text(k)?.is_empty() {
                return Err(ModelError::Range);
            }
            requirements(Some(terms))?;
        }
    } else if f.opt("requirements").is_some() {
        return Err(ModelError::Shape);
    }
    let target = f.req("target")?;
    if !matches!(target, Value::Text(t) if t == "domain") {
        match single(target)? {
            ("anchor" | "party" | "instance", x) => {
                id(x)?;
            }
            _ => return Err(ModelError::Unknown),
        }
    }
    f.done()?;
    Ok(v.clone())
}

impl Payload {
    /// The core action name this payload belongs to.
    #[must_use]
    pub fn action(&self) -> &'static str {
        match self.to_value() {
            Value::Map(entries) => entries
                .first()
                .and_then(|(k, _)| match k {
                    Value::Text(t) => NAMES.iter().copied().find(|n| n == t),
                    _ => None,
                })
                .unwrap_or(""),
            _ => "",
        }
    }

    /// `SHA-256("access/meta/v1" ‖ 0x00 ‖ dCBOR(payload))`, the value of
    /// `intent.opaque.payload` (OP-141 m.13).
    ///
    /// # Errors
    /// The payload is outside the structural limits.
    pub fn digest(&self) -> Result<Digest, dcbor::EncodeError> {
        Ok(context_label("access/meta/v1", &self.to_bytes()?))
    }
}

/// `SHA-256("access/exercise/v1" ‖ 0x00 ‖ dCBOR([DomainID, nonce]))` (OP-141 m.6).
///
/// # Errors
/// The nonce is longer than the structural limits allow.
pub fn exercise_id(domain: &Digest, nonce: &[u8]) -> Result<Digest, dcbor::EncodeError> {
    let v = Value::Array(alloc::vec![domain.to_value(), Value::Bytes(nonce.to_vec())]);
    Ok(context_label(
        "access/exercise/v1",
        &dcbor::encode(&v, Limits::CEILING)?,
    ))
}

/// Id of the `seq`-th object of `kind` created by `origin`, an `ExerciseID` or, for Genesis, the
/// `DomainID` (OP-141 m.6).
#[must_use]
pub fn object_id(origin: &Digest, kind: &str, seq: u64) -> Id {
    let v = Value::Array(alloc::vec![
        origin.to_value(),
        Value::text(kind),
        Value::Unsigned(seq)
    ]);
    let bytes = dcbor::encode(&v, Limits::CEILING).unwrap_or_default();
    let d = context_label("access/object/v1", &bytes);
    let mut out = [0_u8; 16];
    for (o, b) in out.iter_mut().zip(d.0.iter()) {
        *o = *b;
    }
    Id(out)
}

/// The state key of an object named by an `ExerciseID`: `dCBOR([kind, digest])` (L0-META-5).
#[must_use]
pub fn exercise_key(kind: &str, exercise: &Digest) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(alloc::vec![Value::text(kind), exercise.to_value()]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

/// The state key of an object: `dCBOR([kind, id])` (OP-141 m.12).
#[must_use]
pub fn key(kind: &str, id: &Id) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(alloc::vec![Value::text(kind), id.to_value()]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

/// The index key from a key's RFC 7638 thumbprint to the Instance that holds it:
/// `dCBOR(["key", kid])` (L0-META-5).
#[must_use]
pub fn key_index(kid: &[u8; 32]) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(alloc::vec![
            Value::text(kind::KEY),
            Value::Bytes(kid.to_vec())
        ]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

fn index_key(out: &mut Outcome, key: &PublicKey, instance: &Id) {
    out.effects.push((
        key_index(&crate::verify::key_scope::thumbprint(key)),
        Some(instance.to_value()),
    ));
}

fn unindex_key(out: &mut Outcome, key: &PublicKey) {
    out.effects
        .push((key_index(&crate::verify::key_scope::thumbprint(key)), None));
}

/// Kinds of state keys.
pub mod kind {
    /// The Instance holding a key, by thumbprint.
    pub const KEY: &str = "key";
    /// An Anchor.
    pub const ANCHOR: &str = "anchor";
    /// A Grant.
    pub const GRANT: &str = "grant";
    /// A Party's admission.
    pub const PARTY: &str = "party";
    /// An Instance.
    pub const INSTANCE: &str = "instance";
    /// A Mandate.
    pub const MANDATE: &str = "mandate";
    /// An Acceptance.
    pub const ACCEPTANCE: &str = "acceptance";
    /// A `RestrictionPolicy`.
    pub const POLICY: &str = "policy";
    /// A Claim, issued by the domain or ingested.
    pub const CLAIM: &str = "claim";
    /// A contribution, keyed by the `ExerciseID` that made it.
    pub const CONTRIBUTION: &str = "contribution";
    /// An allowed Exercise, keyed by its `ExerciseID`.
    pub const EXERCISE: &str = "exercise";
    /// The Acceptances of an issuer Party.
    pub const ACCEPTANCES: &str = "acceptances";
    /// The `subject-selection` Acceptances of a class.
    pub const SELECTION: &str = "selection";
    /// The restriction policies of a target.
    pub const POLICIES: &str = "policies";
    /// The Grants whose basis is an Anchor or a Grant.
    pub const CHILDREN: &str = "children";
    /// The Instances of a Party.
    pub const INSTANCES: &str = "instances";
    /// The Mandates of an Instance.
    pub const MANDATES: &str = "mandates";
    /// A named `AuthoritySet` (OP-141 m.32).
    pub const AUTHORITY_SET: &str = "authority_set";
    /// A projection, keyed by the `ExerciseID` that issued it (OP-143 m.7).
    pub const PROJECTION: &str = "projection";
}

/// Read access to the authority state at the evaluation position; the caller records every key
/// it serves in the read set (TI-4).
pub trait View {
    /// The value of `key`, if present.
    fn get(&self, key: &[u8]) -> Option<Value>;
}

/// How an object ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndedHow {
    /// Revoked.
    Revoked,
    /// Renounced by its holder.
    Renounced,
    /// Retired.
    Retired,
    /// Terminated.
    Terminated,
    /// Recovered into a successor.
    Recovered,
    /// Its Party departed.
    Departed,
}

const ENDED: [(&str, EndedHow); 6] = [
    ("revoked", EndedHow::Revoked),
    ("renounced", EndedHow::Renounced),
    ("retired", EndedHow::Retired),
    ("terminated", EndedHow::Terminated),
    ("recovered", EndedHow::Recovered),
    ("departed", EndedHow::Departed),
];

/// When and how an object ended (terminal, INV-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ended {
    /// Position of the ending record.
    pub at: u64,
    /// How.
    pub how: EndedHow,
}

pub(crate) fn ended_value(e: &Ended) -> Value {
    map([
        ("at", Some(Value::Unsigned(e.at))),
        ("how", Some(crate::codec::word_of(e.how, &ENDED))),
    ])
}

pub(crate) fn ended(v: Option<&Value>) -> Result<Option<Ended>, ModelError> {
    v.map(|v| {
        let mut f = Fields::of(v)?;
        let e = Ended {
            at: uint(f.req("at")?)?,
            how: crate::codec::word(f.req("how")?, &ENDED)?,
        };
        f.done()?;
        Ok(e)
    })
    .transpose()
}

/// A stored Anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorState {
    /// Scope.
    pub scope: AnchorScope,
    /// Root.
    pub root: Root,
    /// Root terms.
    pub root_terms: BTreeSet<RequirementTerm>,
    /// The root terms' witness and replica sets (OP-159 m.3 (j)).
    pub sets: RootSets,
    /// Creating position.
    pub since: u64,
    /// End.
    pub ended: Option<Ended>,
}

impl Canonical for AnchorState {
    fn to_value(&self) -> Value {
        map([
            ("scope", Some(scope_value(&self.scope))),
            ("root", Some(root_value(&self.root))),
            ("root_terms", requirements_value(&self.root_terms)),
            (
                "sets",
                (!self.sets.is_empty()).then(|| root_sets_value(&self.sets)),
            ),
            ("since", Some(Value::Unsigned(self.since))),
            ("ended", self.ended.as_ref().map(ended_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let s = Self {
            scope: scope(f.req("scope")?)?,
            root: root(f.req("root")?)?,
            root_terms: requirements(f.opt("root_terms"))?,
            sets: f
                .opt("sets")
                .map(root_sets)
                .transpose()?
                .unwrap_or_default(),
            since: uint(f.req("since")?)?,
            ended: ended(f.opt("ended"))?,
        };
        f.done()?;
        Ok(s)
    }
}

/// A stored Grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantState {
    /// Content of the current revision.
    pub content: GrantContent,
    /// Issuing position.
    pub since: u64,
    /// Revision number, 0 at issue (C16).
    pub revision: u64,
    /// End.
    pub ended: Option<Ended>,
}

impl Canonical for GrantState {
    fn to_value(&self) -> Value {
        map([
            ("content", Some(self.content.to_value())),
            ("since", Some(Value::Unsigned(self.since))),
            ("revision", Some(Value::Unsigned(self.revision))),
            ("ended", self.ended.as_ref().map(ended_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let s = Self {
            content: GrantContent::from_value(f.req("content")?)?,
            since: uint(f.req("since")?)?,
            revision: uint(f.req("revision")?)?,
            ended: ended(f.opt("ended"))?,
        };
        f.done()?;
        Ok(s)
    }
}

/// What kind of actor a Party is (OP-149 m.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActorKind {
    /// A person.
    Human,
    /// A software agent.
    Agent,
    /// A system of the platform or of a product.
    System,
    /// A device or workload.
    Machine,
    /// An organization acting as itself.
    Organization,
}

impl ActorKind {
    /// The `actor_is_agent` of an evaluation whose actor belongs to a Party of this kind.
    #[must_use]
    pub const fn is_agent(self) -> bool {
        matches!(self, Self::Agent)
    }

    /// The wire name.
    #[must_use]
    pub fn name(self) -> &'static str {
        ACTOR_KINDS
            .iter()
            .find(|(_, k)| *k == self)
            .map_or("", |(n, _)| n)
    }

    /// The kind with this wire name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        ACTOR_KINDS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, k)| *k)
    }
}

const ACTOR_KINDS: [(&str, ActorKind); 5] = [
    ("human", ActorKind::Human),
    ("agent", ActorKind::Agent),
    ("system", ActorKind::System),
    ("machine", ActorKind::Machine),
    ("organization", ActorKind::Organization),
];

// OP-149 m.6
fn instance_key(v: &Value) -> Result<PublicKey, ModelError> {
    match PublicKey::from_value(v)? {
        k @ (PublicKey::Ed25519(_) | PublicKey::P256(_)) => Ok(k),
        PublicKey::MlDsa(..) => Err(ModelError::Unknown),
    }
}

/// Whether the actor Party `party` is a software agent: the Kernel's `actor_is_agent`, derived
/// from the kind its `party_register` recorded (OP-149 m.8). An unknown Party is not an agent.
#[must_use]
pub fn actor_is_agent(view: &dyn View, party: &Id) -> bool {
    read::<PartyState>(view, kind::PARTY, party).is_ok_and(|p| p.actor_kind.is_agent())
}

/// A Party's admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyState {
    /// Its self-anchor.
    pub anchor: Id,
    /// What kind of actor it is; `party_register` sets it and nothing changes it.
    pub actor_kind: ActorKind,
    /// Admitting position.
    pub since: u64,
    /// Departure.
    pub ended: Option<Ended>,
}

impl Canonical for PartyState {
    fn to_value(&self) -> Value {
        map([
            ("anchor", Some(self.anchor.to_value())),
            (
                "actor_kind",
                Some(crate::codec::word_of(self.actor_kind, &ACTOR_KINDS)),
            ),
            ("since", Some(Value::Unsigned(self.since))),
            ("ended", self.ended.as_ref().map(ended_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let s = Self {
            anchor: id(f.req("anchor")?)?,
            actor_kind: crate::codec::word(f.req("actor_kind")?, &ACTOR_KINDS)?,
            since: uint(f.req("since")?)?,
            ended: ended(f.opt("ended"))?,
        };
        f.done()?;
        Ok(s)
    }
}

/// A stored Instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceState {
    /// Its Party (C8).
    pub party: Id,
    /// Current key.
    pub key: PublicKey,
    /// Creating position.
    pub since: u64,
    /// Recovery successor.
    pub successor: Option<Id>,
    /// End.
    pub ended: Option<Ended>,
}

impl Canonical for InstanceState {
    fn to_value(&self) -> Value {
        map([
            ("party", Some(self.party.to_value())),
            ("key", Some(self.key.to_value())),
            ("since", Some(Value::Unsigned(self.since))),
            (
                "successor",
                self.successor.as_ref().map(Canonical::to_value),
            ),
            ("ended", self.ended.as_ref().map(ended_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let s = Self {
            party: id(f.req("party")?)?,
            key: instance_key(f.req("key")?)?,
            since: uint(f.req("since")?)?,
            successor: f.opt("successor").map(id).transpose()?,
            ended: ended(f.opt("ended"))?,
        };
        f.done()?;
        Ok(s)
    }
}

/// A stored Mandate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MandateState {
    /// Its Instance.
    pub instance: Id,
    /// Envelope.
    pub envelope: MandateEnvelope,
    /// Binding position.
    pub since: u64,
    /// End.
    pub ended: Option<Ended>,
}

impl Canonical for MandateState {
    fn to_value(&self) -> Value {
        map([
            ("instance", Some(self.instance.to_value())),
            ("envelope", Some(self.envelope.to_value())),
            ("since", Some(Value::Unsigned(self.since))),
            ("ended", self.ended.as_ref().map(ended_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let s = Self {
            instance: id(f.req("instance")?)?,
            envelope: MandateEnvelope::from_value(f.req("envelope")?)?,
            since: uint(f.req("since")?)?,
            ended: ended(f.opt("ended"))?,
        };
        f.done()?;
        Ok(s)
    }
}

/// A recorded contribution (`contribution-state`, L0-META-30).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContributionState {
    /// Digest of the intent contributed to.
    pub target: Digest,
    /// Class.
    pub class: String,
    /// The contributor's Party.
    pub party: Id,
    /// The contributor's Instance.
    pub instance: Id,
    /// Position of the contribution.
    pub since: u64,
    /// Position of the decision that consumed it.
    pub consumed: Option<u64>,
    /// H(AAS) of the statement the approver's act signed (§9.14.1, SI-5).
    pub statement: Option<Digest>,
    /// Assurance of the `authentication` Claim bound to that statement (§13.7.3).
    pub assurance: BTreeMap<String, u64>,
    /// `auth_time` of that Claim; the contribution's freshness when it is a proof.
    pub auth_time: Option<u64>,
    /// The surface path the approval came through (`aas::surface_path`), which a `distinct
    /// surface` term counts once (OP-157 m.25, OP-158 m.3 (b)); absent before 0.6.0.
    pub surface_path: Option<Digest>,
}

impl Canonical for ContributionState {
    fn to_value(&self) -> Value {
        map([
            ("target", Some(self.target.to_value())),
            ("class", Some(Value::text(&self.class))),
            ("party", Some(self.party.to_value())),
            ("instance", Some(self.instance.to_value())),
            ("since", Some(Value::Unsigned(self.since))),
            ("consumed", self.consumed.map(Value::Unsigned)),
            (
                "statement",
                self.statement.as_ref().map(Canonical::to_value),
            ),
            (
                "assurance",
                crate::codec::map_value(&self.assurance, |v| Value::Unsigned(*v)),
            ),
            ("auth_time", self.auth_time.map(Value::Unsigned)),
            (
                "surface_path",
                self.surface_path.as_ref().map(Canonical::to_value),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let assurance = crate::codec::assurance(f.opt("assurance"))?;
        crate::requirement::check_assurance(&assurance)?;
        let s = Self {
            target: Digest::from_value(f.req("target")?).ok_or(ModelError::Shape)?,
            class: crate::codec::ident(f.req("class")?)?,
            party: id(f.req("party")?)?,
            instance: id(f.req("instance")?)?,
            since: uint(f.req("since")?)?,
            consumed: f.opt("consumed").map(uint).transpose()?,
            statement: f
                .opt("statement")
                .map(|d| Digest::from_value(d).ok_or(ModelError::Shape))
                .transpose()?,
            assurance,
            auth_time: f.opt("auth_time").map(uint).transpose()?,
            surface_path: f
                .opt("surface_path")
                .map(|d| Digest::from_value(d).ok_or(ModelError::Shape))
                .transpose()?,
        };
        f.done()?;
        Ok(s)
    }
}

/// One budget counter an Exercise drew from (OP-141 m.28 (a)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExerciseDraw {
    /// Counter key, `dCBOR(["budget", GrantID, term, window start])`.
    pub key: Vec<u8>,
    /// Amount drawn.
    pub drawn: u64,
    /// Amount released so far.
    pub released: u64,
    /// Unit of an `amount` term; `None` for a count.
    pub unit: Option<String>,
}

impl Canonical for ExerciseDraw {
    fn to_value(&self) -> Value {
        map([
            ("key", Some(Value::Bytes(self.key.clone()))),
            ("drawn", Some(Value::Unsigned(self.drawn))),
            ("released", Some(Value::Unsigned(self.released))),
            ("unit", self.unit.as_deref().map(Value::text)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let key = match f.req("key")? {
            Value::Bytes(b) => b.clone(),
            _ => return Err(ModelError::Shape),
        };
        let s = Self {
            key,
            drawn: uint(f.req("drawn")?)?,
            released: uint(f.req("released")?)?,
            unit: f.opt("unit").map(crate::codec::unit).transpose()?,
        };
        f.done()?;
        if s.released > s.drawn {
            return Err(ModelError::Range);
        }
        Ok(s)
    }
}

/// An allowed Exercise (`exercise-state`): what a continuation is checked against (L1-ADP-13)
/// and what a release returns (OP-141 m.28).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExerciseState {
    /// Intent digest.
    pub intent: Digest,
    /// Actor Instance.
    pub actor: Id,
    /// Position of the allowing decision.
    pub since: u64,
    /// Budget draws, sorted by key.
    pub draws: Vec<ExerciseDraw>,
    /// Claims already used to ground a release.
    pub grounds: BTreeSet<Id>,
}

impl Canonical for ExerciseState {
    fn to_value(&self) -> Value {
        map([
            ("intent", Some(self.intent.to_value())),
            ("actor", Some(self.actor.to_value())),
            ("since", Some(Value::Unsigned(self.since))),
            (
                "draws",
                (!self.draws.is_empty())
                    .then(|| Value::Array(self.draws.iter().map(Canonical::to_value).collect())),
            ),
            (
                "grounds",
                (!self.grounds.is_empty()).then(|| ids_value(&self.grounds)),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let draws = match f.opt("draws") {
            None => Vec::new(),
            Some(Value::Array(items)) if !items.is_empty() => {
                let draws = items
                    .iter()
                    .map(ExerciseDraw::from_value)
                    .collect::<Result<Vec<_>, _>>()?;
                if draws
                    .iter()
                    .zip(draws.iter().skip(1))
                    .any(|(a, b)| a.key >= b.key)
                {
                    return Err(ModelError::Shape);
                }
                draws
            }
            Some(_) => return Err(ModelError::Shape),
        };
        let s = Self {
            intent: Digest::from_value(f.req("intent")?).ok_or(ModelError::Shape)?,
            actor: id(f.req("actor")?)?,
            since: uint(f.req("since")?)?,
            draws,
            grounds: f
                .opt("grounds")
                .map(|g| set_of(g, true, id))
                .transpose()?
                .unwrap_or_default(),
        };
        f.done()?;
        Ok(s)
    }
}

/// A stored Acceptance, `RestrictionPolicy` or domain Claim: content as given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentState {
    /// Content.
    pub content: Value,
    /// Position of the last change.
    pub since: u64,
    /// Position of the last amendment that widened an Acceptance (OP-141 m.42 (a)).
    pub widened: Option<u64>,
    /// End.
    pub ended: Option<Ended>,
}

impl Canonical for ContentState {
    fn to_value(&self) -> Value {
        map([
            ("content", Some(self.content.clone())),
            ("since", Some(Value::Unsigned(self.since))),
            ("widened", self.widened.map(Value::Unsigned)),
            ("ended", self.ended.as_ref().map(ended_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let s = Self {
            content: f.req("content")?.clone(),
            since: uint(f.req("since")?)?,
            widened: f.opt("widened").map(uint).transpose()?,
            ended: ended(f.opt("ended"))?,
        };
        f.done()?;
        Ok(s)
    }
}

fn read<T: Canonical>(view: &dyn View, kind: &str, id: &Id) -> Result<T, MetaError> {
    let v = view.get(&key(kind, id)).ok_or(MetaError::Unknown)?;
    T::from_value(&v).map_err(|_| MetaError::Corrupt)
}

/// Whether `party` is registered as an organization (C6).
fn organization(view: &dyn View, party: &Id) -> Result<bool, MetaError> {
    view.get(&key(kind::PARTY, party)).map_or(Ok(false), |v| {
        PartyState::from_value(&v)
            .map(|p| p.actor_kind == ActorKind::Organization)
            .map_err(|_| MetaError::Corrupt)
    })
}

fn ids(view: &dyn View, kind: &str, of: &Id) -> Result<BTreeSet<Id>, MetaError> {
    view.get(&key(kind, of)).map_or_else(
        || Ok(BTreeSet::new()),
        |v| set_of(&v, false, id).map_err(|_| MetaError::Corrupt),
    )
}

fn ids_value(s: &BTreeSet<Id>) -> Value {
    set_value(s.iter().map(Canonical::to_value))
}

fn live<T>(ended: Option<Ended>, t: T) -> Result<T, MetaError> {
    if ended.is_some() {
        Err(MetaError::Ended)
    } else {
        Ok(t)
    }
}

/// The Genesis Anchors as effects; the first is the meta-anchor and carries `meta_sets`
/// (OP-159 m.3 (j)).
fn anchor_effects(
    domain: &Digest,
    anchors: Vec<(AnchorScope, Root, BTreeSet<RequirementTerm>)>,
    mut meta_sets: RootSets,
) -> Vec<Effect> {
    let mut out = Vec::new();
    for (seq, (scope, root, root_terms)) in (0_u64..).zip(anchors) {
        let a = object_id(domain, kind::ANCHOR, seq);
        out.push((
            key(kind::ANCHOR, &a),
            Some(
                AnchorState {
                    scope,
                    root,
                    root_terms,
                    sets: if seq == 0 {
                        core::mem::take(&mut meta_sets)
                    } else {
                        RootSets::default()
                    },
                    since: 0,
                    ended: None,
                }
                .to_value(),
            ),
        ));
    }
    out
}

/// The objects Genesis creates, as effects (C4, OP-141 m.6). The meta-anchor is the first Anchor.
///
/// # Errors
/// [`MetaError::Malformed`] for fields that are not `genesis-fields`.
pub fn genesis_effects(
    domain: &Digest,
    fields: &BTreeMap<String, Value>,
) -> Result<Vec<Effect>, MetaError> {
    let mut out = Vec::new();
    let mut known = 0_usize;
    let mut take = |k: &str| {
        let v = fields.get(k);
        if v.is_some() {
            known = known.saturating_add(1);
        }
        v
    };
    let meta = take("meta_anchor").ok_or(MetaError::Malformed(ModelError::Missing))?;
    let mut f = Fields::of(meta)?;
    let meta_root = root(f.req("root")?)?;
    let meta_terms = requirements(f.opt("root_terms"))?;
    // SEC20, OP-158 m.3 (b)
    let entry = f.opt("recovery").cloned();
    // OP-158 m.11, OP-159 m.3 (j)
    let meta_sets = f
        .opt("sets")
        .map(root_sets)
        .transpose()?
        .unwrap_or_default();
    f.done()?;
    let keys_held = genesis_keys_held(entry.as_ref(), take("binding"), &meta_root)?;
    let mut anchors = alloc::vec![(AnchorScope::Domain, meta_root, meta_terms)];
    if let Some(list) = take("anchors") {
        for a in crate::codec::set_items(list, true)? {
            let mut f = Fields::of(a)?;
            anchors.push((
                scope(f.req("scope")?)?,
                root(f.req("root")?)?,
                requirements(f.opt("root_terms"))?,
            ));
            f.done()?;
        }
    }
    out.extend(anchor_effects(domain, anchors, meta_sets));
    let anchor_count = u64::try_from(out.len()).map_err(|_| MetaError::Depth)?;
    let mut children: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
    if let Some(list) = take("grants") {
        for (seq, g) in (0_u64..).zip(crate::codec::set_items(list, true)?) {
            let mut f = Fields::of(g)?;
            let index = uint(f.req("anchor")?)?;
            if index >= anchor_count {
                return Err(MetaError::Malformed(ModelError::Range));
            }
            let parent = object_id(domain, kind::ANCHOR, index);
            let content = GrantContent {
                basis: GrantBasis::Anchor(parent),
                holder: SubjectSelector::from_value(f.req("holder")?)?,
                authority: CanonicalAuthority::from_value(f.req("authority")?)?,
                agency: agency(f.opt("agency"))?,
                named: None,
            };
            f.done()?;
            let gid = object_id(domain, kind::GRANT, seq);
            children.entry(parent).or_default().insert(gid);
            out.push((
                key(kind::GRANT, &gid),
                Some(
                    GrantState {
                        content,
                        since: 0,
                        revision: 0,
                        ended: None,
                    }
                    .to_value(),
                ),
            ));
        }
    }
    for (parent, kids) in children {
        out.push((key(kind::CHILDREN, &parent), Some(ids_value(&kids))));
    }
    if let Some(list) = take("acceptances") {
        out.extend(genesis_acceptances(domain, list)?);
    }
    if let Some(policy) = take("policy") {
        out.extend(genesis_policy(policy)?);
    }
    out.extend(keys_held);
    let _ = take("reserved");
    let _ = take("versions");
    if known != fields.len() {
        return Err(MetaError::Malformed(ModelError::Unknown));
    }
    Ok(out)
}

/// The Genesis provider binding and the meta-anchor's recovery entry, which no key of that
/// binding and no Party outside the root may hold (§9.15, SEC20, U16, OP-158 m.3 (b)).
fn genesis_keys_held(
    entry: Option<&Value>,
    binding: Option<&Value>,
    meta_root: &Root,
) -> Result<Vec<Effect>, MetaError> {
    let mut out = Vec::new();
    let provider = binding.map(crate::recovery::genesis_binding).transpose()?;
    if let Some(e) = entry {
        let e = crate::recovery::RecoveryEntry::from_value(e)?;
        let kids = provider
            .as_ref()
            .map(|(k, _)| k.clone())
            .unwrap_or_default();
        if !crate::recovery::admissible(&e, &root_parties(meta_root), &kids) {
            return Err(MetaError::NotWithin);
        }
        out.push((crate::recovery::entry_key(), Some(e.to_value())));
    }
    if let Some((_, v)) = provider {
        out.push((crate::recovery::binding_key(), Some(v)));
    }
    Ok(out)
}

/// The policy defaults a Genesis sets: the CT3 time-lock (OP-141 m.34 (d)) and the
/// causal-bound allowance declaration (OP-152 m.7 (d) E11), which is only ever `true`.
fn genesis_policy(policy: &Value) -> Result<Vec<Effect>, MetaError> {
    let mut out = Vec::new();
    let mut f = Fields::of(policy)?;
    if let Some(delay) = f.opt(CT3_DELAY) {
        out.push((
            policy_default_key(CT3_DELAY),
            Some(Value::Unsigned(uint(delay)?)),
        ));
    }
    match f.opt(CAUSAL_BINDING) {
        None => {}
        Some(Value::Bool(true)) => {
            out.push((policy_default_key(CAUSAL_BINDING), Some(Value::Bool(true))));
        }
        Some(_) => return Err(MetaError::Malformed(ModelError::Shape)),
    }
    f.done()?;
    Ok(out)
}

/// Genesis Acceptances with their per-issuer index (L0-META-5, L0-META-7).
fn genesis_acceptances(domain: &Digest, list: &Value) -> Result<Vec<Effect>, MetaError> {
    let mut out = Vec::new();
    let mut by_issuer: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
    for (seq, a) in (0_u64..).zip(crate::codec::set_items(list, true)?) {
        let aid = object_id(domain, kind::ACCEPTANCE, seq);
        if let Some(Value::Bytes(_)) = a.get("issuer") {
            by_issuer
                .entry(id(a.get("issuer").ok_or(ModelError::Shape)?)?)
                .or_default()
                .insert(aid);
        }
        out.push((
            key(kind::ACCEPTANCE, &aid),
            Some(
                ContentState {
                    content: acceptance_content(a)?,
                    since: 0,
                    widened: None,
                    ended: None,
                }
                .to_value(),
            ),
        ));
    }
    for (issuer, set) in by_issuer {
        out.push((key(kind::ACCEPTANCES, &issuer), Some(ids_value(&set))));
    }
    // OP-143 m.13 (a)
    let mut by_domain: BTreeMap<Vec<u8>, BTreeSet<Id>> = BTreeMap::new();
    for (seq, a) in (0_u64..).zip(crate::codec::set_items(list, true)?) {
        if let Some(foreign) = crate::foreign::ForeignIssuer::of(a)? {
            by_domain
                .entry(crate::foreign::index_key(&foreign.domain))
                .or_default()
                .insert(object_id(domain, kind::ACCEPTANCE, seq));
        }
    }
    for (k, set) in by_domain {
        out.push((k, Some(ids_value(&set))));
    }
    // OP-141 m.20 (e)
    let mut by_class: BTreeMap<String, (Option<Value>, BTreeSet<Id>)> = BTreeMap::new();
    for (seq, a) in (0_u64..).zip(crate::codec::set_items(list, true)?) {
        if a.get("use") != Some(&Value::text("subject-selection")) {
            continue;
        }
        for class in classes_of(a) {
            let entry = by_class
                .entry(class)
                .or_insert((a.get("issuer").cloned(), BTreeSet::new()));
            if entry.0 != a.get("issuer").cloned() {
                return Err(MetaError::NotWithin);
            }
            entry.1.insert(object_id(domain, kind::ACCEPTANCE, seq));
        }
    }
    for (class, (_, set)) in by_class {
        out.push((selection_key(&class), Some(ids_value(&set))));
    }
    // OP-141 m.35 (d)
    let mut by_namespace: BTreeMap<String, BTreeSet<Id>> = BTreeMap::new();
    for (seq, a) in (0_u64..).zip(crate::codec::set_items(list, true)?) {
        if let Some(ns) = spp_namespace(a) {
            by_namespace
                .entry(ns)
                .or_default()
                .insert(object_id(domain, kind::ACCEPTANCE, seq));
        }
    }
    for (ns, set) in by_namespace {
        out.push((crate::schema::schemas_key(&ns), Some(ids_value(&set))));
    }
    Ok(out)
}

/// Effects sorted by key bytes, the last write of a key winning (L0-META-29).
#[must_use]
pub fn sorted(effects: Vec<Effect>) -> Vec<Effect> {
    effects
        .into_iter()
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .collect()
}

/// The meta-anchor of a domain.
#[must_use]
pub fn meta_anchor(domain: &Digest) -> Id {
    object_id(domain, kind::ANCHOR, 0)
}

/// Who is acting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Actor {
    /// The actor Instance's Party.
    pub party: Id,
    /// The actor Instance.
    pub instance: Id,
}

/// Everything a meta-action is decided against besides state.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// The domain.
    pub domain: Digest,
    /// The `ExerciseID`; new objects derive their ids from it.
    pub exercise: Digest,
    /// Position the decision record will have.
    pub pos: u64,
    /// Trusted time.
    pub now: crate::model::TrustedTime,
    /// The actor.
    pub actor: Actor,
    /// The basis the Exercise names.
    pub basis: ExerciseBasis,
    /// The capacity it declares.
    pub capacity: Capacity,
    /// The pinned catalog.
    pub catalog: &'a Catalog,
}

/// What an allowed meta-action does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// State changes (L2-REC-2).
    pub effects: Vec<Effect>,
    /// Requirements it adds: root terms and joint-root contributions.
    pub requirements: BTreeSet<RequirementTerm>,
    /// Whether it widens authority (expansion class, XI-4); otherwise it narrows or creates.
    pub expansion: bool,
    /// Budget counter keys and the amounts released from them (OP-141 m.28 (g)).
    pub releases: Vec<(Vec<u8>, u64)>,
}

const CO_ROOT: &str = "co_root";

/// Contributions a CT3 meta-action needs from the other principals of a joint root
/// (§13.7.3, SEC26, OP-141 m.43, PD).
pub const CT3_QUORUM: u64 = 2;

/// `count` `co_root` contributions from distinct Parties, bound to the intent.
fn co_root(count: u64) -> RequirementTerm {
    RequirementTerm {
        proof_kind: crate::model::ProofKind::Contribution,
        class: String::from(CO_ROOT),
        count,
        binding: crate::model::Binding::IntentDigest,
        freshness_ms: None,
        independence: crate::model::Independence::DistinctParty,
        consumption: crate::model::Consumption::SingleUse,
        source: None,
        assurance: BTreeMap::new(),
    }
}

/// The contribution class a Party gives to a root change that makes it a root (L0-META-20,
/// TN-91): its own consent, bound to the change's intent.
pub const ACCEPT_ROOT: &str = "accept_root";

fn root_parties(r: &Root) -> BTreeSet<Id> {
    match r {
        Root::Sole(p) => BTreeSet::from([*p]),
        Root::Joint { parties, .. } => parties.iter().copied().collect(),
    }
}

/// One `accept_root` contribution from `party`, single use, bound to the intent.
#[must_use]
pub fn accept_root(party: Id) -> RequirementTerm {
    RequirementTerm {
        proof_kind: crate::model::ProofKind::Contribution,
        class: String::from(ACCEPT_ROOT),
        count: 1,
        binding: crate::model::Binding::IntentDigest,
        freshness_ms: None,
        independence: crate::model::Independence::DistinctParty,
        consumption: crate::model::Consumption::SingleUse,
        source: Some(SubjectSelector::Party(party)),
        assurance: BTreeMap::new(),
    }
}

/// The `accept_root` terms of a root change from `old` to `new`: one for each Party `new`
/// names and `old` does not (L0-META-20, TN-91, OP-153 m.17 (b)).
fn accepting(old: &Root, new: &Root) -> BTreeSet<RequirementTerm> {
    let had = root_parties(old);
    root_parties(new)
        .into_iter()
        .filter(|p| !had.contains(p))
        .map(accept_root)
        .collect()
}

/// The requirements of acting as `anchor`'s root: its root terms and, for a joint root of `k`,
/// `k − 1` further `co_root` contributions (L0-META-10); `None` when the actor is not a root.
#[must_use]
pub fn root_requirements(anchor: &AnchorState, actor: &Actor) -> Option<BTreeSet<RequirementTerm>> {
    let mut req = anchor.root_terms.clone();
    match &anchor.root {
        Root::Sole(p) if *p == actor.party => {}
        Root::Joint { parties, k } if parties.contains(&actor.party) => {
            if *k > 1 {
                req.insert(co_root(k.saturating_sub(1)));
            }
        }
        _ => return None,
    }
    Some(req)
}

fn root_power(
    view: &dyn View,
    anchor: &Id,
    actor: &Actor,
) -> Result<(AnchorState, BTreeSet<RequirementTerm>), MetaError> {
    let a: AnchorState = read(view, kind::ANCHOR, anchor)?;
    let a = live(a.ended, a)?;
    let req = root_requirements(&a, actor).ok_or(MetaError::NotAuthorized)?;
    Ok((a, req))
}

fn anchor_of_basis(ctx: &Context<'_>) -> Result<Id, MetaError> {
    match ctx.basis {
        ExerciseBasis::Anchor(a) => Ok(a),
        _ => Err(MetaError::Basis),
    }
}

/// The resource selector an Anchor scope covers; `None` is the whole domain.
fn scope_selector(s: &AnchorScope) -> Option<ResourceSelector> {
    match s {
        AnchorScope::Resource(r) => Some(r.clone()),
        AnchorScope::Party(p) => Some(ResourceSelector::Structural(crate::model::Structural {
            namespace: String::from("access.party"),
            prefix: alloc::vec![hex16(p)],
            kind: None,
            attrs: BTreeMap::new(),
        })),
        AnchorScope::Domain => None,
    }
}

fn hex16(id: &Id) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for b in id.0 {
        for nibble in [b >> 4, b & 0x0f] {
            s.push(HEX.get(usize::from(nibble)).map_or('0', |c| char::from(*c)));
        }
    }
    s
}

fn within_scope(inner: Option<&ResourceSelector>, outer: Option<&ResourceSelector>) -> bool {
    match (inner, outer) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(i), Some(o)) => resource_le(i, o),
    }
}

/// The lineage of a Grant from its Anchor down to itself.
fn lineage(view: &dyn View, grant: &Id) -> Result<(Id, Vec<(Id, GrantState)>), MetaError> {
    let mut chain = Vec::new();
    let mut at = *grant;
    loop {
        if chain.len() >= MAX_LINEAGE {
            return Err(MetaError::Depth);
        }
        let g: GrantState = read(view, kind::GRANT, &at)?;
        let next = g.content.basis;
        chain.push((at, g));
        match next {
            GrantBasis::Anchor(a) => {
                chain.reverse();
                return Ok((a, chain));
            }
            GrantBasis::Holding(h) => at = h.grant,
        }
    }
}

fn holds(g: &GrantState, party: &Id) -> bool {
    matches!(g.content.holder, SubjectSelector::Party(p) if p == *party)
}

/// OP-141 m.3: the root of the lineage's Anchor, or the holder of a Grant above `grant`.
fn lineage_power(
    view: &dyn View,
    grant: &Id,
    actor: &Actor,
) -> Result<BTreeSet<RequirementTerm>, MetaError> {
    let (anchor, chain) = lineage(view, grant)?;
    let above = chain.len().saturating_sub(1);
    if chain
        .iter()
        .take(above)
        .any(|(_, g)| g.ended.is_none() && holds(g, &actor.party))
    {
        return Ok(BTreeSet::new());
    }
    root_power(view, &anchor, actor).map(|(_, r)| r)
}

fn new_id(ctx: &Context<'_>, kind: &str, seq: u64) -> Id {
    object_id(&ctx.exercise, kind, seq)
}

fn set(out: &mut Outcome, kind: &str, id: &Id, v: Value) {
    out.effects.push((key(kind, id), Some(v)));
}

fn add_child(view: &dyn View, out: &mut Outcome, parent: &Id, child: Id) -> Result<(), MetaError> {
    let mut kids = ids(view, kind::CHILDREN, parent)?;
    kids.insert(child);
    set(out, kind::CHILDREN, parent, ids_value(&kids));
    Ok(())
}

const fn end(at: u64, how: EndedHow) -> Ended {
    Ended { at, how }
}

/// Applies a disposition to the live children of `parent`; it must name exactly them (C10).
fn dispose(
    view: &dyn View,
    out: &mut Outcome,
    parent: &Id,
    disposition: &BTreeMap<Id, Disposition>,
    pos: u64,
    keep_allowed: bool,
) -> Result<(), MetaError> {
    let mut live_kids = Vec::new();
    for kid in ids(view, kind::CHILDREN, parent)? {
        let g: GrantState = read(view, kind::GRANT, &kid)?;
        if g.ended.is_none() {
            live_kids.push((kid, g));
        }
    }
    let named: BTreeSet<&Id> = disposition.keys().collect();
    let current: BTreeSet<&Id> = live_kids.iter().map(|(k, _)| k).collect();
    if named != current {
        return Err(MetaError::Disposition);
    }
    for (kid, mut g) in live_kids {
        match disposition.get(&kid) {
            Some(Disposition::Revoke) => {
                g.ended = Some(end(pos, EndedHow::Revoked));
                set(out, kind::GRANT, &kid, g.to_value());
            }
            Some(Disposition::Keep) if keep_allowed => {}
            _ => return Err(MetaError::Disposition),
        }
    }
    Ok(())
}

fn principal(ctx: &Context<'_>) -> Id {
    match ctx.capacity {
        Capacity::Own => ctx.actor.party,
        Capacity::For(p) => p,
    }
}

fn agency_ok(agency: &BTreeSet<Capacity>, principal: &Id) -> bool {
    agency.iter().all(|c| match c {
        Capacity::Own => true,
        Capacity::For(p) => p == principal,
    })
}

fn own_instance(view: &dyn View, instance: &Id, actor: &Actor) -> Result<InstanceState, MetaError> {
    let i: InstanceState = read(view, kind::INSTANCE, instance)?;
    let i = live(i.ended, i)?;
    if i.party == actor.party {
        Ok(i)
    } else {
        Err(MetaError::NotAuthorized)
    }
}

fn pin_ok(view: &dyn View, pin: Option<&HoldingRef>, party: &Id) -> Result<(), MetaError> {
    let Some(h) = pin else { return Ok(()) };
    let g: GrantState = read(view, kind::GRANT, &h.grant)?;
    let g = live(g.ended, g)?;
    if h.holder == *party && holds(&g, party) && h.since == g.since {
        Ok(())
    } else {
        Err(MetaError::NotAuthorized)
    }
}

fn bind_mandate(
    view: &dyn View,
    ctx: &Context<'_>,
    out: &mut Outcome,
    instance: Id,
    envelope: MandateEnvelope,
    seq: u64,
) -> Result<(), MetaError> {
    pin_ok(view, envelope.pin.as_ref(), &ctx.actor.party)?;
    let m = new_id(ctx, kind::MANDATE, seq);
    set(
        out,
        kind::MANDATE,
        &m,
        MandateState {
            instance,
            envelope,
            since: ctx.pos,
            ended: None,
        }
        .to_value(),
    );
    let mut list = ids(view, kind::MANDATES, &instance)?;
    list.insert(m);
    set(out, kind::MANDATES, &instance, ids_value(&list));
    Ok(())
}

/// Refuses a payload that does not read back as itself: an in-process payload whose
/// identifiers the codec would refuse writes state no reader can decode (L0-META-1).
fn readable(payload: &Payload) -> Result<(), MetaError> {
    // OP-153 m.20 (a), m.25 (a)
    match Payload::from_value(&payload.to_value()) {
        Ok(p) if p == *payload => Ok(()),
        Ok(_) => Err(MetaError::Malformed(ModelError::Shape)),
        Err(e) => Err(MetaError::Malformed(e)),
    }
}

/// Decides a meta-action under the implicit powers of OP-141 m.3 and returns what it does.
/// The caller still evaluates the requirements it returns, and for a meta-action no implicit
/// power covers it evaluates an ordinary Grant over the core action instead.
///
/// # Errors
/// [`MetaError`]; the caller maps it to a blocker.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per meta-action of the closed list"
)]
pub fn apply(ctx: &Context<'_>, payload: &Payload, view: &dyn View) -> Result<Outcome, MetaError> {
    readable(payload)?;
    let mut out = Outcome::default();
    let actor = ctx.actor;
    match payload {
        Payload::AnchorCreate {
            scope: s,
            root: r,
            root_terms,
            sets,
        } => {
            let covering = anchor_of_basis(ctx)?;
            let (a, req) = root_power(view, &covering, &actor)?;
            let inner = scope_selector(s);
            // OP-159 m.3 (j)
            if !sets.is_empty()
                || matches!(s, AnchorScope::Domain)
                || !within_scope(inner.as_ref(), scope_selector(&a.scope).as_ref())
            {
                return Err(MetaError::NotWithin);
            }
            out.requirements = req;
            out.expansion = true;
            let id = new_id(ctx, kind::ANCHOR, 0);
            set(
                &mut out,
                kind::ANCHOR,
                &id,
                AnchorState {
                    scope: s.clone(),
                    root: r.clone(),
                    root_terms: root_terms.clone(),
                    sets: RootSets::default(),
                    since: ctx.pos,
                    ended: None,
                }
                .to_value(),
            );
        }
        Payload::AnchorTransfer {
            anchor,
            root: r,
            disposition,
        } => {
            let (mut a, req) = match ctx.basis {
                ExerciseBasis::Anchor(b) if b == *anchor => {
                    let (a, mut req) = root_power(view, anchor, &actor)?;
                    req.extend(accepting(&a.root, r));
                    (a, req)
                }
                ExerciseBasis::Holding(h) => conditional_transfer(ctx, view, anchor, r, &h)?,
                _ => return Err(MetaError::Basis),
            };
            dispose(view, &mut out, anchor, disposition, ctx.pos, true)?;
            a.root = r.clone();
            // L0-META-6
            a.since = ctx.pos;
            out.requirements = req;
            out.expansion = true;
            set(&mut out, kind::ANCHOR, anchor, a.to_value());
        }
        Payload::AnchorAmend {
            anchor,
            root: r,
            root_terms,
            sets,
        } => {
            if anchor_of_basis(ctx)? != *anchor {
                return Err(MetaError::Basis);
            }
            let (mut a, mut req) = root_power(view, anchor, &actor)?;
            if let Some(r) = r {
                req.extend(accepting(&a.root, r));
                a.root = r.clone();
            }
            if let Some(t) = root_terms {
                out.expansion = !t.is_superset(&a.root_terms);
                a.root_terms.clone_from(t);
            }
            // OP-158 m.11, OP-159 m.3 (j)
            if let Some(new) = sets {
                if *anchor != meta_anchor(&ctx.domain) {
                    return Err(MetaError::NotWithin);
                }
                out.expansion |= a.sets.witnesses.iter().any(|w| !new.witnesses.contains(w))
                    || a.sets.replicas.iter().any(|r| !new.replicas.contains(r));
                a.sets = new.clone();
            }
            out.expansion |= r.is_some();
            // L0-META-6
            a.since = ctx.pos;
            out.requirements = req;
            set(&mut out, kind::ANCHOR, anchor, a.to_value());
        }
        Payload::AnchorRetire {
            anchor,
            disposition,
        } => {
            if anchor_of_basis(ctx)? != *anchor || *anchor == meta_anchor(&ctx.domain) {
                return Err(MetaError::Basis);
            }
            let (mut a, req) = root_power(view, anchor, &actor)?;
            dispose(view, &mut out, anchor, disposition, ctx.pos, false)?;
            a.ended = Some(end(ctx.pos, EndedHow::Retired));
            out.requirements = req;
            set(&mut out, kind::ANCHOR, anchor, a.to_value());
        }
        Payload::PartyRegister {
            party,
            root: r,
            actor_kind,
        } => {
            if !matches!(ctx.basis, ExerciseBasis::Public(_)) {
                return Err(MetaError::Basis);
            }
            if *party != actor.party {
                return Err(MetaError::NotAuthorized);
            }
            if view.get(&key(kind::PARTY, party)).is_some() {
                return Err(MetaError::Ended);
            }
            let a = new_id(ctx, kind::ANCHOR, 0);
            set(
                &mut out,
                kind::ANCHOR,
                &a,
                AnchorState {
                    scope: AnchorScope::Party(*party),
                    root: r.clone(),
                    root_terms: BTreeSet::new(),
                    sets: RootSets::default(),
                    since: ctx.pos,
                    ended: None,
                }
                .to_value(),
            );
            set(
                &mut out,
                kind::PARTY,
                party,
                PartyState {
                    anchor: a,
                    actor_kind: *actor_kind,
                    since: ctx.pos,
                    ended: None,
                }
                .to_value(),
            );
            out.expansion = true;
        }
        Payload::PartyDepart { party, disposition } => {
            let (_, req) = root_power(view, &meta_anchor(&ctx.domain), &actor)?;
            if anchor_of_basis(ctx)? != meta_anchor(&ctx.domain) {
                return Err(MetaError::Basis);
            }
            let mut p: PartyState = read(view, kind::PARTY, party)?;
            p = live(p.ended, p.clone())?;
            dispose(view, &mut out, &p.anchor, disposition, ctx.pos, false)?;
            let mut a: AnchorState = read(view, kind::ANCHOR, &p.anchor)?;
            a.ended = Some(end(ctx.pos, EndedHow::Retired));
            set(&mut out, kind::ANCHOR, &p.anchor, a.to_value());
            for i in ids(view, kind::INSTANCES, party)? {
                let mut inst: InstanceState = read(view, kind::INSTANCE, &i)?;
                if inst.ended.is_none() {
                    inst.ended = Some(end(ctx.pos, EndedHow::Departed));
                    set(&mut out, kind::INSTANCE, &i, inst.to_value());
                }
            }
            p.ended = Some(end(ctx.pos, EndedHow::Departed));
            set(&mut out, kind::PARTY, party, p.to_value());
            out.requirements = req;
        }
        Payload::InstanceCreate {
            party,
            key: k,
            mandate,
        } => {
            if !matches!(ctx.basis, ExerciseBasis::Public(_)) {
                return Err(MetaError::Basis);
            }
            if *party != actor.party {
                return Err(MetaError::NotAuthorized);
            }
            let p: PartyState = read(view, kind::PARTY, party)?;
            live(p.ended, ())?;
            // C6, OP-153 m.3 (b)
            if p.actor_kind == ActorKind::Organization {
                return Err(MetaError::NotAuthorized);
            }
            let i = new_id(ctx, kind::INSTANCE, 0);
            if i != actor.instance {
                return Err(MetaError::NotAuthorized);
            }
            set(
                &mut out,
                kind::INSTANCE,
                &i,
                InstanceState {
                    party: *party,
                    key: k.clone(),
                    since: ctx.pos,
                    successor: None,
                    ended: None,
                }
                .to_value(),
            );
            let mut list = ids(view, kind::INSTANCES, party)?;
            list.insert(i);
            set(&mut out, kind::INSTANCES, party, ids_value(&list));
            index_key(&mut out, k, &i);
            if let Some(m) = mandate {
                bind_mandate(view, ctx, &mut out, i, m.clone(), 0)?;
            }
            out.expansion = true;
        }
        Payload::InstanceRekey { instance, key: k } => {
            if *instance != actor.instance {
                return Err(MetaError::NotAuthorized);
            }
            let mut i = own_instance(view, instance, &actor)?;
            unindex_key(&mut out, &i.key);
            index_key(&mut out, k, instance);
            i.key = k.clone();
            // L0-META-6
            i.since = ctx.pos;
            set(&mut out, kind::INSTANCE, instance, i.to_value());
        }
        Payload::InstanceTerminate { instance } => {
            let mut i: InstanceState = read(view, kind::INSTANCE, instance)?;
            i = live(i.ended, i.clone())?;
            if i.party != actor.party {
                let p: PartyState = read(view, kind::PARTY, &i.party)?;
                out.requirements = root_power(view, &p.anchor, &actor)?.1;
            }
            i.ended = Some(end(ctx.pos, EndedHow::Terminated));
            set(&mut out, kind::INSTANCE, instance, i.to_value());
        }
        Payload::InstanceRecover { instance, key: k } => {
            let mut old = own_instance(view, instance, &actor)?;
            // C6, OP-153 m.3 (b)
            if organization(view, &old.party)? {
                return Err(MetaError::NotAuthorized);
            }
            let succ = new_id(ctx, kind::INSTANCE, 0);
            old.successor = Some(succ);
            old.ended = Some(end(ctx.pos, EndedHow::Recovered));
            set(&mut out, kind::INSTANCE, instance, old.to_value());
            set(
                &mut out,
                kind::INSTANCE,
                &succ,
                InstanceState {
                    party: old.party,
                    key: k.clone(),
                    since: ctx.pos,
                    successor: None,
                    ended: None,
                }
                .to_value(),
            );
            let mut list = ids(view, kind::INSTANCES, &old.party)?;
            list.insert(succ);
            set(&mut out, kind::INSTANCES, &old.party, ids_value(&list));
            unindex_key(&mut out, &old.key);
            index_key(&mut out, k, &succ);
            out.expansion = true;
        }
        Payload::MandateBind { instance, envelope } => {
            own_instance(view, instance, &actor)?;
            bind_mandate(view, ctx, &mut out, *instance, envelope.clone(), 0)?;
            out.expansion = true;
        }
        Payload::MandateRebind { mandate, envelope } => {
            let mut m: MandateState = read(view, kind::MANDATE, mandate)?;
            m = live(m.ended, m.clone())?;
            own_instance(view, &m.instance, &actor)?;
            pin_ok(view, envelope.pin.as_ref(), &actor.party)?;
            // E54 (4)
            let origins_within = envelope.origins.read.is_subset(&m.envelope.origins.read)
                && envelope.origins.write.is_subset(&m.envelope.origins.write);
            out.expansion = !subsumes(&envelope.authority, &m.envelope.authority, ctx.catalog)
                || !origins_within;
            m.envelope = envelope.clone();
            m.since = ctx.pos;
            set(&mut out, kind::MANDATE, mandate, m.to_value());
        }
        Payload::MandateRevoke { mandate } => {
            let mut m: MandateState = read(view, kind::MANDATE, mandate)?;
            m = live(m.ended, m.clone())?;
            own_instance(view, &m.instance, &actor)?;
            m.ended = Some(end(ctx.pos, EndedHow::Revoked));
            set(&mut out, kind::MANDATE, mandate, m.to_value());
        }
        Payload::GrantIssue(content) => {
            if !agency_ok(&content.agency, &principal(ctx)) {
                return Err(MetaError::Agency);
            }
            let parent = match content.basis {
                GrantBasis::Anchor(a) => {
                    if ctx.basis != ExerciseBasis::Anchor(a) {
                        return Err(MetaError::Basis);
                    }
                    let (anchor, req) = root_power(view, &a, &actor)?;
                    let sel = Some(content.authority.authority.resource.clone());
                    if !within_scope(sel.as_ref(), scope_selector(&anchor.scope).as_ref()) {
                        return Err(MetaError::NotWithin);
                    }
                    out.requirements = req;
                    a
                }
                GrantBasis::Holding(h) => {
                    if ctx.basis != ExerciseBasis::Holding(h) || h.holder != actor.party {
                        return Err(MetaError::Basis);
                    }
                    let p: GrantState = read(view, kind::GRANT, &h.grant)?;
                    let p = live(p.ended, p)?;
                    if !holds(&p, &actor.party) || h.since != p.since {
                        return Err(MetaError::NotAuthorized);
                    }
                    if !child_within_parent(
                        &content.authority,
                        &p.content.authority,
                        &content.holder,
                        ctx.catalog,
                    ) {
                        return Err(MetaError::NotWithin);
                    }
                    lineage(view, &h.grant)?;
                    h.grant
                }
            };
            if let Some(pin) = &content.named {
                pinned(view, pin, &content.authority.authority, ctx.catalog)?;
            }
            let g = new_id(ctx, kind::GRANT, 0);
            set(
                &mut out,
                kind::GRANT,
                &g,
                GrantState {
                    content: content.clone(),
                    since: ctx.pos,
                    revision: 0,
                    ended: None,
                }
                .to_value(),
            );
            add_child(view, &mut out, &parent, g)?;
            out.expansion = true;
        }
        Payload::GrantAmend {
            grant,
            authority,
            agency: new_agency,
            named,
        } => {
            let mut g: GrantState = read(view, kind::GRANT, grant)?;
            g = live(g.ended, g.clone())?;
            out.requirements = lineage_power(view, grant, &actor)?;
            let narrows = subsumes(
                &authority.authority,
                &g.content.authority.authority,
                ctx.catalog,
            ) && new_agency.is_subset(&g.content.agency);
            if let GrantBasis::Holding(h) = g.content.basis {
                let p: GrantState = read(view, kind::GRANT, &h.grant)?;
                if !child_within_parent(
                    authority,
                    &p.content.authority,
                    &g.content.holder,
                    ctx.catalog,
                ) {
                    return Err(MetaError::NotWithin);
                }
            }
            // OP-141 m.32 (d)
            if named.is_some() {
                g.content.named.clone_from(named);
            }
            if let Some(pin) = &g.content.named {
                pinned(view, pin, &authority.authority, ctx.catalog)?;
            }
            out.expansion = !narrows;
            g.content.authority = authority.clone();
            g.content.agency.clone_from(new_agency);
            g.revision = g.revision.checked_add(1).ok_or(MetaError::Depth)?;
            set(&mut out, kind::GRANT, grant, g.to_value());
        }
        Payload::GrantRevoke { grant } => {
            let mut g: GrantState = read(view, kind::GRANT, grant)?;
            g = live(g.ended, g.clone())?;
            out.requirements = lineage_power(view, grant, &actor)?;
            g.ended = Some(end(ctx.pos, EndedHow::Revoked));
            set(&mut out, kind::GRANT, grant, g.to_value());
        }
        Payload::GrantRenounce { grant } => {
            let mut g: GrantState = read(view, kind::GRANT, grant)?;
            g = live(g.ended, g.clone())?;
            if !holds(&g, &actor.party) {
                return Err(MetaError::NotAuthorized);
            }
            g.ended = Some(end(ctx.pos, EndedHow::Renounced));
            set(&mut out, kind::GRANT, grant, g.to_value());
        }
        Payload::AcceptanceEstablish(content) => {
            out.requirements = domain_root(ctx, view)?;
            let aid = new_id(ctx, kind::ACCEPTANCE, 0);
            // OP-141 m.35 (d)
            if let Some(ns) = spp_namespace(content) {
                let k = crate::schema::schemas_key(&ns);
                let mut set_of = index_of(view, &k)?;
                set_of.insert(aid);
                out.effects.push((k, Some(ids_value(&set_of))));
            }
            if let Some(issuer @ Value::Bytes(_)) = content.get("issuer") {
                let issuer = id(issuer).map_err(|_| MetaError::Corrupt)?;
                let mut set_of = ids(view, kind::ACCEPTANCES, &issuer)?;
                set_of.insert(aid);
                set(&mut out, kind::ACCEPTANCES, &issuer, ids_value(&set_of));
            }
            // OP-143 m.13 (a)
            if let Ok(Some(foreign)) = crate::foreign::ForeignIssuer::of(content) {
                let k = crate::foreign::index_key(&foreign.domain);
                let mut set_of = index_of(view, &k)?;
                set_of.insert(aid);
                out.effects.push((k, Some(ids_value(&set_of))));
            }
            select(view, &mut out, content, aid, None)?;
            set(
                &mut out,
                kind::ACCEPTANCE,
                &aid,
                ContentState {
                    content: content.clone(),
                    since: ctx.pos,
                    widened: None,
                    ended: None,
                }
                .to_value(),
            );
            out.expansion = true;
        }
        Payload::AcceptanceAmend {
            acceptance,
            content,
        } => {
            out.requirements = domain_root(ctx, view)?;
            let mut a: ContentState = read(view, kind::ACCEPTANCE, acceptance)?;
            a = live(a.ended, a.clone())?;
            let fixed = |c: &Value| {
                (
                    c.get("issuer").cloned(),
                    c.get("use").cloned(),
                    spp_namespace(c),
                )
            };
            if fixed(&a.content) != fixed(content) {
                return Err(MetaError::NotWithin);
            }
            select(view, &mut out, content, *acceptance, Some(&a.content))?;
            // OP-141 m.21 (d)
            out.expansion = match (
                crate::claim::Gate::of(&a.content),
                crate::claim::Gate::of(content),
            ) {
                (Ok(old), Ok(new)) => !crate::claim::narrows(&old, &new),
                _ => true,
            };
            a.content = content.clone();
            a.since = ctx.pos;
            // OP-141 m.42 (a)
            if out.expansion {
                a.widened = Some(ctx.pos);
            }
            set(&mut out, kind::ACCEPTANCE, acceptance, a.to_value());
        }
        Payload::AcceptanceRevoke { acceptance } => {
            out.requirements = domain_root(ctx, view)?;
            let mut a: ContentState = read(view, kind::ACCEPTANCE, acceptance)?;
            a = live(a.ended, a.clone())?;
            a.ended = Some(end(ctx.pos, EndedHow::Revoked));
            set(&mut out, kind::ACCEPTANCE, acceptance, a.to_value());
        }
        Payload::PolicySet {
            policy,
            content,
            defaults,
        } => {
            policy_content(content).map_err(MetaError::Malformed)?;
            // OP-157 m.11 (e), OP-158 m.3 (b), TN-71
            let own = own_anchor_target(ctx, view, content)?;
            out.requirements = match &own {
                Some(req) => req.clone(),
                None => domain_root(ctx, view)?,
            };
            let id = match policy {
                Some(p) => {
                    let s: ContentState = read(view, kind::POLICY, p)?;
                    live(s.ended, ())?;
                    // SI-18, INV-36, OP-157 m.3 (b)
                    out.expansion = !policy_narrows(&s.content, content);
                    *p
                }
                None => new_id(ctx, kind::POLICY, 0),
            };
            // OP-141 m.27 (c)
            let target = content.get("target").cloned().ok_or(MetaError::Corrupt)?;
            if let Some(p) = policy {
                let s: ContentState = read(view, kind::POLICY, p)?;
                if let Some(old) = s.content.get("target").filter(|t| **t != target) {
                    let k = policies_key(old);
                    let mut set_of = index_of(view, &k)?;
                    set_of.remove(p);
                    out.effects
                        .push((k, (!set_of.is_empty()).then(|| ids_value(&set_of))));
                }
            }
            let k = policies_key(&target);
            let mut set_of = index_of(view, &k)?;
            set_of.insert(id);
            out.effects.push((k, Some(ids_value(&set_of))));
            // SI-18, SEC8, OP-157 m.3 (b), (n)
            if let Some(d) = defaults {
                let (effects, loosens) = defaults_effects(view, d);
                out.effects.extend(effects);
                out.expansion |= loosens;
            }
            // OP-157 m.11 (e), OP-158 m.3 (b)
            if own.is_some()
                && (out.expansion
                    || defaults.is_some()
                    || (policy.is_none() && !forbid_only(content)))
            {
                return Err(MetaError::NotWithin);
            }
            set(
                &mut out,
                kind::POLICY,
                &id,
                ContentState {
                    content: content.clone(),
                    since: ctx.pos,
                    widened: None,
                    ended: None,
                }
                .to_value(),
            );
        }
        Payload::PolicyRetire { policy } => {
            out.requirements = domain_root(ctx, view)?;
            let mut s: ContentState = read(view, kind::POLICY, policy)?;
            s = live(s.ended, s.clone())?;
            s.ended = Some(end(ctx.pos, EndedHow::Retired));
            out.expansion = true;
            set(&mut out, kind::POLICY, policy, s.to_value());
        }
        Payload::ClaimIssue {
            subject,
            class,
            value,
            validity,
            bound_intent,
            supersedes,
        } => {
            out.requirements = domain_root(ctx, view)?;
            let cid = new_id(ctx, kind::CLAIM, 0);
            // OP-141 m.31 (f)
            out.effects.push((
                crate::claim::member_key(class, subject, &cid),
                Some(cid.to_value()),
            ));
            // OP-141 m.30 (b)
            if let Some(s) = supersedes {
                out.effects
                    .push((crate::claim::successor_key(s, &cid), Some(cid.to_value())));
            }
            set(
                &mut out,
                kind::CLAIM,
                &cid,
                crate::claim::ClaimState {
                    statement: crate::claim::Statement {
                        domain: ctx.domain,
                        issuer: actor.party,
                        subject: *subject,
                        class: class.clone(),
                        value: Some(value.clone()),
                        issued_at: 0,
                        validity: validity.unwrap_or(Window {
                            from: 0,
                            until: u64::MAX,
                        }),
                        assurance: BTreeMap::new(),
                        bound_intent: *bound_intent,
                        bound_instance: None,
                        bound_resource: None,
                        supersedes: *supersedes,
                    },
                    instance: None,
                    since: ctx.pos,
                    ended: None,
                }
                .to_value(),
            );
            out.expansion = true;
        }
        Payload::Contribute { target, class } => {
            // L0-EVAL-26a, SEC20, OP-158 m.19 (c)
            if class == crate::recovery::RECOVER {
                let entry = view.get(&crate::recovery::entry_key());
                let instance = view.get(&key(kind::INSTANCE, &actor.instance));
                let (Some(entry), Some(instance)) = (entry, instance) else {
                    return Err(MetaError::NotAuthorized);
                };
                let entry = crate::recovery::RecoveryEntry::from_value(&entry)
                    .map_err(|_| MetaError::Corrupt)?;
                let instance =
                    InstanceState::from_value(&instance).map_err(|_| MetaError::Corrupt)?;
                if !entry
                    .keys
                    .contains(&crate::verify::key_scope::thumbprint(&instance.key))
                {
                    return Err(MetaError::NotAuthorized);
                }
            }
            out.effects.push((
                exercise_key(kind::CONTRIBUTION, &ctx.exercise),
                Some(
                    ContributionState {
                        target: *target,
                        class: class.clone(),
                        party: actor.party,
                        instance: actor.instance,
                        since: ctx.pos,
                        consumed: None,
                        statement: None,
                        assurance: BTreeMap::new(),
                        auth_time: None,
                        surface_path: None,
                    }
                    .to_value(),
                ),
            ));
            out.expansion = true;
        }
        Payload::AuthoritySetDefine { name, authority } => {
            out.requirements = domain_root(ctx, view)?;
            let latest = authority_set_key(name, None);
            let version = match view.get(&latest) {
                None => 1,
                Some(v) => uint(&v)
                    .map_err(|_| MetaError::Corrupt)?
                    .checked_add(1)
                    .ok_or(MetaError::Depth)?,
            };
            out.effects.push((latest, Some(Value::Unsigned(version))));
            out.effects.push((
                authority_set_key(name, Some(version)),
                Some(map([
                    ("authority", Some(authority.to_value())),
                    ("since", Some(Value::Unsigned(ctx.pos))),
                ])),
            ));
            out.expansion = true;
        }
        Payload::ConsumptionRelease { exercise, grounds } => {
            release(view, &mut out, &actor, exercise, grounds)?;
        }
        Payload::ProjectionIssue {
            bounds,
            audience,
            class,
            offline_slice,
            ..
        } => {
            // OP-143 m.12
            if offline_slice.is_some()
                && (!matches!(
                    class,
                    crate::validity::ProfileClass::Offline
                        | crate::validity::ProfileClass::Intermittent
                ) || !matches!(ctx.basis, ExerciseBasis::Holding(_)))
            {
                return Err(MetaError::NotWithin);
            }
            out.requirements = project(ctx, view, payload, bounds)?;
            out.effects.push((
                exercise_key(kind::PROJECTION, &ctx.exercise),
                Some(map([
                    ("holder", Some(actor.instance.to_value())),
                    ("basis", Some(basis_value(&ctx.basis))),
                    ("bounds", Some(bounds_digest(bounds).to_value())),
                    (
                        "horizon",
                        Some(Value::Unsigned(bounds.constraints.validity.until)),
                    ),
                    ("audience", Some(texts_value(audience))),
                ])),
            ));
        }
        // §9.13.7, §9.15, PI-15, OP-158 m.3 (b), (l)
        Payload::DomainHandover(h) => {
            out.requirements = domain_scope(ctx, view)?;
            rebind(view, &mut out, ctx, &h.binding, &h.cited, "handover")?;
            out.expansion = true;
        }
        // §13.6, SEC20, SEC21, SEC22, OP-158 m.3 (b), (m)
        Payload::DomainRecover(r) => {
            let general = domain_scope(ctx, view)?;
            let entry = recovery_entry(view)?;
            out.requirements = crate::recovery::entry_terms(&entry);
            match recover_guard(ctx, view, r)? {
                crate::fold::Guard::Pass => {}
                crate::fold::Guard::Lossy { .. } => out.requirements.extend(general),
            }
            rebind(
                view,
                &mut out,
                ctx,
                &r.binding,
                &r.cited_checkpoint,
                "recover",
            )?;
            out.effects.push((
                crate::recovery::recovered_key(),
                Some(map([
                    ("at", Some(Value::Unsigned(ctx.now))),
                    ("pos", Some(Value::Unsigned(ctx.pos))),
                    ("n", Some(Value::Unsigned(r.n))),
                ])),
            ));
            out.expansion = true;
        }
        // OP-56, SI-18, §15.4, OP-158 m.3 (b)
        Payload::VersionActivate { versions } => {
            out.requirements = domain_root(ctx, view)?;
            let k = crate::recovery::versions_key();
            let (floor, pending) = match view.get(&k) {
                None => (
                    crate::verify::key_scope::SpecVersions::default(),
                    crate::verify::key_scope::SpecVersions::default(),
                ),
                Some(v) => {
                    let (floor, pending, at) =
                        crate::recovery::versions_state(&v).map_err(|_| MetaError::Corrupt)?;
                    (
                        crate::version::minimum_at(&floor, &pending, at, ctx.now),
                        pending,
                    )
                }
            };
            out.expansion = crate::version::lowers(&pending, versions);
            out.effects.push((
                k,
                Some(crate::recovery::versions_value(&floor, versions, ctx.now)),
            ));
        }
        // §15.16 k.3, k.4, OP-158 m.3 (b)
        Payload::AlgorithmRetire { algorithm } => {
            out.requirements = domain_root(ctx, view)?;
            let k = crate::recovery::retired_key();
            let mut retired = match view.get(&k) {
                None => BTreeSet::new(),
                Some(v) => set_of(&v, false, crate::codec::int).map_err(|_| MetaError::Corrupt)?,
            };
            retired.insert(algorithm.cose());
            out.effects
                .push((k, Some(set_value(retired.into_iter().map(Value::int)))));
        }
    }
    // L0-META-13, L0-META-30, OP-157 m.22 (f), OP-159 m.3 (k)
    if let ExerciseBasis::Holding(h) = ctx.basis
        && !matches!(payload, Payload::Contribute { .. })
    {
        let terms = holding_terms(ctx, view, &h)?;
        if !carries_terms(payload) {
            out.requirements.extend(terms);
        }
    }
    quorum(ctx, payload, view, &mut out);
    out.effects = sorted(out.effects);
    Ok(out)
}

/// Whether a domain may add `alg` to its allowlist (CR-44, L0-SIG-82, OP-159 m.3 (r)): a domain
/// that declares the FIPS profile cannot add ML-DSA, in whichever order the two are asked for.
///
/// # Errors
/// [`MetaError::AlgorithmProfileConflict`].
pub fn admit_algorithm(
    declared: &crate::verify::key_scope::Declarations,
    alg: crate::verify::cose::Algorithm,
) -> Result<(), MetaError> {
    if declared.crypto_profile == Some(crate::verify::key_scope::CryptoProfile::Fips)
        && crate::verify::ml_dsa::is_ml_dsa(alg)
    {
        return Err(MetaError::AlgorithmProfileConflict);
    }
    Ok(())
}

/// Whether the authority a meta-action creates carries its holding's requirement terms itself:
/// a re-delegation's child and a projection's bounds must be at least as strict as the holding
/// (L0-ALG-61, L0-META-25, L0-META-35), so the terms are met by what is created and not asked
/// of the delegating Exercise (OP-159 m.3 (k)).
const fn carries_terms(payload: &Payload) -> bool {
    matches!(
        payload,
        Payload::GrantIssue(_) | Payload::ProjectionIssue { .. }
    )
}

/// The terms of the holding a meta-Exercise declares (L0-META-13, OP-157 m.22 (f), OP-159
/// m.3 (k)): every Grant of its lineage and the lineage's Anchor have not ended, `now` lies in
/// each Grant's validity window, the first live Mandate of the actor Instance is not pinned to
/// another holding, and the Grants' requirement terms are returned for the Exercise to meet.
/// The powers a meta-action is decided by (root, lineage, own Instance) are not changed, and
/// `contribute` is evaluated against its Grant like any domain action (L0-META-30).
///
/// # Errors
/// [`MetaError::HoldingTerms`] when one of them fails, [`MetaError::Depth`] or
/// [`MetaError::Corrupt`].
pub fn holding_terms(
    ctx: &Context<'_>,
    view: &dyn View,
    h: &HoldingRef,
) -> Result<BTreeSet<RequirementTerm>, MetaError> {
    let fail = |e: MetaError| match e {
        MetaError::Depth | MetaError::Corrupt => e,
        _ => MetaError::HoldingTerms,
    };
    let (anchor, chain) = lineage(view, &h.grant).map_err(fail)?;
    let a: AnchorState = read(view, kind::ANCHOR, &anchor).map_err(fail)?;
    if a.ended.is_some() {
        return Err(MetaError::HoldingTerms);
    }
    let mut terms = BTreeSet::new();
    for (_, g) in &chain {
        let v = &g.content.authority.constraints.validity;
        if g.ended.is_some() || ctx.now < v.from || ctx.now > v.until {
            return Err(MetaError::HoldingTerms);
        }
        terms.extend(g.content.authority.requirements.iter().cloned());
    }
    for m in ids(view, kind::MANDATES, &ctx.actor.instance)? {
        let m: MandateState = read(view, kind::MANDATE, &m)?;
        if m.ended.is_some() {
            continue;
        }
        if m.envelope.pin.is_some_and(|p| p != *h) {
            return Err(MetaError::HoldingTerms);
        }
        break;
    }
    Ok(terms)
}

// §13.7.3, SEC26, OP-141 m.43
fn quorum(ctx: &Context<'_>, payload: &Payload, view: &dyn View, out: &mut Outcome) {
    // SEC20, SEC22
    if matches!(payload, Payload::DomainRecover(_)) {
        return;
    }
    if crate::tier::meta_tier(payload, out.expansion) == crate::tier::Tier::Ct3
        && let ExerciseBasis::Anchor(a) = ctx.basis
        && let Ok(anchor) = read::<AnchorState>(view, kind::ANCHOR, &a)
        && let Root::Joint { parties, k } = &anchor.root
        && parties.contains(&ctx.actor.party)
    {
        let others = u64::try_from(parties.len())
            .unwrap_or(u64::MAX)
            .saturating_sub(1);
        let need = others.min(CT3_QUORUM).max(k.saturating_sub(1));
        if need > 0 {
            out.requirements.retain(|t| t.class != CO_ROOT);
            out.requirements.insert(co_root(need));
        }
    }
}

/// Raises an allowed meta-action's outcome to expansion, with the joint-root quorum an
/// expansion needs: a control-plane analysis may only raise a structurally narrowing change,
/// never lower one (OP-157 m.3 (n)). The raised outcome is a function of the recorded inputs, so
/// a decision record that cites the analysis reproduces it.
pub fn widen(ctx: &Context<'_>, payload: &Payload, view: &dyn View, out: &mut Outcome) {
    if !out.expansion {
        out.expansion = true;
        quorum(ctx, payload, view, out);
    }
}

/// `SHA-256("access/bounds/v1" ‖ 0x00 ‖ dCBOR(canonical-authority))`, the bounds of a
/// projection (L0-META-35).
#[must_use]
pub fn bounds_digest(bounds: &CanonicalAuthority) -> Digest {
    let bytes = dcbor::encode(&bounds.to_value(), Limits::CEILING).unwrap_or_default();
    context_label("access/bounds/v1", &bytes)
}

fn window_in(inner: &Window, outer: &Window) -> bool {
    outer.from <= inner.from && inner.until <= outer.until
}

/// The basis and narrowing rules of `projection_issue`; returns the root requirements of an
/// Anchor basis (OP-143 m.7, L0-META-35).
fn project(
    ctx: &Context<'_>,
    view: &dyn View,
    payload: &Payload,
    bounds: &CanonicalAuthority,
) -> Result<BTreeSet<RequirementTerm>, MetaError> {
    let actor = ctx.actor;
    let mut req = BTreeSet::new();
    match ctx.basis {
        ExerciseBasis::Holding(h) => {
            if h.holder != actor.party {
                return Err(MetaError::Basis);
            }
            let g: GrantState = read(view, kind::GRANT, &h.grant)?;
            let g = live(g.ended, g)?;
            if !holds(&g, &actor.party) || h.since != g.since {
                return Err(MetaError::NotAuthorized);
            }
            let (anchor, chain) = lineage(view, &h.grant)?;
            let a: AnchorState = read(view, kind::ANCHOR, &anchor)?;
            let parent = &g.content.authority;
            if a.ended.is_some()
                || chain.iter().any(|(_, x)| x.ended.is_some())
                || !g.content.agency.contains(&ctx.capacity)
                || !subsumes(&bounds.authority, &parent.authority, ctx.catalog)
                || !window_in(&bounds.constraints.validity, &parent.constraints.validity)
                || !bounds
                    .constraints
                    .conditions
                    .is_superset(&parent.constraints.conditions)
                || !bounds.requirements.is_superset(&parent.requirements)
            {
                return Err(MetaError::NotWithin);
            }
        }
        ExerciseBasis::Anchor(a) => {
            let (anchor, r) = root_power(view, &a, &actor)?;
            if ctx.capacity != Capacity::Own
                || !within_scope(
                    Some(&bounds.authority.resource),
                    scope_selector(&anchor.scope).as_ref(),
                )
            {
                return Err(MetaError::NotWithin);
            }
            req = r;
        }
        ExerciseBasis::Public(_) => return Err(MetaError::Basis),
    }
    if bounds.delegation.depth != 0 || bounds.delegation.downstream_holder_class.is_some() {
        return Err(MetaError::NotWithin);
    }
    for m in ids(view, kind::MANDATES, &actor.instance)? {
        let m: MandateState = read(view, kind::MANDATE, &m)?;
        if m.ended.is_some() {
            continue;
        }
        let e = &m.envelope;
        if !subsumes(&bounds.authority, &e.authority, ctx.catalog)
            || !window_in(&bounds.constraints.validity, &e.constraints.validity)
            || !bounds.requirements.is_superset(&e.requirements)
        {
            return Err(MetaError::NotWithin);
        }
        break;
    }
    let horizon = bounds.constraints.validity.until;
    let ceiling = crate::tier::validity_ceiling(crate::tier::meta_tier(payload, false));
    if horizon < ctx.now || horizon.saturating_sub(ctx.now) > ceiling {
        return Err(MetaError::NotWithin);
    }
    Ok(req)
}

/// A pinned named `AuthoritySet` version: name, version and the digest of its authority-set
/// (OP-141 m.32).
pub type NamedPin = (String, u64, Digest);

fn named_value((n, v, d): &NamedPin) -> Value {
    map([
        ("name", Some(Value::text(n))),
        ("version", Some(Value::Unsigned(*v))),
        ("digest", Some(d.to_value())),
    ])
}

fn named_pin(v: &Value) -> Result<NamedPin, ModelError> {
    let mut g = Fields::of(v)?;
    let out = (
        crate::codec::ident(g.req("name")?)?,
        uint(g.req("version")?)?,
        Digest::from_value(g.req("digest")?).ok_or(ModelError::Shape)?,
    );
    g.done()?;
    Ok(out)
}

/// `dCBOR(["authority_set", name])`, the latest version, or with `version` that version's state
/// (OP-141 m.32 (a)).
#[must_use]
pub fn authority_set_key(name: &str, version: Option<u64>) -> Vec<u8> {
    let mut items = alloc::vec![Value::text(kind::AUTHORITY_SET), Value::text(name)];
    if let Some(v) = version {
        items.push(Value::Unsigned(v));
    }
    dcbor::encode(&Value::Array(items), Limits::CEILING).unwrap_or_default()
}

/// `SHA-256("access/authority-set/v1" ‖ 0x00 ‖ dCBOR(authority-set))` (OP-141 m.32 (b)).
#[must_use]
pub fn authority_set_digest(authority: &AuthoritySet) -> Digest {
    let bytes = dcbor::encode(&authority.to_value(), Limits::CEILING).unwrap_or_default();
    context_label("access/authority-set/v1", &bytes)
}

/// A pin names an existing version by its digest, and `authority` lies within it
/// (OP-141 m.32 (c), (d)).
fn pinned(
    view: &dyn View,
    (name, version, digest): &NamedPin,
    authority: &AuthoritySet,
    catalog: &Catalog,
) -> Result<(), MetaError> {
    let state = view
        .get(&authority_set_key(name, Some(*version)))
        .ok_or(MetaError::Unknown)?;
    let template = state
        .get("authority")
        .ok_or(MetaError::Corrupt)
        .and_then(|a| AuthoritySet::from_value(a).map_err(|_| MetaError::Corrupt))?;
    if authority_set_digest(&template) != *digest || !subsumes(authority, &template, catalog) {
        return Err(MetaError::NotWithin);
    }
    Ok(())
}

/// The policy default holding the CT3 time-lock in seconds (OP-141 m.34 (d)).
pub const CT3_DELAY: &str = "ct3_delay_s";
/// The CT3 time-lock when Genesis sets none: 24 hours (§13.7.3, SEC26).
pub const CT3_DELAY_DEFAULT_S: u64 = 86_400;

/// The policy default declaring causal-bound allowances (§7.9.7.4, E17, OP-152 m.7 (d) E11):
/// `true` when Genesis declares that an upstream `ExerciseID` backs at most one downstream
/// Exercise in the domain. Absent, an upstream causal ref is audit only.
pub const CAUSAL_BINDING: &str = "causal_binding";

/// `dCBOR(["policy_default", name])`: a policy default Genesis sets (OP-141 m.34 (d)).
#[must_use]
pub fn policy_default_key(name: &str) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(alloc::vec![
            Value::text("policy_default"),
            Value::text(name)
        ]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

/// Non-execution of the bound intent (OP-141 m.28 (d)).
pub const NON_EXECUTION: &str = "access_non_execution";
/// The amount actually used by the bound intent (OP-141 m.28 (d)).
pub const ACTUAL_AMOUNT: &str = "access_actual_amount";

/// The Grant a budget counter key belongs to.
#[must_use]
pub fn budget_grant(key: &[u8]) -> Option<Id> {
    match dcbor::decode(key, Limits::CEILING).ok()? {
        Value::Array(items) => match items.as_slice() {
            [Value::Text(t), g, Value::Unsigned(_), Value::Unsigned(_)] if t == "budget" => {
                id(g).ok()
            }
            _ => None,
        },
        _ => None,
    }
}

/// The `released` counter paired with a budget counter key (OP-141 m.28 (g)).
#[must_use]
pub fn released_key(budget: &[u8]) -> Vec<u8> {
    match dcbor::decode(budget, Limits::CEILING) {
        Ok(Value::Array(mut items)) => match items.first_mut() {
            Some(head) => {
                *head = Value::text("released");
                dcbor::encode(&Value::Array(items), Limits::CEILING).unwrap_or_default()
            }
            None => Vec::new(),
        },
        _ => Vec::new(),
    }
}

fn release(
    view: &dyn View,
    out: &mut Outcome,
    actor: &Actor,
    exercise: &Digest,
    grounds: &BTreeSet<Id>,
) -> Result<(), MetaError> {
    let k = exercise_key(kind::EXERCISE, exercise);
    let mut e = view
        .get(&k)
        .ok_or(MetaError::Unknown)
        .and_then(|v| ExerciseState::from_value(&v).map_err(|_| MetaError::Corrupt))?;
    // OP-141 m.28 (c)
    let lineage_holder = || {
        e.draws.iter().any(|d| {
            budget_grant(&d.key)
                .and_then(|g| read::<GrantState>(view, kind::GRANT, &g).ok())
                .is_some_and(|g| g.ended.is_none() && holds(&g, &actor.party))
        })
    };
    if e.actor != actor.instance && !lineage_holder() {
        return Err(MetaError::NotAuthorized);
    }
    // OP-141 m.28 (d)
    let mut none = false;
    let mut actual: Option<u64> = None;
    for g in grounds {
        let c: crate::claim::ClaimState = read(view, kind::CLAIM, g)?;
        live(c.ended, ())?;
        if c.statement.bound_intent != Some(e.intent) {
            return Err(MetaError::NotWithin);
        }
        match (c.statement.class.as_str(), &c.statement.value) {
            (NON_EXECUTION, _) => none = true,
            (ACTUAL_AMOUNT, Some(EqValue::Int(n))) => {
                let n = u64::try_from(*n).map_err(|_| MetaError::NotWithin)?;
                if actual.is_some_and(|a| a != n) {
                    return Err(MetaError::NotWithin);
                }
                actual = Some(n);
            }
            _ => return Err(MetaError::NotWithin),
        }
    }
    // OP-141 m.28 (f)
    if grounds.iter().any(|g| e.grounds.contains(g)) {
        return Err(MetaError::ReleaseExceedsDraw);
    }
    // OP-141 m.28 (e)
    for d in &mut e.draws {
        let target = if none {
            d.drawn
        } else if d.unit.is_some() {
            d.drawn
                .saturating_sub(actual.unwrap_or(d.drawn).min(d.drawn))
        } else {
            0
        };
        let back = target.saturating_sub(d.released);
        if back > 0 {
            d.released = target;
            out.releases.push((d.key.clone(), back));
        }
    }
    if out.releases.is_empty() {
        return Err(MetaError::ReleaseExceedsDraw);
    }
    e.grounds.extend(grounds.iter().copied());
    out.effects.push((k, Some(e.to_value())));
    out.expansion = true;
    Ok(())
}

/// The namespace of a `schema-definition` Acceptance's SPP (OP-141 m.35 (d)).
fn spp_namespace(content: &Value) -> Option<String> {
    match content.get("spp")?.get("namespace")? {
        Value::Text(t) => Some(t.clone()),
        _ => None,
    }
}

/// `dCBOR(["policies", target])`: the restriction policies of a target (OP-141 m.27 (c)).
#[must_use]
pub fn policies_key(target: &Value) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(alloc::vec![Value::text(kind::POLICIES), target.clone()]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

fn index_of(view: &dyn View, key: &[u8]) -> Result<BTreeSet<Id>, MetaError> {
    match view.get(key) {
        Some(v) => crate::codec::set_of(&v, false, Id::from_value).map_err(|_| MetaError::Corrupt),
        None => Ok(BTreeSet::new()),
    }
}

/// `dCBOR(["selection", class])`: the `subject-selection` Acceptances of a class.
#[must_use]
pub fn selection_key(class: &str) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(alloc::vec![
            Value::text(kind::SELECTION),
            Value::text(class)
        ]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

fn classes_of(content: &Value) -> BTreeSet<String> {
    match content.get("classes") {
        Some(Value::Array(c)) => c
            .iter()
            .filter_map(|v| match v {
                Value::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect(),
        _ => BTreeSet::new(),
    }
}

/// OP-141 m.20 (e): a class has one membership issuer; indexes a `subject-selection`
/// Acceptance under each of its classes.
fn select(
    view: &dyn View,
    out: &mut Outcome,
    content: &Value,
    aid: Id,
    before: Option<&Value>,
) -> Result<(), MetaError> {
    if content.get("use") != Some(&Value::text("subject-selection")) {
        return Ok(());
    }
    let issuer = content.get("issuer").cloned();
    let known = before.map(classes_of).unwrap_or_default();
    let now = classes_of(content);
    for class in known.difference(&now) {
        let k = selection_key(class);
        let mut set_of = match view.get(&k) {
            Some(v) => {
                crate::codec::set_of(&v, false, Id::from_value).map_err(|_| MetaError::Corrupt)?
            }
            None => BTreeSet::new(),
        };
        set_of.remove(&aid);
        out.effects
            .push((k, (!set_of.is_empty()).then(|| ids_value(&set_of))));
    }
    for class in now.difference(&known) {
        let k = selection_key(class);
        let mut set_of = match view.get(&k) {
            Some(v) => {
                crate::codec::set_of(&v, false, Id::from_value).map_err(|_| MetaError::Corrupt)?
            }
            None => BTreeSet::new(),
        };
        for other in &set_of {
            let a: ContentState = read(view, kind::ACCEPTANCE, other)?;
            if a.ended.is_none() && a.content.get("issuer").cloned() != issuer {
                return Err(MetaError::NotWithin);
            }
        }
        set_of.insert(aid);
        out.effects.push((k, Some(ids_value(&set_of))));
    }
    Ok(())
}

/// A transfer of `anchor` to the holder of a conditional Grant its root wrote for it: the Grant
/// derives from `anchor` itself, names `anchor_transfer`, carries a `ClaimHeld` while-condition
/// and is in its validity now, and the new root is the holder alone, whose own AIS is its
/// consent. The requirements are `anchor`'s root terms and the Grant's own; the caller checks
/// the condition holds (OP-157 m.13 (b), OP-158 m.3 (b), L0-META-20a).
fn conditional_transfer(
    ctx: &Context<'_>,
    view: &dyn View,
    anchor: &Id,
    new_root: &Root,
    h: &HoldingRef,
) -> Result<(AnchorState, BTreeSet<RequirementTerm>), MetaError> {
    if h.holder != ctx.actor.party || ctx.capacity != Capacity::Own {
        return Err(MetaError::Basis);
    }
    let g: GrantState = read(view, kind::GRANT, &h.grant)?;
    let g = live(g.ended, g)?;
    let authority = &g.content.authority;
    let conditional = authority
        .constraints
        .conditions
        .iter()
        .any(|c| matches!(c, crate::model::WhileCondition::ClaimHeld { .. }));
    if !holds(&g, &ctx.actor.party)
        || h.since != g.since
        || g.content.basis != GrantBasis::Anchor(*anchor)
        || !conditional
        || !authority
            .authority
            .actions
            .exact
            .contains(&core_action("anchor_transfer"))
    {
        return Err(MetaError::NotAuthorized);
    }
    if !window_in(
        &Window {
            from: ctx.now,
            until: ctx.now,
        },
        &authority.constraints.validity,
    ) {
        return Err(MetaError::Ended);
    }
    if *new_root != Root::Sole(ctx.actor.party) {
        return Err(MetaError::NotWithin);
    }
    let a: AnchorState = read(view, kind::ANCHOR, anchor)?;
    let a = live(a.ended, a)?;
    let mut req = a.root_terms.clone();
    req.extend(authority.requirements.iter().cloned());
    Ok((a, req))
}

/// The root requirements of a self-anchor whose root sets a policy on that self-anchor: the
/// basis is the self-anchor and the policy targets `{"anchor": A}` (OP-157 m.11 (e), OP-158
/// m.3 (b)). `None` for every other basis or target, which the meta-anchor root decides.
fn own_anchor_target(
    ctx: &Context<'_>,
    view: &dyn View,
    content: &Value,
) -> Result<Option<BTreeSet<RequirementTerm>>, MetaError> {
    let ExerciseBasis::Anchor(a) = ctx.basis else {
        return Ok(None);
    };
    if a == meta_anchor(&ctx.domain)
        || content.get("target")
            != Some(&Value::Map(alloc::vec![(
                Value::text("anchor"),
                a.to_value()
            )]))
    {
        return Ok(None);
    }
    let (anchor, req) = root_power(view, &a, &ctx.actor)?;
    if !matches!(anchor.scope, AnchorScope::Party(_)) {
        return Err(MetaError::Basis);
    }
    Ok(Some(req))
}

/// Whether every statement of a policy's source is a `forbid` (OP-157 m.3 (b)).
fn forbid_only(content: &Value) -> bool {
    match content.get("source") {
        Some(Value::Text(source)) => statements(source).iter().all(|s| is_forbid(s)),
        _ => false,
    }
}

/// Root power over the meta-anchor, as the only basis of a domain-scope meta-action: any other
/// Anchor, a holding or a `For` capacity cannot change the provider binding (§9.13.7, PI-15).
fn domain_scope(
    ctx: &Context<'_>,
    view: &dyn View,
) -> Result<BTreeSet<RequirementTerm>, MetaError> {
    if ctx.capacity != Capacity::Own {
        return Err(MetaError::Basis);
    }
    domain_root(ctx, view)
}

fn recovery_entry(view: &dyn View) -> Result<crate::recovery::RecoveryEntry, MetaError> {
    let v = view
        .get(&crate::recovery::entry_key())
        .ok_or(MetaError::NotAuthorized)?;
    crate::recovery::RecoveryEntry::from_value(&v).map_err(|_| MetaError::Corrupt)
}

/// The rollback guard over the witness `checkpoint` Claims a recovery names, read from the
/// state, with its declared lost suffix and fork checked against the guard (SEC21, SEC22).
fn recover_guard(
    ctx: &Context<'_>,
    view: &dyn View,
    r: &crate::recovery::RecoverInput,
) -> Result<crate::fold::Guard, MetaError> {
    if r.cited_checkpoint.size != r.n || r.witness_claims.is_empty() {
        return Err(MetaError::NotWithin);
    }
    let mut heads = Vec::new();
    for id in &r.witness_claims {
        let c: crate::claim::ClaimState = read(view, kind::CLAIM, id)?;
        let head = view.get(&crate::recovery::witness_head_key(id));
        heads.push(crate::recovery::witness_head(&c, head.as_ref(), ctx.now));
    }
    let guard = crate::fold::rollback_guard(
        &heads,
        r.replica_head.map(|h| h.size),
        (r.n, r.cited_checkpoint.root.0),
        !r.fork.is_empty(),
        ctx.now,
    )
    .map_err(|e| match e {
        crate::fold::GuardError::Rollback => MetaError::RollbackGuard,
        _ => MetaError::NotWithin,
    })?;
    let declared = r.lost_suffix.map(|s| (s.from, s.to));
    let expected = match guard {
        crate::fold::Guard::Lossy { from, until } if from < until => Some((from, until)),
        _ => None,
    };
    if declared != expected {
        return Err(MetaError::NotWithin);
    }
    Ok(guard)
}

/// Writes the new provider binding and marks the old one superseded at the cited checkpoint
/// (§9.15, PI-15): the binding is the domain's one value, written only here.
fn rebind(
    view: &dyn View,
    out: &mut Outcome,
    ctx: &Context<'_>,
    binding: &BTreeMap<[u8; 32], crate::verify::key_scope::BindingKey>,
    cited: &crate::recovery::CheckpointRef,
    how: &str,
) -> Result<(), MetaError> {
    if binding.values().any(|b| b.superseded.is_some()) {
        return Err(MetaError::NotWithin);
    }
    let k = crate::recovery::binding_key();
    if let Some(old) = view.get(&k) {
        for kid in crate::recovery::binding_kids(&old).map_err(|_| MetaError::Corrupt)? {
            if !binding.contains_key(&kid) {
                out.effects.push((
                    crate::recovery::superseded_key(&kid),
                    Some(map([
                        ("cited", Some(cited.to_value())),
                        ("pos", Some(Value::Unsigned(ctx.pos))),
                    ])),
                ));
            }
        }
    }
    out.effects.push((
        k,
        Some(crate::recovery::binding_value(binding, cited, how, ctx.pos)),
    ));
    Ok(())
}

fn domain_root(ctx: &Context<'_>, view: &dyn View) -> Result<BTreeSet<RequirementTerm>, MetaError> {
    let meta = meta_anchor(&ctx.domain);
    if anchor_of_basis(ctx)? != meta {
        return Err(MetaError::Basis);
    }
    root_power(view, &meta, &ctx.actor).map(|(_, r)| r)
}

#[cfg(test)]
mod tests;
