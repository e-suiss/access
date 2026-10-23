//! Kernel data model (`conformance/cddl/kernel.cddl`, OP-107, OP-109).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::digest::Digest;

/// Milliseconds since the Unix epoch (OP-106 m.16).
pub type TrustedTime = u64;

/// Opaque 16-byte identifier (OP-109 m.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id(pub [u8; 16]);

/// Closed time window `[from, until]` (OP-107 m.12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Window {
    /// First instant inside the window.
    pub from: TrustedTime,
    /// Last instant inside the window.
    pub until: TrustedTime,
}

/// Action identity: namespace, name and major version; the schema digest is a consistency check (OP-107 m.1).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionRef {
    /// Dotted namespace.
    pub namespace: String,
    /// Action name.
    pub name: String,
    /// Major schema version.
    pub major: u64,
    /// Digest of the pinned action schema.
    pub schema: Digest,
}

/// Resource reference (§5.3).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceRef {
    /// Owning namespace.
    pub namespace: String,
    /// Path segments.
    pub path: Vec<String>,
    /// Incarnation of the resource id.
    pub incarnation: u64,
}

/// Purpose reference: a typed code or an opaque reference (§5.3).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PurposeRef {
    /// Schema-declared purpose code.
    Code(String),
    /// Opaque `WorkRef`.
    Work(Digest),
    /// Opaque `AimRef`.
    Aim(Digest),
}

/// Value compared by equality only.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EqValue {
    /// Text.
    Text(String),
    /// Bytes.
    Bytes(Vec<u8>),
    /// Integer.
    Int(i64),
    /// Boolean.
    Bool(bool),
}

/// Structural resource selector (OP-109 m.2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Structural {
    /// Namespace; must match exactly.
    pub namespace: String,
    /// Path prefix, matched at segment boundaries; empty covers the namespace.
    pub prefix: Vec<String>,
    /// Resource type, if constrained.
    pub kind: Option<String>,
    /// Attribute equalities, all required.
    pub attrs: BTreeMap<String, EqValue>,
}

/// Resource selector (OP-109 m.2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceSelector {
    /// One resource.
    Exact(ResourceRef),
    /// Prefix, type and attribute constraints.
    Structural(Structural),
}

/// One conjunct of an intensional selector (OP-109 m.1).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Conjunct {
    /// Claim class with a subject-selection Acceptance.
    pub claim_class: String,
    /// Required claim value, if any.
    pub value: Option<EqValue>,
}

/// Subject selector (§5.3, OP-107 m.14).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SubjectSelector {
    /// One party.
    Party(Id),
    /// Conjunction of claim conditions; never empty.
    Pred(BTreeSet<Conjunct>),
    /// Everyone.
    Public,
    /// Holders of an authority class in a foreign domain.
    Foreign {
        /// Foreign domain.
        domain: Digest,
        /// Authority class there.
        class: String,
    },
}

/// A parameter bound of one of the nine closed types (§7.9.3.4).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bound {
    /// Membership in a finite set; never empty.
    Enum(BTreeSet<String>),
    /// Equality.
    Eq(EqValue),
    /// Closed integer range with a unit; a missing end is unbounded.
    Range {
        /// Lower end.
        min: Option<i64>,
        /// Upper end.
        max: Option<i64>,
        /// Unit; ranges with different units never compare.
        unit: String,
    },
    /// Upper bound on a count.
    CountMax(u64),
    /// The value's interval must lie inside this window.
    Interval(Window),
    /// Resource selector.
    Resource(ResourceSelector),
    /// Subject selector.
    Subject(SubjectSelector),
    /// Purpose set; never empty.
    Purpose(BTreeSet<PurposeRef>),
    /// Boolean equality.
    Flag(bool),
}

/// Action set: exact actions and catalog-pinned namespace prefixes (OP-107 m.2).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionSet {
    /// Named actions.
    pub exact: BTreeSet<ActionRef>,
    /// Namespace prefixes with the catalog version they resolve against.
    pub prefix: BTreeSet<(String, Digest)>,
}

/// What a grant covers (§5.3, §5.8 A).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthoritySet {
    /// Actions.
    pub actions: ActionSet,
    /// Resources.
    pub resource: ResourceSelector,
    /// Typed parameter bounds; a parameter not listed is unconstrained.
    pub params: BTreeMap<String, Bound>,
    /// Recipient; `None` is unconstrained.
    pub recipient: Option<SubjectSelector>,
    /// Purposes; `None` is unconstrained.
    pub purpose: Option<BTreeSet<PurposeRef>>,
}

/// While-condition (OP-107 m.6).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WhileCondition {
    /// While the instance is alive.
    InstanceAlive(Id),
    /// While a claim of the class is held.
    ClaimHeld {
        /// Claim class.
        class: String,
        /// Whose claim.
        subject: SubjectSelector,
        /// Acceptance the claim relies on.
        acceptance: Digest,
    },
}

/// Budget dimension.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BudgetDimension {
    /// Number of exercises.
    Count,
    /// Amount in the given unit.
    Amount(String),
}

/// Budget window (OP-107 m.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BudgetWindow {
    /// Lifetime of the grant.
    Total,
    /// Sliding window of the given seconds.
    RollingSeconds(u64),
}

/// Budget term (§5.3).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BudgetTerm {
    /// What is counted.
    pub dimension: BudgetDimension,
    /// Capacity per window.
    pub capacity: u64,
    /// Window.
    pub window: BudgetWindow,
}

/// Constraint set (OP-107 m.5).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConstraintSet {
    /// Validity window.
    pub validity: Window,
    /// While-conditions, all required.
    pub conditions: BTreeSet<WhileCondition>,
    /// Budget terms.
    pub budget: BTreeSet<BudgetTerm>,
}

/// Delegation terms; a missing depth is 0 (OP-107 m.16, OP-109 m.4).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DelegationTerms {
    /// Remaining delegation depth.
    pub depth: u64,
    /// Who may hold a delegated grant.
    pub downstream_holder_class: Option<SubjectSelector>,
}

/// Proof kind of a requirement term (OP-109 m.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProofKind {
    /// Claim.
    Claim,
    /// Contribution exercise.
    Contribution,
    /// Authentication assertion.
    Authentication,
    /// Foreign authority proof.
    ForeignAuthority,
}

/// Binding of a requirement term (OP-109 m.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Binding {
    /// Not bound.
    None,
    /// Bound to the actor instance.
    ActorInstance,
    /// Bound to the intent digest.
    IntentDigest,
    /// Bound to the resource.
    Resource,
}

/// Independence of a requirement term (OP-109 m.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Independence {
    /// No independence.
    None,
    /// Distinct parties.
    DistinctParty,
    /// Distinct instances.
    DistinctInstance,
    /// Distinct issuers.
    DistinctIssuer,
}

/// Consumption of a requirement term (OP-109 m.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Consumption {
    /// Proof may be reused.
    Reusable,
    /// Proof is consumed once.
    SingleUse,
}

/// Requirement term (§5.3, §9.6, OP-109 m.3).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequirementTerm {
    /// Proof kind.
    pub proof_kind: ProofKind,
    /// Class within the kind.
    pub class: String,
    /// Number of proofs; 1 when not written.
    pub count: u64,
    /// Binding.
    pub binding: Binding,
    /// Maximum proof age in milliseconds.
    pub freshness_ms: Option<u64>,
    /// Independence.
    pub independence: Independence,
    /// Consumption.
    pub consumption: Consumption,
    /// Accepted sources.
    pub source: Option<SubjectSelector>,
    /// Assurance floors, ordered integers per dimension (OP-107 m.21).
    pub assurance: BTreeMap<String, u64>,
}

/// Canonical authority (§5.8).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalAuthority {
    /// What.
    pub authority: AuthoritySet,
    /// When and how much.
    pub constraints: ConstraintSet,
    /// To whom it may pass.
    pub delegation: DelegationTerms,
    /// What must be presented.
    pub requirements: BTreeSet<RequirementTerm>,
}
