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
    AuthoritySet, CanonicalAuthority, ConstraintSet, EqValue, Id, RequirementTerm,
    ResourceSelector, SubjectSelector, Window,
};
use crate::verify::cose::PublicKey;
use suiss_crypto::digest::context_digest as context_label;

/// Namespace of the core meta-actions.
pub const NAMESPACE: &str = "access";

/// Longest lineage walked (OP-108 m.10).
pub const MAX_LINEAGE: usize = 16;

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
    pub named: Option<(String, u64, Digest)>,
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
}

/// What happens to a dependent Grant (C10, E6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// It stays.
    Keep,
    /// It is revoked.
    Revoke,
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
    },
    /// `contribute` (L0-META-30).
    Contribute {
        /// Digest of the intent contributed to.
        target: Digest,
        /// Contribution class.
        class: String,
    },
}

const NAMES: [&str; 24] = [
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
];

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
        }
    }
}

impl From<ModelError> for MetaError {
    fn from(e: ModelError) -> Self {
        Self::Malformed(e)
    }
}

// ---------------------------------------------------------------- encoding

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
            (
                "named",
                self.named.as_ref().map(|(n, v, d)| {
                    map([
                        ("name", Some(Value::text(n))),
                        ("version", Some(Value::Unsigned(*v))),
                        ("digest", Some(d.to_value())),
                    ])
                }),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let named = match f.opt("named") {
            None => None,
            Some(n) => {
                let mut g = Fields::of(n)?;
                let out = (
                    crate::codec::ident(g.req("name")?)?,
                    uint(g.req("version")?)?,
                    Digest::from_value(g.req("digest")?).ok_or(ModelError::Shape)?,
                );
                g.done()?;
                Some(out)
            }
        };
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
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let m = Self {
            authority: AuthoritySet::from_value(f.req("authority")?)?,
            constraints: ConstraintSet::from_value(f.req("constraints")?)?,
            requirements: requirements(f.opt("requirements"))?,
            pin: f.opt("pin").map(holding).transpose()?,
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
            } => (
                "anchor_create",
                map([
                    ("scope", Some(scope_value(scope))),
                    ("root", Some(root_value(root))),
                    ("root_terms", requirements_value(root_terms)),
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
            Self::PartyRegister { party, root } => (
                "party_register",
                map([
                    ("party", Some(party.to_value())),
                    ("root", Some(root_value(root))),
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
            } => (
                "grant_amend",
                map([
                    ("grant", Some(grant.to_value())),
                    ("authority", Some(authority.to_value())),
                    ("agency", agency_value(agency)),
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
            Self::PolicySet { policy, content } => (
                "policy_set",
                map([
                    ("policy", policy.as_ref().map(Canonical::to_value)),
                    ("content", Some(content.clone())),
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
            } => (
                "claim_issue",
                map([
                    ("subject", Some(subject.to_value())),
                    ("class", Some(Value::text(class))),
                    ("value", Some(value.to_value())),
                    ("validity", validity.as_ref().map(Canonical::to_value)),
                ]),
            ),
            Self::Contribute { target, class } => (
                "contribute",
                map([
                    ("target", Some(target.to_value())),
                    ("class", Some(Value::text(class))),
                ]),
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
        let mut f = Fields::of(body)?;
        let p = match name {
            "anchor_create" => Self::AnchorCreate {
                scope: scope(f.req("scope")?)?,
                root: root(f.req("root")?)?,
                root_terms: requirements(f.opt("root_terms"))?,
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
            },
            "anchor_retire" => Self::AnchorRetire {
                anchor: id(f.req("anchor")?)?,
                disposition: disposition(f.req("disposition")?)?,
            },
            "party_register" => Self::PartyRegister {
                party: id(f.req("party")?)?,
                root: root(f.req("root")?)?,
            },
            "party_depart" => Self::PartyDepart {
                party: id(f.req("party")?)?,
                disposition: disposition(f.req("disposition")?)?,
            },
            "instance_create" => Self::InstanceCreate {
                party: id(f.req("party")?)?,
                key: PublicKey::from_value(f.req("key")?)?,
                mandate: f
                    .opt("mandate")
                    .map(MandateEnvelope::from_value)
                    .transpose()?,
            },
            "instance_rekey" => Self::InstanceRekey {
                instance: id(f.req("instance")?)?,
                key: PublicKey::from_value(f.req("key")?)?,
            },
            "instance_terminate" => Self::InstanceTerminate {
                instance: id(f.req("instance")?)?,
            },
            "instance_recover" => Self::InstanceRecover {
                instance: id(f.req("instance")?)?,
                key: PublicKey::from_value(f.req("key")?)?,
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
            },
            "policy_retire" => Self::PolicyRetire {
                policy: id(f.req("policy")?)?,
            },
            "claim_issue" => Self::ClaimIssue {
                subject: id(f.req("subject")?)?,
                class: crate::codec::ident(f.req("class")?)?,
                value: EqValue::from_value(f.req("value")?)?,
                validity: f.opt("validity").map(Window::from_value).transpose()?,
            },
            "contribute" => Self::Contribute {
                target: Digest::from_value(f.req("target")?).ok_or(ModelError::Shape)?,
                class: crate::codec::ident(f.req("class")?)?,
            },
            _ => return Err(ModelError::Unknown),
        };
        f.done()?;
        Ok(p)
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
    match f.req("issuer")? {
        Value::Bytes(_) => {
            f.opt("issuer");
        }
        other => {
            let (k, _) = single(other)?;
            if k != "keys" {
                return Err(ModelError::Unknown);
            }
        }
    }
    match f.req("use")? {
        Value::Text(u) if USES.contains(&u.as_str()) => {}
        _ => return Err(ModelError::Unknown),
    }
    set_of(f.req("classes")?, true, crate::codec::ident)?;
    SubjectSelector::from_value(f.req("subject")?)?;
    f.opt("anchor").map(id).transpose()?;
    crate::codec::assurance(f.opt("assurance_floor"))?;
    Window::from_value(f.req("validity")?)?;
    f.opt("ingest_until").map(uint).transpose()?;
    f.done()?;
    Ok(v.clone())
}

fn policy_content(v: &Value) -> Result<Value, ModelError> {
    let mut f = Fields::of(v)?;
    crate::codec::text(f.req("schema")?)?;
    crate::codec::text(f.req("source")?)?;
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

// ---------------------------------------------------------------- identifiers and keys

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
    /// The Grants whose basis is an Anchor or a Grant.
    pub const CHILDREN: &str = "children";
    /// The Instances of a Party.
    pub const INSTANCES: &str = "instances";
    /// The Mandates of an Instance.
    pub const MANDATES: &str = "mandates";
}

/// Read access to the authority state at the evaluation position; the caller records every key
/// it serves in the read set (TI-4).
pub trait View {
    /// The value of `key`, if present.
    fn get(&self, key: &[u8]) -> Option<Value>;
}

// ---------------------------------------------------------------- stored objects

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

/// A Party's admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyState {
    /// Its self-anchor.
    pub anchor: Id,
    /// Admitting position.
    pub since: u64,
    /// Departure.
    pub ended: Option<Ended>,
}

impl Canonical for PartyState {
    fn to_value(&self) -> Value {
        map([
            ("anchor", Some(self.anchor.to_value())),
            ("since", Some(Value::Unsigned(self.since))),
            ("ended", self.ended.as_ref().map(ended_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let s = Self {
            anchor: id(f.req("anchor")?)?,
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
            key: PublicKey::from_value(f.req("key")?)?,
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
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let s = Self {
            target: Digest::from_value(f.req("target")?).ok_or(ModelError::Shape)?,
            class: crate::codec::ident(f.req("class")?)?,
            party: id(f.req("party")?)?,
            instance: id(f.req("instance")?)?,
            since: uint(f.req("since")?)?,
            consumed: f.opt("consumed").map(uint).transpose()?,
        };
        f.done()?;
        Ok(s)
    }
}

/// An allowed Exercise (`exercise-state`): what a continuation is checked against (L1-ADP-13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExerciseState {
    /// Intent digest.
    pub intent: Digest,
    /// Actor Instance.
    pub actor: Id,
    /// Position of the allowing decision.
    pub since: u64,
}

impl Canonical for ExerciseState {
    fn to_value(&self) -> Value {
        map([
            ("intent", Some(self.intent.to_value())),
            ("actor", Some(self.actor.to_value())),
            ("since", Some(Value::Unsigned(self.since))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let s = Self {
            intent: Digest::from_value(f.req("intent")?).ok_or(ModelError::Shape)?,
            actor: id(f.req("actor")?)?,
            since: uint(f.req("since")?)?,
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
    /// End.
    pub ended: Option<Ended>,
}

impl Canonical for ContentState {
    fn to_value(&self) -> Value {
        map([
            ("content", Some(self.content.clone())),
            ("since", Some(Value::Unsigned(self.since))),
            ("ended", self.ended.as_ref().map(ended_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let s = Self {
            content: f.req("content")?.clone(),
            since: uint(f.req("since")?)?,
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

// ---------------------------------------------------------------- genesis

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
    f.done()?;
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
    for (seq, (scope, root, root_terms)) in (0_u64..).zip(anchors) {
        let a = object_id(domain, kind::ANCHOR, seq);
        out.push((
            key(kind::ANCHOR, &a),
            Some(
                AnchorState {
                    scope,
                    root,
                    root_terms,
                    since: 0,
                    ended: None,
                }
                .to_value(),
            ),
        ));
    }
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
    let _ = take("reserved");
    let _ = take("versions");
    if known != fields.len() {
        return Err(MetaError::Malformed(ModelError::Unknown));
    }
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
                    ended: None,
                }
                .to_value(),
            ),
        ));
    }
    for (issuer, set) in by_issuer {
        out.push((key(kind::ACCEPTANCES, &issuer), Some(ids_value(&set))));
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
    Ok(out)
}

/// The meta-anchor of a domain.
#[must_use]
pub fn meta_anchor(domain: &Digest) -> Id {
    object_id(domain, kind::ANCHOR, 0)
}

// ---------------------------------------------------------------- powers

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
}

const CO_ROOT: &str = "co_root";

/// The requirements of acting as `anchor`'s root: its root terms and, for a joint root of `k`,
/// `k − 1` further `co_root` contributions (L0-META-10); `None` when the actor is not a root.
#[must_use]
pub fn root_requirements(anchor: &AnchorState, actor: &Actor) -> Option<BTreeSet<RequirementTerm>> {
    let mut req = anchor.root_terms.clone();
    match &anchor.root {
        Root::Sole(p) if *p == actor.party => {}
        Root::Joint { parties, k } if parties.contains(&actor.party) => {
            if *k > 1 {
                req.insert(RequirementTerm {
                    proof_kind: crate::model::ProofKind::Contribution,
                    class: String::from(CO_ROOT),
                    count: k.saturating_sub(1),
                    binding: crate::model::Binding::IntentDigest,
                    freshness_ms: None,
                    independence: crate::model::Independence::DistinctParty,
                    consumption: crate::model::Consumption::SingleUse,
                    source: None,
                    assurance: BTreeMap::new(),
                });
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
    let mut out = Outcome::default();
    let actor = ctx.actor;
    match payload {
        Payload::AnchorCreate {
            scope: s,
            root: r,
            root_terms,
        } => {
            let covering = anchor_of_basis(ctx)?;
            let (a, req) = root_power(view, &covering, &actor)?;
            let inner = scope_selector(s);
            if matches!(s, AnchorScope::Domain)
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
            if anchor_of_basis(ctx)? != *anchor {
                return Err(MetaError::Basis);
            }
            let (mut a, req) = root_power(view, anchor, &actor)?;
            dispose(view, &mut out, anchor, disposition, ctx.pos, true)?;
            a.root = r.clone();
            out.requirements = req;
            out.expansion = true;
            set(&mut out, kind::ANCHOR, anchor, a.to_value());
        }
        Payload::AnchorAmend {
            anchor,
            root: r,
            root_terms,
        } => {
            if anchor_of_basis(ctx)? != *anchor {
                return Err(MetaError::Basis);
            }
            let (mut a, req) = root_power(view, anchor, &actor)?;
            if let Some(r) = r {
                a.root = r.clone();
            }
            if let Some(t) = root_terms {
                out.expansion = !t.is_superset(&a.root_terms);
                a.root_terms.clone_from(t);
            }
            out.expansion |= r.is_some();
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
        Payload::PartyRegister { party, root: r } => {
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
            out.expansion = !subsumes(&envelope.authority, &m.envelope.authority, ctx.catalog);
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
            if let Some(issuer @ Value::Bytes(_)) = content.get("issuer") {
                let issuer = id(issuer).map_err(|_| MetaError::Corrupt)?;
                let mut set_of = ids(view, kind::ACCEPTANCES, &issuer)?;
                set_of.insert(aid);
                set(&mut out, kind::ACCEPTANCES, &issuer, ids_value(&set_of));
            }
            select(view, &mut out, content, aid, None)?;
            set(
                &mut out,
                kind::ACCEPTANCE,
                &aid,
                ContentState {
                    content: content.clone(),
                    since: ctx.pos,
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
            let fixed = |c: &Value| (c.get("issuer").cloned(), c.get("use").cloned());
            if fixed(&a.content) != fixed(content) {
                return Err(MetaError::NotWithin);
            }
            select(view, &mut out, content, *acceptance, Some(&a.content))?;
            a.content = content.clone();
            a.since = ctx.pos;
            out.expansion = true;
            set(&mut out, kind::ACCEPTANCE, acceptance, a.to_value());
        }
        Payload::AcceptanceRevoke { acceptance } => {
            out.requirements = domain_root(ctx, view)?;
            let mut a: ContentState = read(view, kind::ACCEPTANCE, acceptance)?;
            a = live(a.ended, a.clone())?;
            a.ended = Some(end(ctx.pos, EndedHow::Revoked));
            set(&mut out, kind::ACCEPTANCE, acceptance, a.to_value());
        }
        Payload::PolicySet { policy, content } => {
            out.requirements = domain_root(ctx, view)?;
            let id = match policy {
                Some(p) => {
                    let s: ContentState = read(view, kind::POLICY, p)?;
                    live(s.ended, ())?;
                    *p
                }
                None => new_id(ctx, kind::POLICY, 0),
            };
            out.expansion = policy.is_some();
            set(
                &mut out,
                kind::POLICY,
                &id,
                ContentState {
                    content: content.clone(),
                    since: ctx.pos,
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
        } => {
            out.requirements = domain_root(ctx, view)?;
            set(
                &mut out,
                kind::CLAIM,
                &new_id(ctx, kind::CLAIM, 0),
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
                        bound_intent: None,
                        bound_instance: None,
                        bound_resource: None,
                        supersedes: None,
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
                    }
                    .to_value(),
                ),
            ));
            out.expansion = true;
        }
    }
    Ok(out)
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
    for class in classes_of(content).difference(&known) {
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

fn domain_root(ctx: &Context<'_>, view: &dyn View) -> Result<BTreeSet<RequirementTerm>, MetaError> {
    let meta = meta_anchor(&ctx.domain);
    if anchor_of_basis(ctx)? != meta {
        return Err(MetaError::Basis);
    }
    root_power(view, &meta, &ctx.actor).map(|(_, r)| r)
}

#[cfg(test)]
mod tests;
