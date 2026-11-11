//! The legal-process Grant (CI-13, §6.1, §7.9.12.7, OP-157 m.3 (i)).
//!
//! A court order is a `court_order` Claim (CDDL `product-seam.cddl`); it never acts by itself.
//! What it unlocks is a Grant the domain wrote before: held by the legal-ops Party, naming its
//! reserved actions one by one, passing on to no one, held only while that Party holds a current
//! `court_order` Claim the named Acceptance admits, and asking for at least two approvals from
//! distinct Parties bound to each use.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::meta::{GrantBasis, GrantContent};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, Binding, CanonicalAuthority, ConstraintSet, Consumption,
    DelegationTerms, Id, Independence, ProofKind, PurposeRef, RequirementTerm, ResourceSelector,
    SubjectSelector, WhileCondition, Window,
};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

/// The purpose a legal-process Grant and each of its uses carry.
pub const PURPOSE: &str = "legal_process";

/// The Claim class of a court order.
pub const COURT_ORDER: &str = "court_order";

/// The contribution class of a legal-process approval.
pub const APPROVAL: &str = "legal_process";

/// Fewest approvals from distinct Parties a use needs (CI-13, PD).
pub const MIN_APPROVALS: u64 = 2;

/// Why a legal-process setup is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// No action named, a prefix, fewer than two approvals, or an order that is not a jurisdiction.
    #[error("a legal-process Grant names its actions and asks for two approvals")]
    Shape,
}

impl Refusal {
    /// The problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        "legal-process-grant"
    }
}

/// What a legal-process setup installs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setup {
    /// Where the Grant derives from.
    pub basis: GrantBasis,
    /// The legal-ops Party that holds it and that court orders are served to.
    pub holder: Id,
    /// The reserved actions, named one by one.
    pub actions: BTreeSet<ActionRef>,
    /// What they cover.
    pub resource: ResourceSelector,
    /// How long the Grant stands.
    pub validity: Window,
    /// How many approvals a use needs.
    pub approvals: u64,
    /// Who may approve; `None` for anyone the domain accepts.
    pub approvers: Option<SubjectSelector>,
    /// The digest of the `predicate-input` Acceptance that admits the court's Claims.
    pub acceptance: Digest,
}

/// The purposes a legal-process Grant covers.
#[must_use]
pub fn purposes() -> BTreeSet<PurposeRef> {
    BTreeSet::from([PurposeRef::Code(String::from(PURPOSE))])
}

/// The approval term: `approvals` contributions from distinct Parties, each bound to the use and
/// used once.
#[must_use]
pub fn approval_term(approvals: u64, approvers: Option<SubjectSelector>) -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Contribution,
        class: String::from(APPROVAL),
        count: approvals,
        binding: Binding::IntentDigest,
        freshness_ms: None,
        independence: Independence::DistinctParty,
        consumption: Consumption::SingleUse,
        source: approvers,
        assurance: BTreeMap::new(),
    }
}

/// The condition that holds the Grant: `holder` holds a current `court_order` Claim that
/// `acceptance` admits.
#[must_use]
pub fn condition(holder: Id, acceptance: Digest) -> WhileCondition {
    WhileCondition::ClaimHeld {
        class: String::from(COURT_ORDER),
        subject: SubjectSelector::Party(holder),
        acceptance,
    }
}

impl Setup {
    /// The Grant of the setup.
    ///
    /// # Errors
    /// [`Refusal::Shape`] without a named action or with fewer than two approvals.
    pub fn grant(&self) -> Result<GrantContent, Refusal> {
        if self.actions.is_empty() || self.approvals < MIN_APPROVALS {
            return Err(Refusal::Shape);
        }
        Ok(GrantContent {
            basis: self.basis,
            holder: SubjectSelector::Party(self.holder),
            authority: CanonicalAuthority {
                authority: AuthoritySet {
                    actions: ActionSet {
                        exact: self.actions.clone(),
                        prefix: BTreeSet::new(),
                    },
                    resource: self.resource.clone(),
                    params: BTreeMap::new(),
                    recipient: None,
                    purpose: Some(purposes()),
                },
                constraints: ConstraintSet {
                    validity: self.validity,
                    conditions: BTreeSet::from([condition(self.holder, self.acceptance)]),
                    budget: BTreeSet::new(),
                },
                delegation: DelegationTerms::default(),
                requirements: BTreeSet::from([approval_term(
                    self.approvals,
                    self.approvers.clone(),
                )]),
            },
            agency: BTreeSet::from([Capacity::Own]),
            named: None,
        })
    }
}

/// Whether `a` claims to be a legal-process authority: it carries the `legal_process` purpose or
/// a `court_order` condition.
#[must_use]
pub fn is_legal(a: &CanonicalAuthority) -> bool {
    a.authority
        .purpose
        .as_ref()
        .is_some_and(|p| p.contains(&PurposeRef::Code(String::from(PURPOSE))))
        || a.constraints
            .conditions
            .iter()
            .any(|c| matches!(c, WhileCondition::ClaimHeld { class, .. } if class == COURT_ORDER))
}

/// Whether a Grant with `content` has the legal-process shape (CI-13).
#[must_use]
pub fn well_formed(content: &GrantContent) -> bool {
    let SubjectSelector::Party(holder) = content.holder else {
        return false;
    };
    well_formed_authority(&content.authority, Some(holder))
}

/// The authority half of [`well_formed`]; `holder` is `None` for an amendment, which keeps it.
#[must_use]
pub fn well_formed_authority(a: &CanonicalAuthority, holder: Option<Id>) -> bool {
    let mut orders = a.constraints.conditions.iter().filter_map(|c| match c {
        WhileCondition::ClaimHeld { class, subject, .. } if class == COURT_ORDER => Some(subject),
        _ => None,
    });
    let served = match (orders.next(), orders.next()) {
        (Some(SubjectSelector::Party(p)), None) => holder.is_none_or(|h| h == *p),
        _ => false,
    };
    served
        && a.authority.purpose.as_ref() == Some(&purposes())
        && !a.authority.actions.exact.is_empty()
        && a.authority.actions.prefix.is_empty()
        && a.delegation.depth == 0
        && a.requirements.iter().any(|t| {
            t.proof_kind == ProofKind::Contribution
                && t.count >= MIN_APPROVALS
                && t.independence == Independence::DistinctParty
                && t.binding == Binding::IntentDigest
        })
}

/// Whether a meta-action payload may stand as far as legal process goes: a Grant it issues or
/// amends that claims to be a legal-process authority has the legal-process shape (CI-13).
#[must_use]
pub fn admissible(payload: &access_kernel::meta::Payload) -> bool {
    use access_kernel::meta::Payload;
    match payload {
        Payload::GrantIssue(g) => !is_legal(&g.authority) || well_formed(g),
        Payload::GrantAmend { authority, .. } => {
            !is_legal(authority) || well_formed_authority(authority, None)
        }
        _ => true,
    }
}

/// The `court-order` body (CDDL `product-seam.cddl`): `order` is the digest of the order's
/// reference, `scope` the actions it names, `until` when it ends (Unix ms).
#[must_use]
pub fn body(order: &Digest, jurisdiction: &str, scope: &BTreeSet<String>, until: u64) -> Value {
    Value::Map(vec![
        (Value::text("order"), Value::Bytes(order.0.to_vec())),
        (
            Value::text("scope"),
            Value::Array(scope.iter().map(|s| Value::text(s)).collect()),
        ),
        (Value::text("until"), Value::Unsigned(until)),
        (Value::text("jurisdiction"), Value::text(jurisdiction)),
    ])
}

/// The `value` of a `court_order` Claim with `body` (L2-CLB-1).
#[must_use]
pub fn value_digest(body: &Value) -> [u8; 32] {
    let bytes = dcbor::encode(
        &Value::Array(vec![Value::text(COURT_ORDER), body.clone()]),
        Limits::CEILING,
    )
    .unwrap_or_default();
    context_digest(access_kernel::claim::body::BODY_CONTEXT, &bytes).0
}

#[cfg(test)]
mod tests;
