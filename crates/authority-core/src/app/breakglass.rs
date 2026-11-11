//! Break-glass at the authority level (INV-28, SI-22, G29, TN-93, §12.3.8, OP-157 m.3 (h)).
//!
//! Break-glass is a pre-issued Grant that names its reserved actions, carries the
//! `break_glass` purpose and asks for at least two approvals from distinct Parties. No flag,
//! account or operator path stands in for it: the `is_breakglass` membership flag only changes
//! how the account signs in, and grants nothing (Ek B 5653).
//!
//! A use of such a Grant skips the CT3 time-lock and carries its own limits instead: an intent
//! of at most [`USE_MAX_MS`], approvals no older than that, the subject's notice written in the
//! same commit, and a review by another Party within [`REVIEW_WITHIN_H`] hours.

use std::collections::BTreeSet;

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::meta::{self, ExerciseBasis, GrantBasis, GrantContent, GrantState, kind};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, Binding, CanonicalAuthority, ConstraintSet, Consumption,
    DelegationTerms, Id, Independence, ProofKind, PurposeRef, RequirementTerm, ResourceSelector,
    SubjectSelector, Window,
};
use suiss_crypto::dcbor::Value;

use crate::CoreError;
use crate::app::Authority;
use crate::domain::Request;
use crate::ports::{Binding as BindingPort, Reader, Salts};
use access_authority_sequencer::ports::DomainLog;

/// The purpose a break-glass Grant and each of its emergency uses carry (§12.3.8).
pub const PURPOSE: &str = "break_glass";

/// The purpose a drill carries: a real use of the Grant, classified as a drill (§12.3.8 (5)).
pub const DRILL: &str = "drill";

/// The contribution class of a break-glass approval.
pub const APPROVAL: &str = "breakglass";

/// Fewest break-glass Grants a setup installs, each on its own Party (§12.3.8 (1)).
pub const MIN_GRANTS: usize = 2;

/// Fewest approvals from distinct Parties a use needs (TN-93).
pub const MIN_APPROVALS: u64 = 2;

/// Longest a use's intent and its approvals stay valid, ms (PD, 4 hours).
pub const USE_MAX_MS: u64 = 4 * 3_600_000;

/// Hours within which another Party reviews a use (PD, `breakglass_review_h`).
pub const REVIEW_WITHIN_H: u64 = 72;

/// Longest gap between two drills, ms (PD, 90 days).
pub const DRILL_EVERY_MS: u64 = 90 * 86_400_000;

/// Why a break-glass setup is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// Fewer than two holders, or fewer than two approvals (§12.3.8 (1), TN-93).
    #[error("break-glass needs at least two Grants and two approvals")]
    MinimumTwo,
    /// No reserved action named, a prefix, or an action outside the realm's catalog.
    #[error("break-glass Grants name their reserved actions")]
    Actions,
}

impl Refusal {
    /// The problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MinimumTwo => "breakglass-minimum-two",
            Self::Actions => "invalid-request",
        }
    }
}

/// The classification a review gives a use (§12.3.8 (4)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Classification {
    /// A planned drill.
    Drill,
    /// A real emergency.
    Emergency,
    /// A use that should not have happened.
    Misuse,
}

impl Classification {
    /// Every classification.
    pub const ALL: [Self; 3] = [Self::Drill, Self::Emergency, Self::Misuse];

    /// Its wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Drill => "drill",
            Self::Emergency => "emergency",
            Self::Misuse => "misuse",
        }
    }

    /// The classification named `s`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == s)
    }
}

/// The purposes a break-glass Grant covers.
#[must_use]
pub fn purposes() -> BTreeSet<PurposeRef> {
    BTreeSet::from([
        PurposeRef::Code(String::from(PURPOSE)),
        PurposeRef::Code(String::from(DRILL)),
    ])
}

/// Whether `a` is a break-glass authority: `break_glass` among its purposes and nothing beyond
/// `break_glass` and `drill`.
#[must_use]
pub fn is_breakglass(a: &AuthoritySet) -> bool {
    let all = purposes();
    a.purpose
        .as_ref()
        .is_some_and(|p| p.contains(&PurposeRef::Code(String::from(PURPOSE))) && p.is_subset(&all))
}

/// The approval term a break-glass Grant carries: `approvals` contributions from distinct
/// Parties, each at most [`USE_MAX_MS`] old (TN-93, Joint(k)).
#[must_use]
pub fn approval_term(approvals: u64, approvers: Option<SubjectSelector>) -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Contribution,
        class: String::from(APPROVAL),
        count: approvals,
        binding: Binding::None,
        freshness_ms: Some(USE_MAX_MS),
        independence: Independence::DistinctParty,
        consumption: Consumption::Reusable,
        source: approvers,
        assurance: std::collections::BTreeMap::new(),
    }
}

/// Whether a Grant with `content` has the break-glass shape: one Party holds it, it names its
/// actions one by one and passes on to no one, and it asks for at least two fresh approvals
/// from distinct Parties (G29, TN-93).
#[must_use]
pub fn well_formed(content: &GrantContent) -> bool {
    matches!(content.holder, SubjectSelector::Party(_)) && well_formed_authority(&content.authority)
}

/// The authority half of [`well_formed`], for an amendment that keeps the holder.
#[must_use]
pub fn well_formed_authority(a: &CanonicalAuthority) -> bool {
    !a.authority.actions.exact.is_empty()
        && a.authority.actions.prefix.is_empty()
        && a.delegation.depth == 0
        && a.requirements.iter().any(|t| {
            t.proof_kind == ProofKind::Contribution
                && t.count >= MIN_APPROVALS
                && t.independence == Independence::DistinctParty
                && t.freshness_ms.is_some_and(|f| f <= USE_MAX_MS)
        })
}

/// What a break-glass setup installs (§12.3.8, OP-157 m.3 (h)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setup {
    /// Where the Grants derive from.
    pub basis: GrantBasis,
    /// The Parties that hold one each.
    pub holders: BTreeSet<Id>,
    /// The reserved actions, named one by one.
    pub actions: BTreeSet<ActionRef>,
    /// What they cover.
    pub resource: ResourceSelector,
    /// How long the Grants stand.
    pub validity: Window,
    /// How many approvals a use needs.
    pub approvals: u64,
    /// Who may approve; `None` for anyone the domain accepts.
    pub approvers: Option<SubjectSelector>,
}

impl Setup {
    /// The Grants of the setup, one per holder.
    ///
    /// # Errors
    /// [`Refusal::MinimumTwo`] for fewer than two holders or approvals,
    /// [`Refusal::Actions`] without a named action.
    pub fn grants(&self) -> Result<Vec<GrantContent>, Refusal> {
        if self.holders.len() < MIN_GRANTS || self.approvals < MIN_APPROVALS {
            return Err(Refusal::MinimumTwo);
        }
        if self.actions.is_empty() {
            return Err(Refusal::Actions);
        }
        let authority = CanonicalAuthority {
            authority: AuthoritySet {
                actions: ActionSet {
                    exact: self.actions.clone(),
                    prefix: BTreeSet::new(),
                },
                resource: self.resource.clone(),
                params: std::collections::BTreeMap::new(),
                recipient: None,
                purpose: Some(purposes()),
            },
            constraints: ConstraintSet {
                validity: self.validity,
                conditions: BTreeSet::new(),
                budget: BTreeSet::new(),
            },
            delegation: DelegationTerms::default(),
            requirements: BTreeSet::from([approval_term(self.approvals, self.approvers.clone())]),
        };
        Ok(self
            .holders
            .iter()
            .map(|h| GrantContent {
                basis: self.basis,
                holder: SubjectSelector::Party(*h),
                authority: authority.clone(),
                agency: BTreeSet::from([access_kernel::combinator::Capacity::Own]),
                named: None,
            })
            .collect())
    }
}

/// One use of a break-glass Grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Use {
    /// The Grant used.
    pub grant: Id,
    /// Whether the use is a drill.
    pub drill: bool,
    /// How many approvals the Grant asks for.
    pub approvals: u64,
}

/// The break-glass use `req` is, given the state of the Grant it names: a holding of a live
/// break-glass Grant and an intent carrying `break_glass` or `drill`; `None` for any other
/// request, whatever purpose it declares.
#[must_use]
pub fn of(req: &Request, grant: Option<&GrantState>) -> Option<Use> {
    let ExerciseBasis::Holding(h) = req.basis else {
        return None;
    };
    let g = grant.filter(|g| g.ended.is_none())?;
    if !is_breakglass(&g.content.authority.authority) {
        return None;
    }
    let drill = match &req.intent.purpose {
        Some(PurposeRef::Code(c)) if c == PURPOSE => false,
        Some(PurposeRef::Code(c)) if c == DRILL => true,
        _ => return None,
    };
    let approvals = g
        .content
        .authority
        .requirements
        .iter()
        .filter(|t| t.proof_kind == ProofKind::Contribution)
        .map(|t| t.count)
        .max()
        .unwrap_or(0);
    Some(Use {
        grant: h.grant,
        drill,
        approvals,
    })
}

/// When a use at `used_at` must be reviewed by, ms.
#[must_use]
pub const fn review_due(used_at: u64, within_h: u64) -> u64 {
    used_at.saturating_add(within_h.saturating_mul(3_600_000))
}

/// The uses of `uses` (`(exercise, used_at)`) not reviewed by `now`: each is a
/// `breakglass.review_overdue` (§12.3.8 (4)).
#[must_use]
pub fn overdue<'a>(
    uses: impl IntoIterator<Item = &'a (Digest, u64)>,
    reviewed: &BTreeSet<Digest>,
    now: u64,
    within_h: u64,
) -> Vec<Digest> {
    uses.into_iter()
        .filter(|(e, at)| !reviewed.contains(e) && now > review_due(*at, within_h))
        .map(|(e, _)| *e)
        .collect()
}

/// Whether a realm whose break-glass stands since `since` is past its drill: no drill in the
/// last [`DRILL_EVERY_MS`] (§12.3.8 (5)).
#[must_use]
pub fn drill_overdue(last_drill: Option<u64>, since: u64, now: u64) -> bool {
    now.saturating_sub(last_drill.unwrap_or(since).max(since)) > DRILL_EVERY_MS
}

impl<L: DomainLog, R: Reader, B: BindingPort, S: Salts> Authority<L, R, B, S> {
    /// The break-glass use `req` is, read from the Grant it names (G29).
    pub(crate) async fn breakglass(&self, req: &Request) -> Result<Option<Use>, CoreError> {
        let ExerciseBasis::Holding(h) = req.basis else {
            return Ok(None);
        };
        if !matches!(&req.intent.purpose, Some(PurposeRef::Code(c)) if c == PURPOSE || c == DRILL) {
            return Ok(None);
        }
        let rows = self.fetch(&[meta::key(kind::GRANT, &h.grant)]).await?;
        let grant = rows
            .into_iter()
            .next()
            .and_then(|(_, v, _)| v)
            .and_then(|v: Value| GrantState::from_value(&v).ok());
        Ok(of(req, grant.as_ref()))
    }
}

#[cfg(test)]
mod tests;
