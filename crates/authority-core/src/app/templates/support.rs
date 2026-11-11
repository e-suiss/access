//! Support access templates (MD-9, TN-70…TN-73, §8.16, §12.3.4, OP-157 m.3 (c), (e)): support
//! access is the person's own `grant.issue` to a support operator, never an identity the
//! operator takes on. The Grant derives from the person's self-anchor, names only the support
//! actions of `idp.account` on the person's own resources, acts `For` the person alone, passes
//! on to no one, is bound to one case by `PurposeRef::Case`, and holds only while the case
//! system's `support_case` Claim says that case is open.
//!
//! - [`Template::Session`]: the actions the person chose, at most [`SESSION_MAX_MS`].
//! - [`Template::Standing`]: read only, at most [`STANDING_MAX_MS`] (TN-137 (2)).
//! - [`Template::Org`]: the same shape `For` an organization on its own resources (TN-72); an
//!   employee's account is never reached this way.
//! - [`Template::Artifacts`]: reading the person's support artifacts alone, at most
//!   [`SESSION_MAX_MS`], a Grant apart from any other (§8.16 #12, TN-74).
//!
//! A meta-action that would make a support Grant of another shape is refused with the reason
//! [`admissible`] names, and a support Grant is never amended: a longer one is a new consent.

use std::collections::BTreeSet;

use access_internal_api::idp::IdpAction;
use access_kernel::claim::body::BODY_CONTEXT;
use access_kernel::claim::{self, ClaimState, Gate, PREDICATE_INPUT, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, HopStatus};
use access_kernel::digest::Digest;
use access_kernel::meta::{
    self, AnchorScope, AnchorState, ContentState, ExerciseBasis, GrantBasis, GrantContent,
    GrantState, Payload, View, kind,
};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms,
    EqValue, Id, PurposeRef, ResourceSelector, Structural, SubjectSelector, WhileCondition, Window,
};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::domain::{Snapshot, claim_held_where, read};

/// The Claim class of a case system's case state (OP-157 m.3 (e)).
pub const CLASS: &str = "support_case";

/// The namespace support access targets (E34).
pub const NAMESPACE: &str = "idp.account";

/// The resource namespace of a Party's own resources under its self-anchor (L0-META-7).
pub const RESOURCES: &str = "access.party";

/// Longest support Grant that may write, ms (§8.16 #5, PD).
pub const SESSION_MAX_MS: u64 = 60 * 60 * 1000;

/// Longest read-only standing support Grant, ms (TN-137 (2), OP-157 m.3 (c), PD).
pub const STANDING_MAX_MS: u64 = 24 * 60 * 60 * 1000;

/// The actions a support Grant may name (§8.16, E34): reading the account and changing its
/// profile fields.
pub const ELIGIBLE: [IdpAction; 2] = [IdpAction::AccountRead, IdpAction::AccountProfileUpdate];

/// The actions a read-only support Grant names (TN-137 (2), (4)).
pub const READ_ONLY: [IdpAction; 1] = [IdpAction::AccountRead];

/// The one action a support artifact Grant names; no other support Grant names it (§8.16 #12,
/// TN-74, OP-157 m.3 (g)).
pub const ARTIFACTS: [IdpAction; 1] = [IdpAction::AccountArtifactRead];

/// The `idp.account` actions no support Grant names and the `support-protected` policy forbids
/// for every `For` Exercise (§8.16 #3, OP-157 m.3 (a), (c)): every reserved one, the primary
/// e-mail change and the bulk export.
pub const PROTECTED: [IdpAction; 13] = [
    IdpAction::AccountEmailChange,
    IdpAction::AccountExport,
    IdpAction::AccountDelete,
    IdpAction::AccountRecoveryPolicyLoosen,
    IdpAction::AccountMigrationExport,
    IdpAction::AccountSigninMethodChange,
    IdpAction::AccountMfaChange,
    IdpAction::AccountPhoneChange,
    IdpAction::AccountPayment,
    IdpAction::AccountRoleElevate,
    IdpAction::AccountInvite,
    IdpAction::AccountApiKeyCreate,
    IdpAction::AccountTokenLongLived,
];

/// The policy default that lowers the support ceiling, in minutes (OP-157 m.3 (n)).
pub const MAX_MINUTES_DEFAULT: &str = "support_max_min";

/// Refused: no case, or not exactly one open-case condition and one case purpose
/// (OP-157 m.3 (c)).
pub const CASE_REQUIRED: &str = "support-case-required";

/// Refused: a protected `idp.account` action (§8.16 #3).
pub const PROTECTED_ACTION: &str = "support-protected";

/// Refused: an action outside [`ELIGIBLE`], a resource outside the person's own, or an agency
/// other than `For` that person (§8.16 #2, TN-72).
pub const OUT_OF_SCOPE: &str = "support-scope";

/// Refused: longer than the ceiling (§8.16 #5).
pub const TOO_LONG: &str = "support-ceiling";

/// Refused: a support Grant that may be passed on (§8.16 #9).
pub const PASSES_ON: &str = "support-depth";

/// Refused: a support Grant not issued by the person on their own self-anchor (MD-9).
pub const NOT_OWN: &str = "support-not-own";

/// Refused: a projection of a support Grant whose case is closed, or whose open-case Claim is
/// missing or stale (OP-157 m.3 (e)).
pub const CASE_CLOSED: &str = "support-case-closed";

/// Refused: an amendment of a support Grant; a longer one is a new `grant.issue` (§8.16 #5).
pub const AMENDED: &str = "support-new-consent";

/// A support template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Template {
    /// `support.session`.
    Session,
    /// `support.standing`: read only.
    Standing,
    /// `support.org`: for an organization on its own resources.
    Org,
    /// `support.artifacts`: reading the person's support artifacts.
    Artifacts,
}

impl Template {
    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Session => "support.session",
            Self::Standing => "support.standing",
            Self::Org => "support.org",
            Self::Artifacts => "support.artifacts",
        }
    }

    /// Its ceiling, ms.
    #[must_use]
    pub const fn ceiling_ms(self) -> u64 {
        match self {
            Self::Standing => STANDING_MAX_MS,
            Self::Session | Self::Org | Self::Artifacts => SESSION_MAX_MS,
        }
    }
}

/// What the person gives: to whom, on which case, which actions and for how long.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Give {
    /// The template.
    pub template: Template,
    /// The person or organization the operator acts for.
    pub subject: Id,
    /// Their self-anchor.
    pub anchor: Id,
    /// The operator Party or the support team selector.
    pub holder: SubjectSelector,
    /// The `PurposeRef::Case` digest of the case.
    pub case: Digest,
    /// The digest of the domain's `predicate-input` Acceptance of the case system.
    pub acceptance: Digest,
    /// The actions; [`Template::Standing`] takes [`READ_ONLY`] whatever is named.
    pub actions: BTreeSet<IdpAction>,
    /// When it starts and ends, Unix ms.
    pub validity: Window,
}

fn hex(id: &Id) -> String {
    use std::fmt::Write as _;
    id.0.iter().fold(String::with_capacity(32), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl Give {
    /// The `grant.issue` content of this support access.
    ///
    /// # Errors
    /// The refusal reason [`shape`] names.
    pub fn grant(&self) -> Result<GrantContent, &'static str> {
        let actions: BTreeSet<ActionRef> = match self.template {
            Template::Standing => READ_ONLY.iter().map(|a| a.action_ref()).collect(),
            Template::Artifacts => ARTIFACTS.iter().map(|a| a.action_ref()).collect(),
            Template::Session | Template::Org => {
                self.actions.iter().map(|a| a.action_ref()).collect()
            }
        };
        let content = GrantContent {
            basis: GrantBasis::Anchor(self.anchor),
            holder: self.holder.clone(),
            authority: CanonicalAuthority {
                authority: AuthoritySet {
                    actions: ActionSet {
                        exact: actions,
                        prefix: BTreeSet::new(),
                    },
                    resource: ResourceSelector::Structural(Structural {
                        namespace: String::from(RESOURCES),
                        prefix: vec![hex(&self.subject)],
                        kind: None,
                        attrs: std::collections::BTreeMap::new(),
                    }),
                    params: std::collections::BTreeMap::new(),
                    recipient: None,
                    purpose: Some(BTreeSet::from([PurposeRef::Case(self.case)])),
                },
                constraints: ConstraintSet {
                    validity: self.validity,
                    conditions: BTreeSet::from([WhileCondition::ClaimHeld {
                        class: String::from(CLASS),
                        subject: SubjectSelector::Party(self.subject),
                        acceptance: self.acceptance,
                    }]),
                    budget: BTreeSet::new(),
                },
                delegation: DelegationTerms::default(),
                requirements: BTreeSet::new(),
            },
            agency: BTreeSet::from([Capacity::For(self.subject)]),
            named: None,
        };
        shape(&content, self.validity.from, None)?;
        Ok(content)
    }
}

/// The `support-case` body (CDDL `product-seam.cddl`) a case system states, without the
/// optional `operator_team`: a support Grant holds only on that form (OP-157 m.3 (e)).
#[must_use]
pub fn body(case: &Digest, subject: &Id, open: bool) -> Value {
    Value::Map(vec![
        (Value::text("case"), Value::Bytes(case.0.to_vec())),
        (Value::text("open"), Value::Bool(open)),
        (Value::text("subject"), Value::Bytes(subject.0.to_vec())),
    ])
}

/// The `value` of a `support_case` Claim with `body(case, subject, open)` (L2-CLB-1).
#[must_use]
pub fn value_digest(case: &Digest, subject: &Id, open: bool) -> [u8; 32] {
    let bytes = dcbor::encode(
        &Value::Array(vec![Value::text(CLASS), body(case, subject, open)]),
        Limits::CEILING,
    )
    .unwrap_or_default();
    context_digest(BODY_CONTEXT, &bytes).0
}

fn names_namespace(authority: &AuthoritySet) -> bool {
    authority
        .actions
        .exact
        .iter()
        .any(|a| a.namespace == NAMESPACE)
        || authority
            .actions
            .prefix
            .iter()
            .any(|(p, _)| p == NAMESPACE || p.starts_with("idp.account."))
}

fn case_condition(authority: &CanonicalAuthority) -> bool {
    authority
        .constraints
        .conditions
        .iter()
        .any(|c| matches!(c, WhileCondition::ClaimHeld { class, .. } if class == CLASS))
}

/// Whether a Grant of `authority` and `agency` is a support Grant: one held while a case is
/// open, or one that acts `For` someone with an `idp.account` action.
#[must_use]
pub fn is_support(authority: &CanonicalAuthority, agency: &BTreeSet<Capacity>) -> bool {
    case_condition(authority)
        || (agency.iter().any(|c| matches!(c, Capacity::For(_)))
            && names_namespace(&authority.authority))
}

/// The one person a support Grant acts for, the Acceptance its case condition relies on and
/// its case.
fn parts(authority: &CanonicalAuthority) -> Option<(Id, Digest, Digest)> {
    let mut found = authority
        .constraints
        .conditions
        .iter()
        .filter_map(|c| match c {
            WhileCondition::ClaimHeld {
                class,
                subject: SubjectSelector::Party(p),
                acceptance,
            } if class == CLASS => Some((*p, *acceptance)),
            _ => None,
        });
    let (party, acceptance) = found.next()?;
    if found.next().is_some() || authority.constraints.conditions.len() != 1 {
        return None;
    }
    let purposes = authority.authority.purpose.as_ref()?;
    let mut cases = purposes.iter();
    let Some(PurposeRef::Case(case)) = cases.next() else {
        return None;
    };
    if cases.next().is_some() {
        return None;
    }
    Some((party, acceptance, *case))
}

fn own_resource(resource: &ResourceSelector, party: &Id) -> bool {
    let me = hex(party);
    match resource {
        ResourceSelector::Structural(s) => {
            s.namespace == RESOURCES && s.prefix.first().is_some_and(|p| *p == me)
        }
        ResourceSelector::Exact(r) => {
            r.namespace == RESOURCES && r.path.first().is_some_and(|p| *p == me)
        }
    }
}

/// Whether `content` has the shape of a support Grant at `now`, the ceiling lowered to
/// `max_minutes` when the domain set one (§8.16, OP-157 m.3 (c)).
///
/// # Errors
/// The refusal reason.
pub fn shape(
    content: &GrantContent,
    now: u64,
    max_minutes: Option<u64>,
) -> Result<(), &'static str> {
    let a = &content.authority;
    // TN-73, §8.16
    let (party, _, _) = parts(a).ok_or(CASE_REQUIRED)?;
    // INV-4, TN-72
    if content.agency != BTreeSet::from([Capacity::For(party)]) {
        return Err(OUT_OF_SCOPE);
    }
    if content.holder == SubjectSelector::Party(party) || content.holder == SubjectSelector::Public
    {
        return Err(OUT_OF_SCOPE);
    }
    // §8.16
    let named = &a.authority.actions;
    if named
        .exact
        .iter()
        .any(|x| x.namespace == NAMESPACE && PROTECTED.iter().any(|p| p.name() == x.name))
    {
        return Err(PROTECTED_ACTION);
    }
    // §8.16, TN-74
    let artifacts = named.exact.len() == 1
        && named
            .exact
            .iter()
            .all(|x| ARTIFACTS.iter().any(|e| e.action_ref() == *x));
    // §8.16, E34
    if named.exact.is_empty()
        || !named.prefix.is_empty()
        || !(artifacts
            || named
                .exact
                .iter()
                .all(|x| ELIGIBLE.iter().any(|e| e.action_ref() == *x)))
        || !own_resource(&a.authority.resource, &party)
        || !a.authority.params.is_empty()
        || a.authority.recipient.is_some()
    {
        return Err(OUT_OF_SCOPE);
    }
    // §8.16
    if a.delegation.depth != 0 || a.delegation.downstream_holder_class.is_some() {
        return Err(PASSES_ON);
    }
    if !matches!(content.basis, GrantBasis::Anchor(_)) {
        return Err(NOT_OWN);
    }
    // §8.16, TN-137 (2)
    let read_only = named
        .exact
        .iter()
        .all(|x| READ_ONLY.iter().any(|r| r.action_ref() == *x));
    let template = if artifacts {
        Template::Artifacts
    } else if read_only {
        Template::Standing
    } else {
        Template::Session
    };
    let ceiling = max_minutes
        .and_then(|m| m.checked_mul(60_000))
        .map_or(template.ceiling_ms(), |m| m.min(template.ceiling_ms()));
    let v = a.constraints.validity;
    let span = v.until.checked_sub(v.from).ok_or(TOO_LONG)?;
    let ahead = v.until.saturating_sub(now.max(v.from));
    if span > ceiling || ahead > ceiling {
        return Err(TOO_LONG);
    }
    Ok(())
}

fn max_minutes(view: &Snapshot) -> Option<u64> {
    match view.get(&meta::policy_default_key(MAX_MINUTES_DEFAULT)) {
        Some(Value::Unsigned(n)) => Some(n),
        _ => None,
    }
}

/// Whether a meta-action may stand as far as support access goes (MD-9, §8.16, OP-157 m.3 (c)):
/// a new support Grant has the template shape and derives from the self-anchor of the one it
/// acts for; a support Grant is never amended, nor is a Grant amended into one; a projection on a
/// support Grant needs its case open now.
///
/// # Errors
/// The refusal reason.
pub(crate) fn admissible(
    view: &Snapshot,
    payload: &Payload,
    basis: ExerciseBasis,
    now: u64,
) -> Result<(), &'static str> {
    match payload {
        Payload::GrantIssue(content) if is_support(&content.authority, &content.agency) => {
            shape(content, now, max_minutes(view))?;
            let (party, _, _) = parts(&content.authority).ok_or(CASE_REQUIRED)?;
            let GrantBasis::Anchor(anchor) = content.basis else {
                return Err(NOT_OWN);
            };
            // MD-9, TN-70
            let own = read::<AnchorState>(view, kind::ANCHOR, &anchor)
                .is_some_and(|s| s.scope == AnchorScope::Party(party));
            if own { Ok(()) } else { Err(NOT_OWN) }
        }
        Payload::GrantAmend {
            grant,
            authority,
            agency,
            ..
        } => {
            let was = read::<GrantState>(view, kind::GRANT, grant)
                .is_some_and(|g| is_support(&g.content.authority, &g.content.agency));
            if was || is_support(authority, agency) {
                Err(AMENDED)
            } else {
                Ok(())
            }
        }
        // OP-157 m.3 (d), (e)
        Payload::ProjectionIssue { .. } => match basis {
            ExerciseBasis::Holding(h) => {
                let held = read::<GrantState>(view, kind::GRANT, &h.grant)
                    .is_none_or(|g| status(view, &g, Some(now)).is_none());
                if held { Ok(()) } else { Err(CASE_CLOSED) }
            }
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}

/// The status a support Grant has beyond its own record (OP-157 m.3 (e)): `Revoked` once its
/// case system said the case is closed, `Lapsed` while no current open-case Claim holds at
/// `now`, `None` when it is not a support Grant or its case is open. A support Grant whose case
/// cannot be read stands for nothing.
pub(crate) fn status(view: &Snapshot, state: &GrantState, now: Option<u64>) -> Option<HopStatus> {
    if !case_condition(&state.content.authority) {
        return None;
    }
    let Some((party, acceptance, case)) = parts(&state.content.authority) else {
        return Some(HopStatus::Revoked);
    };
    if closed(view, &party, &acceptance, &case) {
        return Some(HopStatus::Revoked);
    }
    let open = value_digest(&case, &party, true);
    let current =
        |s: &Statement| matches!(&s.value, Some(EqValue::Bytes(d)) if d.as_slice() == open);
    match now {
        Some(now) if !claim_held_where(view, CLASS, &party, &acceptance, now, current) => {
            Some(HopStatus::Lapsed)
        }
        _ => None,
    }
}

/// Whether a closed-case Claim about `case` was ever admitted from the case system the
/// Acceptance with digest `acceptance` names: terminal, whatever came after.
fn closed(view: &Snapshot, party: &Id, acceptance: &Digest, case: &Digest) -> bool {
    let shut = value_digest(case, party, false);
    view.scan(&claim::member_prefix(CLASS, party))
        .into_iter()
        .filter_map(|(_, v)| Id::from_value(&v).ok())
        .filter_map(|id| read::<ClaimState>(view, kind::CLAIM, &id))
        .any(|c| {
            c.statement.class == CLASS
                && c.statement.subject == *party
                && matches!(&c.statement.value, Some(EqValue::Bytes(d)) if d.as_slice() == shut)
                && names_issuer(view, &c.statement.issuer, acceptance)
        })
}

fn names_issuer(view: &Snapshot, issuer: &Id, acceptance: &Digest) -> bool {
    view.get(&meta::key(kind::ACCEPTANCES, issuer))
        .map(|v| match v {
            Value::Array(ids) => ids,
            _ => Vec::new(),
        })
        .unwrap_or_default()
        .iter()
        .filter_map(|v| Id::from_value(v).ok())
        .filter_map(|a| read::<ContentState>(view, kind::ACCEPTANCE, &a))
        .filter(|a| claim::acceptance_digest(&a.content) == *acceptance)
        .filter_map(|a| Gate::of(&a.content).ok())
        .any(|g| {
            g.issuer == Some(*issuer)
                && g.use_ == PREDICATE_INPUT
                && g.classes.iter().any(|c| c == CLASS)
        })
}

/// The digest of the live `predicate-input` Acceptance of `issuer` that takes `support_case`
/// Claims: what a support Grant's case condition names (OP-157 m.3 (e)). `None` while the domain
/// accepts no such Claims from it.
#[must_use]
pub fn case_acceptance(view: &Snapshot, issuer: &Id) -> Option<Digest> {
    view.get(&meta::key(kind::ACCEPTANCES, issuer))
        .map(|v| match v {
            Value::Array(ids) => ids,
            _ => Vec::new(),
        })
        .unwrap_or_default()
        .iter()
        .filter_map(|v| Id::from_value(v).ok())
        .filter_map(|a| read::<ContentState>(view, kind::ACCEPTANCE, &a))
        .filter(|a| {
            Gate::of(&a.content).is_ok_and(|g| {
                g.issuer == Some(*issuer)
                    && g.use_ == PREDICATE_INPUT
                    && g.classes.iter().any(|c| c == CLASS)
            })
        })
        .map(|a| claim::acceptance_digest(&a.content))
        .next()
}

/// What the identity plane needs to draft a person's support Grant (OP-157 m.3 (f)): the
/// person's self-anchor and the Acceptance the case system's Claims count under.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// The self-anchor of the person, when the domain knows the Party.
    pub anchor: Option<Id>,
    /// The case system's `support_case` Acceptance, when the domain has one.
    pub acceptance: Option<Digest>,
}

impl<
    L: access_authority_sequencer::ports::DomainLog,
    R: crate::ports::Reader,
    B: crate::ports::Binding,
    S: crate::ports::Salts,
> crate::app::Authority<L, R, B, S>
{
    /// The [`Facts`] of `party` and the case system `issuer` at the head.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn support_facts(&self, party: &Id, issuer: &Id) -> Result<Facts, crate::CoreError> {
        self.settled(|snap| Facts {
            anchor: read::<meta::PartyState>(snap, kind::PARTY, party)
                .filter(|p| p.ended.is_none())
                .map(|p| p.anchor),
            acceptance: case_acceptance(snap, issuer),
        })
        .await
    }
}

#[cfg(test)]
mod tests;
