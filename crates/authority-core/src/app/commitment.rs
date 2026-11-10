//! Commitment-scoped Grants (§7.9.5.4 R7, §8.17.7.2, E8, EI-5, OP-156 m.3 (b), (t)): a Grant
//! held `while commitment.active(CommitmentRef)`, written with the existing primitive
//! `WhileCondition::ClaimHeld { class: "commitment_active", … }` and no Kernel change.
//!
//! The grantor names the `CommitmentRef` in the issuing intent's context; Access keeps it beside
//! the Grant. The coordinator's `commitment_active` Claim carries in `value` the body digest of
//! `{commitment, active}` (L2-CLB-1), so Access compares digests and never needs the body. A
//! current `active: true` Claim from the issuer the condition's Acceptance admits keeps the
//! Grant in force; without one it lapses. An affirmative `active: false` Claim ever admitted
//! ends it for good, like an expiry and without an Exercise; a later `true` never revives it
//! (E14). This is the only channel through which a coordinator ends authority, and it never
//! starts any.

use access_kernel::claim::{self, ClaimState, Gate, PREDICATE_INPUT, Statement};
use access_kernel::claim::body::BODY_CONTEXT;
use access_kernel::codec::Canonical;
use access_kernel::combinator::HopStatus;
use access_kernel::digest::Digest;
use access_kernel::fold::Effect;
use access_kernel::intent::IntentEnvelope;
use access_kernel::meta::{self, ContentState, GrantState, Payload, View, kind};
use access_kernel::model::{CanonicalAuthority, EqValue, Id, SubjectSelector, WhileCondition};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::domain::{Snapshot, claim_held_where, read};

/// The Claim class of a coordinator's commitment state (OP-156 m.3 (b)).
pub const CLASS: &str = "commitment_active";

/// The kind of the key that keeps a Grant's `CommitmentRef`: `dCBOR(["commitment", GrantID])`.
pub const BINDING: &str = "commitment";

/// The `commitment-active` body (CDDL `product-seam.cddl`).
#[must_use]
pub fn body(commitment: &Digest, active: bool) -> Value {
    Value::Map(vec![
        (Value::text("active"), Value::Bool(active)),
        (Value::text("commitment"), commitment.to_value()),
    ])
}

/// The `value` of a `commitment_active` Claim with `body(commitment, active)` (L2-CLB-1).
#[must_use]
pub fn value_digest(commitment: &Digest, active: bool) -> [u8; 32] {
    let bytes = dcbor::encode(
        &Value::Array(vec![Value::text(CLASS), body(commitment, active)]),
        Limits::CEILING,
    )
    .unwrap_or_default();
    context_digest(BODY_CONTEXT, &bytes).0
}

/// The `{commitment, active}` a disclosed body says, when it is one and matches `value`.
#[must_use]
pub fn decode(value: Option<&EqValue>, body: &[u8]) -> Option<(Digest, bool)> {
    let v = dcbor::decode(body, Limits::CEILING).ok()?;
    let Value::Map(entries) = &v else {
        return None;
    };
    if entries.len() != 2 {
        return None;
    }
    let mut commitment = None;
    let mut active = None;
    for (k, v) in entries {
        match (k, v) {
            (Value::Text(k), Value::Bool(b)) if k == "active" => active = Some(*b),
            (Value::Text(k), d) if k == "commitment" => commitment = Digest::from_value(d),
            _ => return None,
        }
    }
    let (commitment, active) = (commitment?, active?);
    match value {
        Some(EqValue::Bytes(d)) if d.as_slice() == value_digest(&commitment, active) => {
            Some((commitment, active))
        }
        _ => None,
    }
}

/// The key of Grant `grant`'s `CommitmentRef`.
#[must_use]
pub fn binding_key(grant: &Id) -> Vec<u8> {
    meta::key(BINDING, grant)
}

/// Whether `authority` names a `commitment_active` condition at all.
#[must_use]
pub fn scoped(authority: &CanonicalAuthority) -> bool {
    authority
        .constraints
        .conditions
        .iter()
        .any(|c| matches!(c, WhileCondition::ClaimHeld { class, .. } if class == CLASS))
}

/// The one well-formed `commitment_active` condition of `authority`: whose Claim (a named
/// Party) and the Acceptance it relies on. `None` when there is none, more than one, or one
/// about a group.
fn condition(authority: &CanonicalAuthority) -> Option<(Id, Digest)> {
    let mut found = authority
        .constraints
        .conditions
        .iter()
        .filter_map(|c| match c {
            WhileCondition::ClaimHeld {
                class,
                subject,
                acceptance,
            } if class == CLASS => Some((subject, acceptance)),
            _ => None,
        });
    let first = found.next()?;
    if found.next().is_some() {
        return None;
    }
    match first {
        (SubjectSelector::Party(p), d) => Some((*p, *d)),
        _ => None,
    }
}

/// Whether a meta-action may stand as far as commitment scoping goes (EI-5, E14): a new
/// commitment-scoped Grant names one Party's `commitment_active` and a `CommitmentRef` in its
/// intent's context; an amendment keeps the condition exactly as it was, so a Grant can neither
/// be scoped afterwards nor freed from its commitment, and an ended one is not revived.
pub(crate) fn admissible(view: &Snapshot, intent: &IntentEnvelope, payload: &Payload) -> bool {
    match payload {
        Payload::GrantIssue(content) => {
            !scoped(&content.authority)
                || (condition(&content.authority).is_some() && intent.context.commitment.is_some())
        }
        Payload::GrantAmend {
            grant, authority, ..
        } => {
            let Some(old) = read::<GrantState>(view, kind::GRANT, grant) else {
                return !scoped(authority);
            };
            let before = old.content.authority.constraints.conditions.iter();
            let after = authority.constraints.conditions.iter();
            let of_class = |c: &&WhileCondition| {
                matches!(c, WhileCondition::ClaimHeld { class, .. } if class == CLASS)
            };
            before.filter(of_class).eq(after.filter(of_class))
        }
        _ => true,
    }
}

/// The effect that keeps a new commitment-scoped Grant's `CommitmentRef` (§7.9.5.1: the
/// `CommitmentRef` is opaque intent context).
pub(crate) fn binding(
    intent: &IntentEnvelope,
    payload: Option<&Payload>,
    exercise: &Digest,
) -> Option<Effect> {
    let Some(Payload::GrantIssue(content)) = payload else {
        return None;
    };
    condition(&content.authority)?;
    let commitment = intent.context.commitment?;
    let grant = meta::object_id(exercise, kind::GRANT, 0);
    Some((binding_key(&grant), Some(commitment.to_value())))
}

/// The `CommitmentRef` Grant `grant` ends with, if it is commitment-scoped.
#[must_use]
pub fn of(view: &dyn View, grant: &Id) -> Option<Digest> {
    view.get(&binding_key(grant))
        .and_then(|v| Digest::from_value(&v))
}

/// The status a commitment-scoped Grant has beyond its own record (EI-5): `Revoked` once its
/// commitment ended, `Lapsed` while no current `active: true` Claim holds at `now`, `None` when
/// it is not commitment-scoped or its commitment is active. A scoped Grant without a readable
/// condition or `CommitmentRef` stands for nothing.
pub(crate) fn status(
    view: &Snapshot,
    grant: &Id,
    state: &GrantState,
    now: Option<u64>,
) -> Option<HopStatus> {
    if !scoped(&state.content.authority) {
        return None;
    }
    let Some((party, acceptance)) = condition(&state.content.authority) else {
        return Some(HopStatus::Revoked);
    };
    let Some(commitment) = of(view, grant) else {
        return Some(HopStatus::Revoked);
    };
    if ended(view, &party, &acceptance, &commitment) {
        return Some(HopStatus::Revoked);
    }
    let active = value_digest(&commitment, true);
    let current =
        |s: &Statement| matches!(&s.value, Some(EqValue::Bytes(d)) if d.as_slice() == active);
    match now {
        Some(now) if !claim_held_where(view, CLASS, &party, &acceptance, now, current) => {
            Some(HopStatus::Lapsed)
        }
        _ => None,
    }
}

/// Whether an `active: false` Claim about `commitment` was ever admitted from the issuer the
/// Acceptance with digest `acceptance` names: terminal, whatever came after (E14).
fn ended(view: &Snapshot, party: &Id, acceptance: &Digest, commitment: &Digest) -> bool {
    let inactive = value_digest(commitment, false);
    view.scan(&claim::member_prefix(CLASS, party))
        .into_iter()
        .filter_map(|(_, v)| Id::from_value(&v).ok())
        .filter_map(|id| read::<ClaimState>(view, kind::CLAIM, &id))
        .any(|c| {
            c.statement.class == CLASS
                && c.statement.subject == *party
                && matches!(&c.statement.value, Some(EqValue::Bytes(d)) if d.as_slice() == inactive)
                && names_issuer(view, &c.statement.issuer, acceptance)
        })
}

/// Whether the Acceptance with digest `acceptance`, live or not, is `issuer`'s for this class.
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
            g.issuer == Some(*issuer) && g.use_ == PREDICATE_INPUT && g.classes.iter().any(|c| c == CLASS)
        })
}

#[cfg(test)]
mod tests;
