//! Requirement Resolver: which proofs satisfy which requirement terms (T14, OP-111 m.3–m.5).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::algebra::subject_le;
use crate::codec::{Canonical, ModelError};
use crate::combinator::{Fuel, Rejection};
use crate::digest::Digest;
use crate::model::{
    Binding, Consumption, Id, Independence, ProofKind, RequirementTerm, ResourceRef,
    SubjectSelector, TrustedTime,
};

/// Assurance dimension that needs a human; an agent actor cannot satisfy it (OP-111 m.4).
pub const HUMAN_PRESENCE: &str = "human_presence";

/// Assurance dimension where the lower level is the stronger one (OP-118 m.3).
pub const SYNCED: &str = "synced";

/// The closed assurance dimensions with their lowest and highest level (§10.1.6, OP-118 m.3).
pub const ASSURANCE_DIMENSIONS: [(&str, u64, u64); 9] = [
    ("aal", 1, 3),
    ("app_controlled_factor", 0, 1),
    ("hardware_bound", 0, 1),
    (HUMAN_PRESENCE, 0, 1),
    ("loa_eidas", 1, 3),
    ("non_custodial", 0, 1),
    ("phishing_resistant", 0, 1),
    (SYNCED, 0, 1),
    ("uv", 0, 1),
];

/// Checks that every dimension is known and every level is in its range (OP-118 m.3).
///
/// # Errors
/// [`ModelError::Unknown`] for a dimension outside [`ASSURANCE_DIMENSIONS`],
/// [`ModelError::Range`] for a level outside its range; the first entry in key order wins.
pub fn check_assurance(levels: &BTreeMap<alloc::string::String, u64>) -> Result<(), ModelError> {
    for (dim, level) in levels {
        let (_, low, high) = ASSURANCE_DIMENSIONS
            .iter()
            .find(|(d, _, _)| d == dim)
            .ok_or(ModelError::Unknown)?;
        if level < low || level > high {
            return Err(ModelError::Range);
        }
    }
    Ok(())
}

// OP-118 m.3
pub(crate) fn meets_floor(dim: &str, floor: u64, level: u64) -> bool {
    if dim == SYNCED {
        level <= floor
    } else {
        level >= floor
    }
}

/// What a proof is bound to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProofBinding {
    /// Actor instance.
    pub actor_instance: Option<Id>,
    /// Intent digest.
    pub intent_digest: Option<Digest>,
    /// Resource.
    pub resource: Option<ResourceRef>,
}

/// A presented proof with its log position (T14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Proof identifier.
    pub id: Id,
    /// Proof kind.
    pub kind: ProofKind,
    /// Class within the kind.
    pub class: alloc::string::String,
    /// Log position.
    pub position: u64,
    /// Issue time.
    pub time: TrustedTime,
    /// Party the proof is about or from.
    pub party: Id,
    /// Instance that produced it.
    pub instance: Id,
    /// Issuer party.
    pub issuer: Id,
    /// Binding.
    pub binding: ProofBinding,
    /// Assurance values per dimension.
    pub assurance: BTreeMap<alloc::string::String, u64>,
    /// Already consumed by an earlier exercise.
    pub consumed: bool,
}

/// Context the binding and freshness checks need.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// Verifier time.
    pub now: TrustedTime,
    /// Actor instance, if authenticated.
    pub actor_instance: Option<Id>,
    /// Digest of the intent.
    pub intent_digest: &'a Digest,
    /// Intent resources.
    pub resources: &'a [ResourceRef],
}

/// Result for one term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Satisfied by these proofs, in selection order.
    Satisfied(Vec<Id>),
    /// Not satisfied; this many proofs are still missing.
    Unmet(u64),
}

/// Whether one proof satisfies one term on its own (OP-111 m.4).
#[must_use]
pub fn matches(term: &RequirementTerm, proof: &Proof, ctx: &Context<'_>) -> bool {
    let bound = match term.binding {
        Binding::None => true,
        Binding::ActorInstance => {
            ctx.actor_instance.is_some() && proof.binding.actor_instance == ctx.actor_instance
        }
        Binding::IntentDigest => proof.binding.intent_digest.as_ref() == Some(ctx.intent_digest),
        Binding::Resource => proof
            .binding
            .resource
            .as_ref()
            .is_some_and(|r| ctx.resources.contains(r)),
    };
    // OP-114 m.7
    let fresh = proof.time <= ctx.now
        && term.freshness_ms.is_none_or(|max| {
            ctx.now
                .checked_sub(proof.time)
                .is_some_and(|age| age <= max)
        });
    let source = term
        .source
        .as_ref()
        .is_none_or(|sel| subject_le(&SubjectSelector::Party(proof.issuer), sel));
    let assurance = term.assurance.iter().all(|(dim, floor)| {
        proof
            .assurance
            .get(dim)
            .is_some_and(|v| meets_floor(dim, *floor, *v))
    });
    let usable = term.consumption == Consumption::Reusable || !proof.consumed;
    proof.kind == term.proof_kind
        && proof.class == term.class
        && bound
        && fresh
        && source
        && assurance
        && usable
}

/// Whether a proof of the term's kind and class was presented but its issuer is outside the
/// term's source selector (`source-not-accepted`, OP-111 m.8).
#[must_use]
pub fn source_rejected(term: &RequirementTerm, proofs: &[Proof]) -> bool {
    term.source.as_ref().is_some_and(|sel| {
        proofs.iter().any(|p| {
            p.kind == term.proof_kind
                && p.class == term.class
                && !subject_le(&SubjectSelector::Party(p.issuer), sel)
        })
    })
}

fn independence_key(proof: &Proof, independence: Independence) -> Option<Id> {
    match independence {
        Independence::None => None,
        Independence::DistinctParty => Some(proof.party),
        Independence::DistinctInstance => Some(proof.instance),
        Independence::DistinctIssuer => Some(proof.issuer),
    }
}

/// Resolves terms in the order of their canonical bytes; single-use proofs count once across
/// terms (OP-111 m.3, m.5).
///
/// # Errors
/// [`Rejection::Fuel`]: one unit per proof × term comparison (OP-111 m.7).
pub fn resolve(
    terms: &BTreeSet<RequirementTerm>,
    proofs: &[Proof],
    ctx: &Context<'_>,
    fuel: &mut Fuel,
) -> Result<Vec<(RequirementTerm, Outcome)>, Rejection> {
    let mut ordered: Vec<&Proof> = proofs.iter().collect();
    ordered.sort_by_key(|p| (p.position, p.id));
    // OP-114 m.5, OP-122 m.2
    let mut canonical: Vec<(Vec<u8>, &RequirementTerm)> = terms
        .iter()
        .map(|t| t.to_bytes().map(|b| (b, t)).map_err(|_| Rejection::Input))
        .collect::<Result<_, _>>()?;
    canonical.sort_by(|a, b| a.0.cmp(&b.0));
    let mut spent: BTreeSet<Id> = BTreeSet::new();
    let mut out = Vec::new();
    for (_, term) in canonical {
        let mut chosen: Vec<Id> = Vec::new();
        let mut keys: BTreeSet<Id> = BTreeSet::new();
        for proof in &ordered {
            fuel.spend(1)?;
            if u64::try_from(chosen.len()).is_ok_and(|n| n >= term.count) {
                break;
            }
            if spent.contains(&proof.id) || !matches(term, proof, ctx) {
                continue;
            }
            if let Some(k) = independence_key(proof, term.independence)
                && !keys.insert(k)
            {
                continue;
            }
            chosen.push(proof.id);
        }
        let have = u64::try_from(chosen.len()).map_err(|_| Rejection::Input)?;
        if have >= term.count {
            if term.consumption == Consumption::SingleUse {
                spent.extend(chosen.iter().copied());
            }
            out.push((term.clone(), Outcome::Satisfied(chosen)));
        } else {
            out.push((
                term.clone(),
                Outcome::Unmet(term.count.checked_sub(have).unwrap_or(term.count)),
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
