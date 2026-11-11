//! Spec version tracks: understanding, adoption and the domain minimum (§9.17, §9.17.2, PI-21).
//!
//! Each track moves on its own: the core semantic spec, the core meta-schema and every interop
//! profile by name. Action schemas are pinned by Acceptance, not ordered, and connectivity
//! profiles are named by the `ValidityContract`.

use alloc::collections::BTreeSet;

use crate::verify::cose::Algorithm;
use crate::verify::key_scope::{DomainMetadata, SpecVersions};

/// Core Semantic Spec version this Kernel evaluates; its vectors are `core/1` (OP-106 m.23).
pub const CORE: u64 = 1;

/// A version track of [`SpecVersions`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Track {
    /// Core Semantic Spec.
    Core,
    /// Core meta-schema.
    MetaSchema,
    /// An interop profile.
    Profile,
}

/// Why the versions an artefact or record cites are not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VersionError {
    /// Newer than this verifier understands; fail closed (§9.17 compat k.3, k.5).
    #[error("{0:?} version not understood")]
    NotUnderstood(Track),
    /// Not adopted by the domain, so it has no effect there (§9.17 compat k.2).
    #[error("{0:?} version not adopted by the domain")]
    NotAdopted(Track),
    /// Below the domain minimum (§9.17 compat k.4, PI-21).
    #[error("{0:?} version below the domain minimum")]
    BelowMinimum(Track),
}

fn at_most(cited: &SpecVersions, ceiling: &SpecVersions) -> Option<Track> {
    if cited.core > ceiling.core {
        return Some(Track::Core);
    }
    if cited.meta_schema > ceiling.meta_schema {
        return Some(Track::MetaSchema);
    }
    cited
        .profiles
        .iter()
        .any(|(name, v)| ceiling.profiles.get(name).is_none_or(|c| v > c))
        .then_some(Track::Profile)
}

fn at_least(cited: &SpecVersions, floor: &SpecVersions) -> Option<Track> {
    if cited.core < floor.core {
        return Some(Track::Core);
    }
    if cited.meta_schema < floor.meta_schema {
        return Some(Track::MetaSchema);
    }
    cited
        .profiles
        .iter()
        .any(|(name, v)| floor.profiles.get(name).is_some_and(|f| v < f))
        .then_some(Track::Profile)
}

/// One-way compatibility: a verifier accepts every version up to the one it implements, and
/// rejects a newer one or a profile it does not know (§9.17 compat k.5).
///
/// # Errors
/// [`VersionError::NotUnderstood`] with the first failing track.
pub fn check_understood(
    cited: &SpecVersions,
    supported: &SpecVersions,
) -> Result<(), VersionError> {
    at_most(cited, supported).map_or(Ok(()), |t| Err(VersionError::NotUnderstood(t)))
}

/// Checks cited versions against what a domain has adopted and its minimum, both read from its
/// verified Domain Metadata (OP-120 m.7), after [`check_understood`]. A version above the adopted one has no effect in the domain (k.2);
/// one below the minimum is a downgrade (k.4). Profiles are compared by name only, so a change of
/// a standard's version moves only its profile track (k.6).
///
/// # Errors
/// The first failing check, as [`VersionError`].
pub fn check_domain(
    cited: &SpecVersions,
    supported: &SpecVersions,
    metadata: &DomainMetadata,
) -> Result<(), VersionError> {
    check_understood(cited, supported)?;
    if let Some(t) = at_most(cited, &metadata.adopted) {
        return Err(VersionError::NotAdopted(t));
    }
    at_least(cited, &metadata.min_versions).map_or(Ok(()), |t| Err(VersionError::BelowMinimum(t)))
}

/// How long a raised domain minimum waits after its activation before it binds (§15.4, §13.7.8,
/// PD): 90 days.
pub const TRANSITION_MS: u64 = 90 * 24 * 3_600 * 1_000;

/// The least time-lock of a downgrade, whatever the domain's CT3 delay (§15.4, CR-8, SI-18):
/// 24 hours.
pub const DOWNGRADE_DELAY_MS: u64 = 24 * 3_600 * 1_000;

/// Whether `new` lowers any track of `old`: a lower core or meta-schema version, a lower or a
/// dropped profile floor, or a dropped pinned schema (SI-18, §17.10).
#[must_use]
pub fn lowers(old: &SpecVersions, new: &SpecVersions) -> bool {
    new.core < old.core
        || new.meta_schema < old.meta_schema
        || old
            .profiles
            .iter()
            .any(|(name, v)| new.profiles.get(name).is_none_or(|n| n < v))
        || !old.schemas.is_subset(&new.schemas)
}

/// Whether a change of the domain minimum from `old_min` to `new_min` and of the algorithm
/// allowlist from `old_algs` to `new_algs` is a downgrade: lowering the minimum or adding any
/// algorithm, strong or weak, is expansion (CT3 and at least [`DOWNGRADE_DELAY_MS`]); raising the
/// minimum and removing algorithms narrow (CT1) (SI-18, CR-8, §15.4, §15.16 k.2).
#[must_use]
pub fn downgrades(
    (old_min, new_min): (&SpecVersions, &SpecVersions),
    (old_algs, new_algs): (&BTreeSet<Algorithm>, &BTreeSet<Algorithm>),
) -> bool {
    lowers(old_min, new_min) || !new_algs.is_subset(old_algs)
}

/// The domain minimum in force at `now`: `current`, raised track by track to `activated` once
/// [`TRANSITION_MS`] have passed since `activated_at`, never lowered (§15.4, §13.7.8).
#[must_use]
pub fn minimum_at(
    current: &SpecVersions,
    activated: &SpecVersions,
    activated_at: u64,
    now: u64,
) -> SpecVersions {
    let due = activated_at
        .checked_add(TRANSITION_MS)
        .is_some_and(|t| now >= t);
    if !due {
        return current.clone();
    }
    let mut out = current.clone();
    out.core = out.core.max(activated.core);
    out.meta_schema = out.meta_schema.max(activated.meta_schema);
    for (name, v) in &activated.profiles {
        let floor = out.profiles.entry(name.clone()).or_insert(*v);
        *floor = (*floor).max(*v);
    }
    out.schemas.extend(activated.schemas.iter().copied());
    out
}

#[cfg(test)]
mod tests;
