//! Spec version tracks: understanding, adoption and the domain minimum (§9.17, §9.17.2, PI-21).
//!
//! Each track moves on its own: the core semantic spec, the core meta-schema and every interop
//! profile by name. Action schemas are pinned by Acceptance, not ordered, and connectivity
//! profiles are named by the `ValidityContract`.

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

#[cfg(test)]
mod tests;
