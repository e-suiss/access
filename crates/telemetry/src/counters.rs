//! Security counters with permanent event names (OP-67, §13.7.8).

use crate::metrics::{Counter, Label};

/// Artefacts refused because they cite a version this process does not understand, has not
/// adopted or holds below the minimum (§15.4: "red + sayaç"), by `kind` and `track`.
pub static UNKNOWN_VERSION: Counter<2> = Counter::new(
    "access_artifact_unknown_version_total",
    "Artefacts refused for an unknown version (§15.4, §13.7.8)",
    [Label::Kind, Label::Track],
);

/// Records one artefact of `kind` refused for its `track` version (core, meta-schema or
/// profile) and logs the permanent event `artifact.version.unknown`. The refusal itself is the
/// caller's (fail closed, §15.4); this only counts it.
pub fn unknown_version(kind: &'static str, track: &'static str) -> u64 {
    let total = UNKNOWN_VERSION.incr([kind, track]);
    tracing::warn!(
        event = "artifact.version.unknown",
        outcome = "refused",
        kind,
        track,
        total,
        "artefact with an unknown version refused (§15.4)"
    );
    total
}

/// Issuer quota windows used up (G44, §16.7): one per issuer and window.
pub static ISSUER_QUOTA: Counter<0> = Counter::new(
    "access_claim_issuer_quota_reached_total",
    "Issuer Claim quota windows used up (G44)",
    [],
);

/// Records that an issuer used up its Claim quota for a window and logs the permanent event
/// `claim.issuer.quota`; the issuer itself learns it from the `quota` reason of its held
/// Claims (§16.7).
pub fn issuer_quota(window_s: u64) -> u64 {
    let total = ISSUER_QUOTA.incr([]);
    tracing::warn!(
        event = "claim.issuer.quota",
        outcome = "held",
        window_s,
        total,
        "an issuer used up its Claim quota; qualifying Claims are held (G44)"
    );
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    // §15.4, CR-7, OP-150, §13.7.8
    #[test]
    fn unknown_versions_are_counted() {
        let before = UNKNOWN_VERSION.get();
        assert!(unknown_version("receipt", "core") > before);
        assert!(UNKNOWN_VERSION.get() > before);
        assert_eq!(
            UNKNOWN_VERSION.name(),
            "access_artifact_unknown_version_total"
        );
    }
}
