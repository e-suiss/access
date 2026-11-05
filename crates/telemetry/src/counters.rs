//! Process counters with permanent event names (OP-67), read by the metric export and the
//! health surface.

use std::sync::atomic::{AtomicU64, Ordering};

/// A monotonic process counter.
#[derive(Debug)]
pub struct Counter {
    name: &'static str,
    value: AtomicU64,
}

impl Counter {
    /// A counter at zero.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            value: AtomicU64::new(0),
        }
    }

    /// The metric name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Adds one and returns the new total; it saturates instead of wrapping.
    pub fn incr(&self) -> u64 {
        let before = self
            .value
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(1))
            })
            .unwrap_or(u64::MAX);
        before.saturating_add(1)
    }

    /// The total so far.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Artefacts refused because they cite a version this process does not understand, has not
/// adopted or holds below the minimum (§15.4: "red + sayaç").
pub static UNKNOWN_VERSION: Counter = Counter::new("access_artifact_unknown_version_total");

/// Records one artefact of `kind` refused for its `track` version (core, meta-schema or
/// profile) and logs the permanent event `artifact.version.unknown`. The refusal itself is the
/// caller's (fail closed, §15.4); this only counts it.
pub fn unknown_version(kind: &'static str, track: &'static str) -> u64 {
    let total = UNKNOWN_VERSION.incr();
    tracing::warn!(
        event = "artifact.version.unknown",
        kind,
        track,
        total,
        "artefact with an unknown version refused (§15.4)"
    );
    total
}

/// Issuer quota windows used up (G44, §16.7): one per issuer and window.
pub static ISSUER_QUOTA: Counter = Counter::new("access_claim_issuer_quota_reached_total");

/// Records that an issuer used up its Claim quota for a window and logs the permanent event
/// `claim.issuer.quota`; the issuer itself learns it from the `quota` reason of its held
/// Claims (§16.7).
pub fn issuer_quota(window_s: u64) -> u64 {
    let total = ISSUER_QUOTA.incr();
    tracing::warn!(
        event = "claim.issuer.quota",
        window_s,
        total,
        "an issuer used up its Claim quota; qualifying Claims are held (G44)"
    );
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    // §15.4, CR-7, OP-150: each refused unknown-version artefact counts once; the counter never
    // wraps
    #[test]
    fn unknown_versions_are_counted() {
        let before = UNKNOWN_VERSION.get();
        assert_eq!(unknown_version("receipt", "core"), before.saturating_add(1));
        assert!(UNKNOWN_VERSION.get() > before);
        let c = Counter::new("x_total");
        c.value.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(c.incr(), u64::MAX);
        assert_eq!(c.name(), "x_total");
    }
}
