//! CR-K2: the `ValidityContract` arithmetic of `access_kernel::validity` (MD-7, SI-7, OP-108
//! m.1, m.2): the horizon is the earliest bound and never wraps, adding a bound only narrows it,
//! and Δ of `bounded-staleness` is consumed from the last refresh and never extends.

use std::collections::BTreeSet;

use access_kernel::validity::{self, ProfileVariant, ValidityError};

use super::{Moment, contract};

/// Up to three dependency bounds.
pub(crate) const BOUNDS: usize = 3;

/// `horizon` is `min(issued_at + profile_max, bounds…)` and `Overflow` when the sum leaves
/// `u64`; one more bound never raises it.
pub(crate) fn horizon_is_the_earliest_bound(
    issued_at: u64,
    bounds: [u64; BOUNDS],
    used: usize,
    profile_max: u64,
    extra: u64,
) -> bool {
    let used = used.min(BOUNDS);
    let Some(deps) = bounds.get(..used) else {
        return false;
    };
    let r = validity::horizon(issued_at, deps, profile_max);
    let Some(profile) = issued_at.checked_add(profile_max) else {
        return r == Err(ValidityError::Overflow);
    };
    let want = deps.iter().copied().fold(profile, u64::min);
    if r != Ok(want) {
        return false;
    }
    let mut more = deps.to_vec();
    more.push(extra);
    matches!(validity::horizon(issued_at, &more, profile_max), Ok(h) if h <= want)
}

fn offline(now: u64, last_refresh: Option<u64>) -> Moment {
    Moment {
        now,
        iat: 0,
        skew_ms: 0,
        horizon_cap_ms: u64::MAX,
        online: false,
        last_refresh,
    }
}

fn staleness(now: u64, refresh: Option<u64>, delta: Option<u64>) -> Result<(), ValidityError> {
    let understood = BTreeSet::new();
    validity::check(
        &contract(u64::MAX, ProfileVariant::BoundedStaleness, delta, 0),
        &offline(now, refresh).context(&understood),
    )
}

/// Offline `bounded-staleness` use is accepted exactly when a refresh at or before `now` is at
/// most Δ old; no Δ, no refresh or a refresh from the future is `Stale`, and a smaller Δ never
/// accepts what a larger one refuses.
pub(crate) fn delta_is_consumed(
    now: u64,
    refresh: Option<u64>,
    delta: Option<u64>,
    narrower: u64,
) -> bool {
    let r = staleness(now, refresh, delta);
    let ok = match (refresh, delta) {
        (Some(t), Some(d)) if t <= now => match t.checked_add(d) {
            Some(limit) => now <= limit,
            None => return r == Err(ValidityError::Overflow),
        },
        _ => return r == Err(ValidityError::Stale),
    };
    if r.is_ok() != ok || (!ok && r != Err(ValidityError::Stale)) {
        return false;
    }
    let Some(d) = delta else {
        return true;
    };
    staleness(now, refresh, Some(narrower.min(d))).is_err() || r.is_ok()
}

#[cfg(kani)]
mod harness {
    // CR-K2, OP-108 m.1, m.2
    #[kani::proof]
    #[kani::unwind(5)]
    fn k2_horizon_is_the_earliest_bound() {
        assert!(super::horizon_is_the_earliest_bound(
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any()
        ));
    }

    // CR-K2, SI-7
    #[kani::proof]
    fn k2_delta_is_consumed_and_never_extends() {
        assert!(super::delta_is_consumed(
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any()
        ));
    }
}

#[cfg(all(test, not(kani)))]
mod tests {
    use proptest::prelude::*;

    use super::super::edge;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 2048, failure_persistence: None, ..ProptestConfig::default() })]

        // CR-K2, OP-108 m.1, m.2
        #[test]
        fn k2_horizon_is_the_earliest_bound(
            issued in edge(), a in edge(), b in edge(), c in edge(), used in 0..=3usize,
            max in edge(), extra in edge()
        ) {
            prop_assert!(super::horizon_is_the_earliest_bound(issued, [a, b, c], used, max, extra));
        }

        // CR-K2, SI-7
        #[test]
        fn k2_delta_is_consumed_and_never_extends(
            now in edge(), refresh in proptest::option::of(edge()),
            delta in proptest::option::of(edge()), narrower in edge()
        ) {
            prop_assert!(super::delta_is_consumed(now, refresh, delta, narrower));
        }
    }
}
