//! CR-K1: the local acceptance arithmetic `min(horizon, iat + cap)` of
//! `access_kernel::validity::check` (T20, OP-117 m.13, OP-118 m.4).

use std::collections::BTreeSet;

use access_kernel::validity::ceiling::{
    CT2_OFFLINE_EXTENSION_MS, REPORT_GRACE_MS, ct2_offline_extension, report_deadline,
};
use access_kernel::validity::{self, ProfileVariant, ValidityError};

use super::{Moment, contract};

/// The verdict of `validity::check` online, for a contract with `horizon` and its own skew.
fn verdict(m: &Moment, horizon: u64, vc_skew: u64) -> Result<(), ValidityError> {
    let understood = BTreeSet::new();
    validity::check(
        &contract(horizon, ProfileVariant::OnlineStrict, None, vc_skew),
        &m.context(&understood),
    )
}

const fn online(now: u64, iat: u64, skew_ms: u64, horizon_cap_ms: u64) -> Moment {
    Moment {
        now,
        iat,
        skew_ms,
        horizon_cap_ms,
        online: true,
        last_refresh: None,
    }
}

/// The acceptance is exactly `iat ≤ now + skew ∧ now ≤ min(iat + cap, horizon) + skew` over
/// unbounded integers, and every sum that leaves `u64` is `Overflow`, never acceptance.
pub(crate) fn exact(now: u64, iat: u64, cap: u64, horizon: u64, vc_skew: u64, skew: u64) -> bool {
    let r = verdict(&online(now, iat, skew, cap), horizon, vc_skew);
    let s = u128::from(vc_skew.min(skew));
    let (now, iat, cap, horizon) = (
        u128::from(now),
        u128::from(iat),
        u128::from(cap),
        u128::from(horizon),
    );
    let max = u128::from(u64::MAX);
    let until = (iat + cap).min(horizon);
    let overflow = now + s > max || (iat <= now + s && (iat + cap > max || until + s > max));
    if overflow {
        return r == Err(ValidityError::Overflow);
    }
    let accepted = iat <= now + s && now <= until + s;
    r.is_ok() == accepted
}

/// A narrower ceiling or horizon never accepts what the wider one refuses (monotone); where the
/// wider sum leaves `u64` the wider one is `Overflow`, which is a refusal too.
pub(crate) fn narrowing_is_monotone(
    now: u64,
    iat: u64,
    (cap, narrow_cap): (u64, u64),
    (horizon, narrow_horizon): (u64, u64),
    skew: u64,
) -> bool {
    let wide_fits = iat
        .checked_add(cap)
        .and_then(|u| u.min(horizon).checked_add(skew))
        .is_some();
    if narrow_cap > cap || narrow_horizon > horizon || !wide_fits {
        return true;
    }
    let narrow = verdict(&online(now, iat, skew, narrow_cap), narrow_horizon, skew);
    let wide = verdict(&online(now, iat, skew, cap), horizon, skew);
    narrow.is_err() || wide.is_ok()
}

/// The CT2 offline extension never exceeds its ceiling, and the report deadline never wraps.
pub(crate) fn ceilings_hold(declared: u64, horizon: u64) -> bool {
    ct2_offline_extension(declared).horizon_ms <= CT2_OFFLINE_EXTENSION_MS
        && ct2_offline_extension(declared).horizon_ms <= declared
        && report_deadline(horizon) >= horizon
        && (horizon.checked_add(REPORT_GRACE_MS).is_none()
            || report_deadline(horizon) == horizon + REPORT_GRACE_MS)
}

#[cfg(kani)]
mod harness {
    // CR-K1, T20
    #[kani::proof]
    fn k1_acceptance_is_exact_and_overflow_is_refused() {
        assert!(super::exact(
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any()
        ));
    }

    // CR-K1
    #[kani::proof]
    fn k1_narrowing_is_monotone() {
        assert!(super::narrowing_is_monotone(
            kani::any(),
            kani::any(),
            (kani::any(), kani::any()),
            (kani::any(), kani::any()),
            kani::any()
        ));
    }

    // CR-K1, SEC14
    #[kani::proof]
    fn k1_ceilings_hold() {
        assert!(super::ceilings_hold(kani::any(), kani::any()));
    }
}

#[cfg(all(test, not(kani)))]
mod tests {
    use proptest::prelude::*;

    use super::super::edge;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 2048, failure_persistence: None, ..ProptestConfig::default() })]

        // CR-K1, T20
        #[test]
        fn k1_acceptance_is_exact_and_overflow_is_refused(
            now in edge(), iat in edge(), cap in edge(), horizon in edge(), a in edge(), b in edge()
        ) {
            prop_assert!(super::exact(now, iat, cap, horizon, a, b));
        }

        // CR-K1
        #[test]
        fn k1_narrowing_is_monotone(
            now in edge(), iat in edge(), cap in edge(), nc in edge(), h in edge(), nh in edge(), s in edge()
        ) {
            prop_assert!(super::narrowing_is_monotone(now, iat, (cap, nc.min(cap)), (h, nh.min(h)), s));
        }

        // CR-K1, SEC14
        #[test]
        fn k1_ceilings_hold(declared in edge(), horizon in edge()) {
            prop_assert!(super::ceilings_hold(declared, horizon));
        }
    }
}
