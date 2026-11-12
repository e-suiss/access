//! CR-K5: the `N_cited` comparison of the rollback guard, `access_kernel::fold::rollback_guard`
//! (T19, SEC21, SEC22, §13.6): a recovery citing `N` below `R*` is refused, an accepted one is
//! bound to the cited `N` and to a root a witness co-signed at that size.

use access_kernel::fold::{Guard, GuardError, WitnessHead, rollback_guard};

/// The most declared witnesses the harness takes.
pub(crate) const WITNESSES: usize = 3;

/// One declared witness: whether a Claim was ingested, its size, a root label and its age.
pub(crate) type Head = (bool, u64, bool, u64);

const fn root(second: bool) -> [u8; 32] {
    if second { [0xb2; 32] } else { [0xa1; 32] }
}

/// The guard's verdict, checked against SEC21 and SEC22.
pub(crate) fn guard_is_bound_to_n(
    heads: [Head; WITNESSES],
    declared: usize,
    replica: Option<u64>,
    (n, n_root): (u64, bool),
    fork: bool,
    now: u64,
) -> bool {
    let declared = declared.min(WITNESSES);
    let Some(heads) = heads.get(..declared) else {
        return false;
    };
    let heads: Vec<Option<WitnessHead>> = heads
        .iter()
        .map(|&(ingested, size, second, age)| {
            ingested.then(|| WitnessHead::new(size, root(second), now.saturating_sub(age)))
        })
        .collect();
    let fresh: Vec<&WitnessHead> = heads
        .iter()
        .flatten()
        .filter(|h| h.at <= now && now - h.at <= access_kernel::fold::WITNESS_FRESHNESS_MS)
        .collect();
    let highest = fresh.iter().map(|h| h.size).max();
    let cosigned_at_n: Vec<[u8; 32]> = fresh
        .iter()
        .filter(|h| h.size == n)
        .map(|h| h.root)
        .collect();
    match rollback_guard(&heads, replica, (n, root(n_root)), fork, now) {
        Ok(g) => {
            let Some(highest) = highest else {
                return false;
            };
            let bound = n <= highest
                && replica.is_none_or(|r| n >= r)
                && (cosigned_at_n.is_empty() || cosigned_at_n.contains(&root(n_root)));
            bound
                && match g {
                    Guard::Pass => replica == Some(n) && n == highest && fresh.len() == heads.len(),
                    Guard::Lossy { from, until } => from == n && until == highest,
                    _ => false,
                }
        }
        Err(GuardError::Rollback) => replica.is_some_and(|r| n < r),
        Err(_) => true,
    }
}

/// Below `R*` is never accepted, whatever else holds.
pub(crate) fn below_r_star_is_refused(
    heads: [Head; WITNESSES],
    declared: usize,
    r: u64,
    (n, n_root): (u64, bool),
    fork: bool,
    now: u64,
) -> bool {
    if n >= r {
        return true;
    }
    let declared = declared.min(WITNESSES);
    let Some(heads) = heads.get(..declared) else {
        return false;
    };
    let heads: Vec<Option<WitnessHead>> = heads
        .iter()
        .map(|&(i, size, second, age)| {
            i.then(|| WitnessHead::new(size, root(second), now.saturating_sub(age)))
        })
        .collect();
    rollback_guard(&heads, Some(r), (n, root(n_root)), fork, now).is_err()
}

#[cfg(kani)]
mod harness {
    // CR-K5, SEC21, SEC22, T19
    #[kani::proof]
    #[kani::unwind(5)]
    fn k5_guard_is_bound_to_n_cited() {
        assert!(super::guard_is_bound_to_n(
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any()
        ));
    }

    // CR-K5, SEC21
    #[kani::proof]
    #[kani::unwind(5)]
    fn k5_below_r_star_is_refused() {
        assert!(super::below_r_star_is_refused(
            kani::any(),
            kani::any(),
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

    use super::{Head, WITNESSES};

    fn head() -> impl Strategy<Value = Head> {
        (any::<bool>(), 0..8u64, any::<bool>(), 0..5_000_000u64)
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 4096, failure_persistence: None, ..ProptestConfig::default() })]

        // CR-K5, SEC21, SEC22, T19
        #[test]
        fn k5_guard_is_bound_to_n_cited(
            heads in proptest::array::uniform3(head()), declared in 0..=WITNESSES,
            replica in proptest::option::of(0..8u64), n in 0..9u64, nr in any::<bool>(),
            fork in any::<bool>(), now in 0..10_000_000u64
        ) {
            prop_assert!(super::guard_is_bound_to_n(heads, declared, replica, (n, nr), fork, now));
        }

        // CR-K5, SEC21
        #[test]
        fn k5_below_r_star_is_refused(
            heads in proptest::array::uniform3(head()), declared in 0..=WITNESSES,
            r in 0..8u64, n in 0..9u64, nr in any::<bool>(), fork in any::<bool>(),
            now in 0..10_000_000u64
        ) {
            prop_assert!(super::below_r_star_is_refused(heads, declared, r, (n, nr), fork, now));
        }
    }
}
