//! CR-K9: the lineage walk of `access_kernel::combinator::evaluate` (SI-20, OP-108 m.10,
//! OP-111 m.7): a lineage deeper than 16 is refused, every lineage up to 16 is decided within
//! the step budget without panic, and a step budget too small is `Fuel`, never a decision.

use access_kernel::combinator::{MAX_LINEAGE, Outcome, Rejection};

use super::{basis, commit, hop};

/// The deepest lineage the harness builds.
pub(crate) const DEEPEST: usize = MAX_LINEAGE + 1;

/// Depth `n` with `fuel` steps: above [`MAX_LINEAGE`] `Input`; otherwise a decision or `Fuel`,
/// and ALLOW on an active, covering lineage when the steps suffice.
pub(crate) fn lineage_walk_terminates(n: usize, fuel: u64) -> bool {
    let n = n.min(DEEPEST);
    match commit(&basis(std::iter::repeat_with(hop).take(n).collect()), fuel) {
        Err(Rejection::Input) => n > MAX_LINEAGE || n == 0,
        Err(Rejection::Fuel) => n <= MAX_LINEAGE && fuel < 10_000,
        Ok(d) => (1..=MAX_LINEAGE).contains(&n) && d.outcome == Outcome::Allow,
    }
}

#[cfg(kani)]
mod harness {
    // CR-K9, SI-20, OP-108 m.10
    #[kani::proof]
    #[kani::unwind(19)]
    fn k9_lineage_of_sixteen_is_decided() {
        let fuel: u64 = kani::any();
        assert!(super::lineage_walk_terminates(super::MAX_LINEAGE, fuel));
    }

    // CR-K9, OP-108 m.10
    #[kani::proof]
    #[kani::unwind(19)]
    fn k9_lineage_of_seventeen_is_refused() {
        assert!(super::lineage_walk_terminates(super::DEEPEST, kani::any()));
    }
}

#[cfg(all(test, not(kani)))]
mod tests {
    use proptest::prelude::*;

    use super::DEEPEST;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        // CR-K9, SI-20, OP-108 m.10, OP-111 m.7
        #[test]
        fn k9_lineage_walk_terminates(n in 0..=DEEPEST, fuel in prop_oneof![0..200u64, 0..20_000u64]) {
            prop_assert!(super::lineage_walk_terminates(n, fuel));
        }
    }
}
