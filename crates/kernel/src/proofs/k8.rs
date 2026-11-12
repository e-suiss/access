//! CR-K8: the budget counter of a decision, `access_kernel::combinator::evaluate` (CR-36,
//! L0-EVAL-15, OP-114 m.11): what a window allows never exceeds its remaining budget, and a
//! rolling window that cannot say when it frees capacity is an input error.

use access_kernel::combinator::{BlockerClass, BudgetState, Outcome, Rejection};
use access_kernel::model::BudgetWindow;

use super::{basis, commit, hop};

/// The most budget terms on the hop.
pub(crate) const TERMS: usize = 2;

/// One budget term: rolling or total, remaining, demand and whether a reset time is known.
pub(crate) type Term = (bool, u64, u64, bool);

/// ALLOW exactly when every demand fits its remaining budget; an unfitting rolling window
/// without a reset time is `Input`, any other unfitting window a `budget-exhausted` DENY.
pub(crate) fn allowed_never_exceeds_budget(terms: [Term; TERMS], used: usize) -> bool {
    let used = used.min(TERMS);
    let Some(terms) = terms.get(..used) else {
        return false;
    };
    let mut h = hop();
    h.budgets = terms
        .iter()
        .map(|&(rolling, remaining, demand, resets)| BudgetState {
            window: if rolling {
                BudgetWindow::RollingSeconds(60)
            } else {
                BudgetWindow::Total
            },
            remaining,
            demand,
            resets_at: resets.then_some(70_000),
        })
        .collect();
    let over = |&(_, remaining, demand, _): &Term| demand > remaining;
    let unresettable = terms.iter().any(|t| over(t) && t.0 && !t.3);
    let exceeded = terms.iter().any(over);
    match commit(&basis(vec![h]), 10_000) {
        Err(Rejection::Input) => unresettable,
        Err(_) => false,
        Ok(d) => {
            !unresettable
                && (d.outcome == Outcome::Allow) != exceeded
                && (!exceeded
                    || d.blockers
                        .iter()
                        .any(|b| b.class == BlockerClass::BudgetExhausted))
        }
    }
}

#[cfg(kani)]
mod harness {
    // CR-K8, CR-36, L0-EVAL-15
    #[kani::proof]
    #[kani::unwind(6)]
    fn k8_allowed_never_exceeds_budget() {
        assert!(super::allowed_never_exceeds_budget(
            kani::any(),
            kani::any()
        ));
    }
}

#[cfg(all(test, not(kani)))]
mod tests {
    use proptest::prelude::*;

    use super::super::edge;
    use super::TERMS;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 1024, failure_persistence: None, ..ProptestConfig::default() })]

        // CR-K8, CR-36, L0-EVAL-15
        #[test]
        fn k8_allowed_never_exceeds_budget(
            terms in proptest::array::uniform2(
                (any::<bool>(), edge(), edge(), any::<bool>())
            ),
            used in 0..=TERMS
        ) {
            prop_assert!(super::allowed_never_exceeds_budget(terms, used));
        }
    }
}
