//! CR-K3: slice accounting (TI-RT8, L2-PAP-3 step 5, L2-RPT-3, OP-141 m.28): the demand one use
//! draws never wraps, a stored draw never holds more released than drawn, and an offline
//! report's totals are the exact sums of its `allow` draws.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::intent::ParamValue;
use access_kernel::meta::ExerciseDraw;
use access_kernel::model::Window;
use access_kernel::pap::demand;
use access_kernel::report::{self, Entry, LocalOutcome, Report, ReportError, SliceAmount};

use super::{digest, intent};

const UNITS: [&str; 2] = ["eur", "usd"];

fn unit(second: bool) -> &'static str {
    if second { UNITS[1] } else { UNITS[0] }
}

/// A `count` slice draws one per use; an amount slice draws the sum of the intent's amounts in
/// its unit, and nothing when an amount is negative or the sum leaves `u64`.
pub(crate) fn demand_is_the_checked_sum(amounts: [(i64, bool); 2], asked: bool) -> bool {
    let mut i = intent();
    for (n, (value, second)) in amounts.iter().enumerate() {
        i.params.insert(
            format!("p{n}"),
            ParamValue::Amount {
                value: *value,
                unit: String::from(unit(*second)),
            },
        );
    }
    let mut want: Option<u64> = Some(0);
    for (value, second) in amounts {
        if second == asked {
            want = want.and_then(|w| w.checked_add(u64::try_from(value).ok()?));
        }
    }
    demand("count", &i) == Some(1) && demand(unit(asked), &i) == want
}

/// A stored draw reads back only when `released ≤ drawn`, and then unchanged.
pub(crate) fn release_never_exceeds_draw(drawn: u64, released: u64, counted: bool) -> bool {
    let d = ExerciseDraw {
        key: vec![1, 2, 3],
        drawn,
        released,
        unit: (!counted).then(|| String::from(UNITS[0])),
    };
    match ExerciseDraw::from_value(&d.to_value()) {
        Ok(back) => released <= drawn && back == d,
        Err(_) => released > drawn,
    }
}

/// One report entry: allowed or not, and the term and amount it draws, if any.
pub(crate) type Use = (bool, Option<(bool, u64)>);

fn term(second: bool) -> Digest {
    if second { digest(21) } else { digest(20) }
}

fn report_of(uses: &[Use]) -> Result<Report, ReportError> {
    let (exercise, contract) = (digest(10), digest(11));
    let mut head = report::seed(&exercise, &contract)?;
    let mut entries = Vec::new();
    for (seq, (allow, draw)) in (0u64..).zip(uses) {
        let e = Entry {
            intent: digest(12),
            params: None,
            time: seq,
            clock_evidence: None,
            outcome: if *allow {
                LocalOutcome::Allow
            } else {
                LocalOutcome::Deny
            },
            drawn: draw
                .iter()
                .map(|(second, amount)| SliceAmount {
                    budget_term: term(*second),
                    amount: *amount,
                })
                .collect(),
            holder_proof: None,
        };
        head = report::link(&head, seq, &e)?;
        entries.push(e);
    }
    Ok(Report {
        verifier_profile: digest(13),
        verifier_instance: None,
        exercise,
        contract,
        period: Window {
            from: 0,
            until: u64::MAX,
        },
        previous: None,
        first_seq: 0,
        entries,
        head,
        slice_unused: BTreeSet::new(),
        profile_version: 1,
    })
}

/// A report is accepted exactly when no `deny` entry draws and no total leaves `u64`, and then
/// each total is the sum of the `allow` draws on its term.
pub(crate) fn report_totals_are_exact(uses: &[Use]) -> bool {
    let Ok(r) = report_of(uses) else {
        return false;
    };
    let mut want: BTreeMap<Digest, u128> = BTreeMap::new();
    let mut deny_draws = false;
    for (allow, draw) in uses {
        if let Some((second, amount)) = draw {
            if *allow {
                *want.entry(term(*second)).or_insert(0) += u128::from(*amount);
            } else {
                deny_draws = true;
            }
        }
    }
    let fits = want.values().all(|t| *t <= u128::from(u64::MAX));
    match report::verify(&r) {
        Ok(summary) => {
            !deny_draws
                && fits
                && summary.drawn.len() == want.len()
                && summary
                    .drawn
                    .iter()
                    .all(|(t, n)| want.get(t) == Some(&u128::from(*n)))
        }
        Err(e) => e == ReportError::Entry && (deny_draws || !fits),
    }
}

#[cfg(kani)]
mod harness {
    use access_kernel::digest::Digest;
    use access_kernel::report::{Entry, ReportError};

    fn seed_stub(exercise: &Digest, contract: &Digest) -> Result<Digest, ReportError> {
        Ok(Digest([exercise.0[0] ^ contract.0[0]; 32]))
    }

    fn link_stub(previous: &Digest, seq: u64, _entry: &Entry) -> Result<Digest, ReportError> {
        Ok(Digest([previous.0[0] ^ seq.to_le_bytes()[0]; 32]))
    }

    // CR-K3, L2-PAP-3
    #[kani::proof]
    #[kani::unwind(4)]
    fn k3_demand_is_the_checked_sum() {
        assert!(super::demand_is_the_checked_sum(kani::any(), kani::any()));
    }

    // CR-K3, TI-RT8, OP-141 m.28
    #[kani::proof]
    #[kani::unwind(8)]
    fn k3_release_never_exceeds_draw() {
        assert!(super::release_never_exceeds_draw(
            kani::any(),
            kani::any(),
            kani::any()
        ));
    }

    // CR-K3, L2-RPT-3
    #[kani::proof]
    #[kani::unwind(4)]
    #[kani::stub(access_kernel::report::seed, seed_stub)]
    #[kani::stub(access_kernel::report::link, link_stub)]
    fn k3_report_totals_are_exact() {
        let uses: [super::Use; 2] = kani::any();
        assert!(super::report_totals_are_exact(&uses));
    }
}

#[cfg(all(test, not(kani)))]
mod tests {
    use proptest::prelude::*;

    use super::super::edge;

    fn amount() -> impl Strategy<Value = i64> {
        prop_oneof![-3..=1_000i64, (i64::MAX - 1_000)..=i64::MAX, any::<i64>()]
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 1024, failure_persistence: None, ..ProptestConfig::default() })]

        // CR-K3, L2-PAP-3
        #[test]
        fn k3_demand_is_the_checked_sum(
            a in amount(), b in amount(), ua in any::<bool>(), ub in any::<bool>(), asked in any::<bool>()
        ) {
            prop_assert!(super::demand_is_the_checked_sum([(a, ua), (b, ub)], asked));
        }

        // CR-K3, TI-RT8, OP-141 m.28
        #[test]
        fn k3_release_never_exceeds_draw(drawn in edge(), released in edge(), counted in any::<bool>()) {
            prop_assert!(super::release_never_exceeds_draw(drawn, released, counted));
        }

        // CR-K3, L2-RPT-3
        #[test]
        fn k3_report_totals_are_exact(
            uses in proptest::collection::vec(
                (any::<bool>(), proptest::option::of((any::<bool>(), edge()))),
                0..6,
            )
        ) {
            prop_assert!(super::report_totals_are_exact(&uses));
        }
    }
}
