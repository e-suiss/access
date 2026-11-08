#![allow(clippy::arithmetic_side_effects, reason = "test fixtures")]

use proptest::prelude::*;

use super::{MS_PER_DAY, Timestamp, civil, days_from_civil};
use crate::schedule::Period;

fn at(y: u64, m: u64, d: u64) -> Timestamp {
    Timestamp::from_unix_millis(days_from_civil(y, m, d).unwrap() * MS_PER_DAY)
}

#[test]
fn civil_dates_match_known_days() {
    assert_eq!(days_from_civil(1970, 1, 1), Some(0));
    assert_eq!(civil(0), Some((1970, 1, 1)));
    assert_eq!(days_from_civil(2000, 3, 1), Some(11_017));
    assert_eq!(civil(19_782), Some((2024, 2, 29)));
    assert_eq!(days_from_civil(1969, 12, 31), None);
}

// OP-147 m.2
#[test]
fn a_missing_day_moves_to_the_next_month() {
    assert_eq!(
        at(2024, 2, 29).checked_add(Period::Years(1)),
        Some(at(2025, 3, 1))
    );
    assert_eq!(
        at(2024, 2, 29).checked_add(Period::Years(4)),
        Some(at(2028, 2, 29))
    );
    assert_eq!(
        at(2025, 1, 31).checked_add(Period::Months(1)),
        Some(at(2025, 3, 1))
    );
    assert_eq!(
        at(2025, 12, 31).checked_add(Period::Months(11)),
        Some(at(2026, 12, 1))
    );
    assert_eq!(
        at(2025, 11, 30).checked_add(Period::Months(1)),
        Some(at(2025, 12, 30))
    );
    assert_eq!(
        at(2025, 3, 31).checked_add(Period::Months(12)),
        Some(at(2026, 3, 31))
    );
    assert_eq!(
        at(2025, 1, 1).checked_add(Period::Days(400)),
        Some(at(2026, 2, 5))
    );
}

// OP-147 m.2, Ek C.2
#[test]
fn year_end_is_the_next_first_of_january() {
    assert_eq!(at(2025, 1, 1).next_year_start(), Some(at(2026, 1, 1)));
    let last_ms = Timestamp::from_unix_millis(at(2026, 1, 1).unix_millis() - 1);
    assert_eq!(last_ms.next_year_start(), Some(at(2026, 1, 1)));
}

#[test]
fn out_of_range_is_none() {
    let max = Timestamp::from_unix_millis(u64::MAX);
    assert_eq!(max.checked_add(Period::Days(1)), None);
    assert_eq!(max.checked_add(Period::Years(u32::MAX)), None);
}

proptest! {
    #[test]
    fn civil_round_trips(days in 0u64..100_000_000) {
        let (y, m, d) = civil(days).unwrap();
        prop_assert!((1..=12).contains(&m));
        prop_assert!(d >= 1 && d <= super::days_in_month(y, m));
        prop_assert_eq!(days_from_civil(y, m, d), Some(days));
    }

    // OP-147 m.2
    #[test]
    fn periods_never_end_early(
        ms in 0u64..10_000_000_000_000,
        n in 0u32..2_000,
    ) {
        let t = Timestamp::from_unix_millis(ms);
        let floor = |days: u64| ms + days * MS_PER_DAY;
        let days = t.checked_add(Period::Days(n)).unwrap().unix_millis();
        prop_assert_eq!(days, floor(u64::from(n)));
        let months = t.checked_add(Period::Months(n)).unwrap().unix_millis();
        prop_assert!(months >= floor(28 * u64::from(n)));
        let years = t.checked_add(Period::Years(n)).unwrap().unix_millis();
        prop_assert!(years >= floor(365 * u64::from(n)));
        prop_assert_eq!(years % MS_PER_DAY, ms % MS_PER_DAY);
        prop_assert!(t.next_year_start().unwrap() > t);
    }
}
