#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code"
)]

use super::*;

// TN-146
#[test]
fn the_cancellation_window_is_the_ct3_delay_between_a_day_and_thirty_days() {
    assert_eq!(cancellation_window_s(0), 86_400);
    assert_eq!(cancellation_window_s(3_600), 86_400);
    assert_eq!(cancellation_window_s(86_400), 86_400);
    assert_eq!(cancellation_window_s(3 * 86_400), 3 * 86_400);
    assert_eq!(cancellation_window_s(30 * 86_400), 30 * 86_400);
    assert_eq!(cancellation_window_s(60 * 86_400), 30 * 86_400);
    assert_eq!(cancellation_window_s(u64::MAX), 30 * 86_400);
    assert_eq!(WINDOW_MAX_S / 86_400, u64::try_from(ANSWER_DAYS).unwrap());
}
