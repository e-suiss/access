//! Certificate lifetime and renewal (OP-156 m.3 (i)): an ACME certificate of 90 days is renewed
//! when 30 days remain; a failed order is tried again after a growing pause.

/// The lifetime Access asks for and expects: 90 days.
pub const LIFETIME_S: i64 = 90 * 86_400;

/// Renewal starts when this much validity remains: 30 days.
pub const RENEW_BEFORE_S: i64 = 30 * 86_400;

/// First pause after a failed order (PD).
pub const RETRY_FIRST_S: i64 = 300;

/// Longest pause after failed orders (PD): a day, well inside Let's Encrypt's failed
/// validation limit.
pub const RETRY_MAX_S: i64 = 86_400;

/// When a certificate valid `not_before..not_after` is renewed: 30 days before its end, or at a
/// third of its life when it is shorter than 90 days.
#[must_use]
pub fn renew_after(not_before: i64, not_after: i64) -> i64 {
    let life = not_after.saturating_sub(not_before).max(0);
    let before = RENEW_BEFORE_S.min(life.checked_div(3).unwrap_or(0));
    not_after.saturating_sub(before)
}

/// The pause after the `failures`-th consecutive failed order.
#[must_use]
pub fn retry_after(failures: u32) -> i64 {
    let shift = failures.saturating_sub(1).min(16);
    RETRY_FIRST_S
        .checked_shl(shift)
        .unwrap_or(RETRY_MAX_S)
        .min(RETRY_MAX_S)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-156 m.3 (i)
    #[test]
    fn a_ninety_day_certificate_renews_with_thirty_days_left() {
        assert_eq!(renew_after(0, LIFETIME_S), LIFETIME_S - RENEW_BEFORE_S);
        assert_eq!(renew_after(0, 6 * 86_400), 4 * 86_400);
        assert_eq!(retry_after(1), RETRY_FIRST_S);
        assert_eq!(retry_after(2), 2 * RETRY_FIRST_S);
        assert_eq!(retry_after(40), RETRY_MAX_S);
    }
}
