//! Tenant analytics (IDP-36, OP-151 m.3 (n)): daily counters per realm, derived from the
//! sign-in flows, the credentials, the audit log and the risk review queue. Counters only: no
//! identifier, no pseudonym. Never a decision input (TI-18).

/// A failed-login day is a surge when it is more than this many times the day before (PD)...
pub const SURGE_RATIO: u64 = 3;

/// ...and has at least this many failed logins (PD).
pub const SURGE_MIN: u64 = 100;

/// Whether `today` failed logins after `yesterday` is a surge.
#[must_use]
pub const fn surge(yesterday: u64, today: u64) -> bool {
    today >= SURGE_MIN && today > yesterday.saturating_mul(SURGE_RATIO)
}

/// A share in parts per million; `None` when the whole is zero.
#[must_use]
pub fn ppm(part: u64, whole: u64) -> Option<u64> {
    part.checked_mul(1_000_000)?.checked_div(whole)
}

/// The FP budget (OP-151 m.3 (o)): at most 0.5 % of step-up requests marked false positive.
pub const FP_BUDGET_PPM: u64 = 5_000;

#[cfg(test)]
mod tests {
    use super::*;

    // IDP-36
    #[test]
    fn surge_rule() {
        assert!(surge(10, 100));
        assert!(!surge(40, 100));
        assert!(!surge(0, 99));
        assert!(surge(0, 100));
        assert_eq!(ppm(1, 4), Some(250_000));
        assert_eq!(ppm(1, 0), None);
    }
}
