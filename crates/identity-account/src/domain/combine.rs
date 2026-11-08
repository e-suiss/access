//! Combining two accounts (OP-153 m.3 (m), TN-67): irreversible, so linking is preferred; both
//! accounts of one realm authenticated within five minutes.

/// How fresh each account's last authentication must be to combine them.
pub const COMBINE_FRESHNESS_MS: u64 = 5 * 60_000;

/// Whether two accounts may be combined at `now_ms`: two different accounts, each
/// authenticated within [`COMBINE_FRESHNESS_MS`].
#[must_use]
pub fn combine_allowed(
    survivor: [u8; 16],
    survivor_auth_ms: u64,
    absorbed: [u8; 16],
    absorbed_auth_ms: u64,
    now_ms: u64,
) -> bool {
    let fresh = |at: u64| now_ms.saturating_sub(at) <= COMBINE_FRESHNESS_MS;
    survivor != absorbed && fresh(survivor_auth_ms) && fresh(absorbed_auth_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-153 m.3 (m), TN-67
    #[test]
    fn combining_needs_two_accounts_both_fresh() {
        let (a, b) = ([1; 16], [2; 16]);
        assert!(combine_allowed(a, 1_000, b, 2_000, 300_000));
        assert!(!combine_allowed(a, 1_000, a, 2_000, 300_000));
        assert!(!combine_allowed(a, 0, b, 2_000, 300_001));
        assert!(!combine_allowed(a, 300_000, b, 0, 300_001));
    }
}
