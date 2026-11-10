//! What a risk signal may do (CI-2, E38, TN-46, OP-156 m.3 (r)): the set is closed and every
//! member narrows. A risk level never allows, never widens and never locks for good: a risk
//! Claim counts for at most [`access_internal_api::signals::RISK_HORIZON_MS`] after its issue,
//! and the domain lifts it sooner by an attributable Exercise that ends its Acceptance. A lost
//! or late signal is no signal, and no signal is never a reason to allow.

use access_internal_api::signals::RiskLevel;

/// The narrowing a risk level suggests to the identity plane; the authority plane reads the
/// level only through the domain's forbid-only restriction policies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Narrowing {
    /// Nothing changes.
    None,
    /// One more step is asked for (`REQUIRE`).
    Require,
    /// The request is refused (`DENY`).
    Deny,
    /// Refused, and a containment is put in front of a person; a person performs it as an
    /// attributable, narrowing Exercise.
    Contain,
}

/// The narrowing of `level`, `None` when no signal is known.
#[must_use]
pub const fn narrowing(level: Option<RiskLevel>) -> Narrowing {
    match level {
        None | Some(RiskLevel::Low) => Narrowing::None,
        Some(RiskLevel::Medium) => Narrowing::Require,
        Some(RiskLevel::High) => Narrowing::Deny,
        Some(RiskLevel::Critical) => Narrowing::Contain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CI-2, TN-46
    #[test]
    fn a_risk_level_only_narrows_and_never_holds_for_good() {
        assert_eq!(narrowing(None), Narrowing::None);
        assert_eq!(narrowing(Some(RiskLevel::Low)), Narrowing::None);
        assert_eq!(narrowing(Some(RiskLevel::High)), Narrowing::Deny);
        for l in RiskLevel::ALL {
            assert!(narrowing(Some(l)) >= Narrowing::None);
        }
        assert_eq!(
            access_internal_api::signals::RISK_HORIZON_MS,
            24 * 3_600 * 1_000
        );
    }
}
