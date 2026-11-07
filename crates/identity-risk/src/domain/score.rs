//! Score to level (TN-46, PD values of OP-151 m.3 (o)): a deterministic table, the sum of the
//! fired signals' weights.
//!
//! | Score | Level |
//! |---|---|
//! | 0–29 | `low` |
//! | 30–59 | `medium` |
//! | 60 and above | `high` |
//!
//! When a source could not answer and nothing fired, the level is `unavailable`: it is never
//! read as `low` (MD-8).

use std::collections::BTreeSet;

use access_identity_account::domain::signal::RiskLevel;

use crate::domain::signal::RiskSignal;

/// The lowest `medium` score.
pub const MEDIUM_AT: u32 = 30;
/// The lowest `high` score.
pub const HIGH_AT: u32 = 60;

/// An SL2 level, the value of the `risk_level` Claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// A source could not answer and nothing fired: the engine says nothing (MD-8).
    Unavailable,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
}

impl Level {
    /// The Claim value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// The level of a name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Unavailable, Self::Low, Self::Medium, Self::High]
            .into_iter()
            .find(|l| l.name() == name)
    }

    /// The CAEP level; `unavailable` has none and is never signalled.
    #[must_use]
    pub const fn caep(self) -> Option<RiskLevel> {
        match self {
            Self::Unavailable => None,
            Self::Low => Some(RiskLevel::Low),
            Self::Medium => Some(RiskLevel::Medium),
            Self::High => Some(RiskLevel::High),
        }
    }
}

/// The score of `signals`.
#[must_use]
pub fn score(signals: &BTreeSet<RiskSignal>) -> u32 {
    signals
        .iter()
        .fold(0_u32, |s, x| s.saturating_add(x.weight()))
}

/// The level of `signals`; `complete` is false when a source could not answer.
#[must_use]
pub fn level(signals: &BTreeSet<RiskSignal>, complete: bool) -> Level {
    let s = score(signals);
    if s >= HIGH_AT {
        Level::High
    } else if s >= MEDIUM_AT {
        Level::Medium
    } else if complete {
        Level::Low
    } else {
        Level::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(s: &[RiskSignal]) -> BTreeSet<RiskSignal> {
        s.iter().copied().collect()
    }

    // TN-46, OP-151 m.3 (o): the documented table, deterministic
    #[test]
    fn the_table() {
        use RiskSignal::*;
        assert_eq!(level(&set(&[]), true), Level::Low);
        assert_eq!(level(&set(&[NewDevice]), true), Level::Low);
        assert_eq!(level(&set(&[BruteForce]), true), Level::Medium);
        assert_eq!(level(&set(&[SuspiciousIp]), true), Level::Medium);
        assert_eq!(level(&set(&[BreachedPassword]), true), Level::Medium);
        assert_eq!(level(&set(&[NewDevice, SuspiciousIp]), true), Level::High);
        assert_eq!(level(&set(&[ImpossibleTravel]), true), Level::High);
        assert_eq!(level(&set(&[CanaryHit]), true), Level::High);
        assert_eq!(score(&set(&RiskSignal::ALL)), 290);
    }

    // MD-8: a missing source with nothing fired is unavailable, never low; what fired still
    // counts
    #[test]
    fn missing_sources_are_not_low() {
        assert_eq!(level(&set(&[]), false), Level::Unavailable);
        assert_eq!(
            level(&set(&[RiskSignal::NewDevice]), false),
            Level::Unavailable
        );
        assert_eq!(
            level(&set(&[RiskSignal::BreachedPassword]), false),
            Level::Medium
        );
        assert_eq!(Level::Unavailable.caep(), None);
        for l in [Level::Unavailable, Level::Low, Level::Medium, Level::High] {
            assert_eq!(Level::parse(l.name()), Some(l));
        }
    }
}
