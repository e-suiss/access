//! Connectivity ceilings (§13.7.2, PD; §9.10 step 2; T20, U25, CR-K1): the acceptance ceilings
//! by connectivity variant and consequence tier. The issuer applies them to every
//! `projection.issue` and a conformant verifier applies them locally, whatever the artefact
//! declares; both sides read this one table.

use crate::tier::{self, Tier};
use crate::validity::ProfileVariant;

/// One minute in milliseconds.
pub const MINUTE_MS: u64 = 60_000;
/// One hour in milliseconds.
pub const HOUR_MS: u64 = 60 * MINUTE_MS;

/// Domain Metadata freshness when the contract declares no Δ (§13.7.2, TI-RT5).
pub const METADATA_FRESHNESS_MS: u64 = HOUR_MS;
/// Offline report delivery ceiling after the horizon (§13.7.2, SEC14).
pub const REPORT_GRACE_MS: u64 = 24 * HOUR_MS;
/// Horizon of a CT2 exact-intent token on the `online-strict` variant (§13.7.2, EP-7).
pub const EXACT_INTENT_HORIZON_MS: u64 = 5 * MINUTE_MS;
/// Horizon of a CT2 `checkpointed-offline` contract under an explicit domain extension
/// (§13.7.2).
pub const CT2_OFFLINE_EXTENSION_MS: u64 = 4 * HOUR_MS;
/// The clock source class a CT1 `checkpointed-offline` verifier declares (§13.7.2, OP-150
/// m.7 (b)).
pub const SECURE_CLOCK_CLASS: &str = "monotonic_signed";
/// The share of the narrowest lineage budget term a CT1 `checkpointed-offline` slice may take,
/// as a divisor: one tenth (§13.7.2).
pub const SLICE_SHARE_DIVISOR: u64 = 10;

/// The ceilings of one variant at one tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ceiling {
    /// Longest acceptance after `iat`, in milliseconds.
    pub horizon_ms: u64,
    /// Longest Δ (`max_staleness_ms`), for `bounded-staleness`.
    pub staleness_ms: Option<u64>,
    /// Longest checkpoint interval (`checkpoint_ms` parameter), for
    /// `checkpoint-continuation`; `Some(0)` means every consequential step.
    pub checkpoint_ms: Option<u64>,
    /// The verifier must declare a tamper-evident counter, a secure clock and hardware
    /// attestation.
    pub hardware: bool,
}

const fn horizon(horizon_ms: u64) -> Ceiling {
    Ceiling {
        horizon_ms,
        staleness_ms: None,
        checkpoint_ms: None,
        hardware: false,
    }
}

/// The ceilings of `variant` at `tier` (§13.7.2), or `None` where the policy default allows no
/// projection of that variant. A CT2 `checkpointed-offline` contract exists only under an
/// explicit domain extension ([`ct2_offline_extension`]).
#[must_use]
pub const fn policy(variant: ProfileVariant, tier: Tier) -> Option<Ceiling> {
    let day = 24 * HOUR_MS;
    match (variant, tier) {
        (ProfileVariant::OnlineStrict, Tier::Ct0 | Tier::Ct1) => {
            Some(horizon(tier::validity_ceiling(tier)))
        }
        (ProfileVariant::OnlineStrict, Tier::Ct2) => Some(horizon(EXACT_INTENT_HORIZON_MS)),
        (ProfileVariant::BoundedStaleness, Tier::Ct0) => Some(Ceiling {
            staleness_ms: Some(15 * MINUTE_MS),
            ..horizon(day)
        }),
        (ProfileVariant::BoundedStaleness, Tier::Ct1) => Some(Ceiling {
            staleness_ms: Some(5 * MINUTE_MS),
            ..horizon(8 * HOUR_MS)
        }),
        (ProfileVariant::RevalidateOnReconnect, Tier::Ct0) => Some(horizon(day)),
        (ProfileVariant::RevalidateOnReconnect, Tier::Ct1) => Some(horizon(8 * HOUR_MS)),
        (ProfileVariant::CheckpointedOffline, Tier::Ct0) => Some(horizon(72 * HOUR_MS)),
        (ProfileVariant::CheckpointedOffline, Tier::Ct1) => Some(Ceiling {
            hardware: true,
            ..horizon(day)
        }),
        (ProfileVariant::CheckpointContinuation, Tier::Ct0) => Some(Ceiling {
            checkpoint_ms: Some(HOUR_MS),
            ..horizon(day)
        }),
        (ProfileVariant::CheckpointContinuation, Tier::Ct1) => Some(Ceiling {
            checkpoint_ms: Some(15 * MINUTE_MS),
            ..horizon(8 * HOUR_MS)
        }),
        (ProfileVariant::CheckpointContinuation, Tier::Ct2) => Some(Ceiling {
            checkpoint_ms: Some(0),
            ..horizon(2 * HOUR_MS)
        }),
        _ => None,
    }
}

/// The CT2 `checkpointed-offline` ceiling when the domain declares a CT2 horizon in its
/// Domain Metadata ceilings: at most [`CT2_OFFLINE_EXTENSION_MS`], one verifier, with the same
/// hardware duties as CT1 (§13.7.2, OP-150 m.7 (c)).
#[must_use]
pub const fn ct2_offline_extension(declared_ms: u64) -> Ceiling {
    let horizon_ms = if declared_ms < CT2_OFFLINE_EXTENSION_MS {
        declared_ms
    } else {
        CT2_OFFLINE_EXTENSION_MS
    };
    Ceiling {
        hardware: true,
        ..horizon(horizon_ms)
    }
}

/// Clock skew tolerance by tier (§13.7.2, C33).
#[must_use]
pub const fn skew_ms(tier: Tier) -> u64 {
    match tier {
        Tier::Ct0 | Tier::Ct1 => 2 * MINUTE_MS,
        Tier::Ct2 | Tier::Ct3 => MINUTE_MS,
    }
}

/// The tier as the `cap_horizon` and Domain Metadata ceilings key it.
#[must_use]
pub const fn ct(tier: Tier) -> u8 {
    match tier {
        Tier::Ct0 => 0,
        Tier::Ct1 => 1,
        Tier::Ct2 => 2,
        Tier::Ct3 => 3,
    }
}

/// The last moment an offline report for a contract with `horizon` is on time (SEC14).
#[must_use]
pub const fn report_deadline(horizon: u64) -> u64 {
    horizon.saturating_add(REPORT_GRACE_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    // §13.7.2
    #[test]
    fn the_table_closes_ct3_and_most_of_ct2() {
        for v in [
            ProfileVariant::OnlineStrict,
            ProfileVariant::BoundedStaleness,
            ProfileVariant::RevalidateOnReconnect,
            ProfileVariant::CheckpointedOffline,
            ProfileVariant::CheckpointContinuation,
        ] {
            assert_eq!(policy(v, Tier::Ct3), None);
        }
        assert_eq!(policy(ProfileVariant::BoundedStaleness, Tier::Ct2), None);
        assert_eq!(policy(ProfileVariant::CheckpointedOffline, Tier::Ct2), None);
        assert_eq!(
            policy(ProfileVariant::OnlineStrict, Tier::Ct2).map(|c| c.horizon_ms),
            Some(EXACT_INTENT_HORIZON_MS)
        );
        assert_eq!(
            policy(ProfileVariant::CheckpointedOffline, Tier::Ct1).map(|c| c.hardware),
            Some(true)
        );
    }

    // §13.7.2, OP-150 m.7 (c)
    #[test]
    fn the_ct2_offline_extension_is_capped() {
        assert_eq!(ct2_offline_extension(HOUR_MS).horizon_ms, HOUR_MS);
        assert_eq!(
            ct2_offline_extension(9 * HOUR_MS).horizon_ms,
            CT2_OFFLINE_EXTENSION_MS
        );
        assert!(ct2_offline_extension(HOUR_MS).hardware);
        assert_eq!(report_deadline(10), 10 + REPORT_GRACE_MS);
    }

    // §13.7.2, OP-150 m.7 (c)
    #[test]
    fn the_ct2_offline_extension_keeps_a_declared_horizon_up_to_four_hours() {
        assert_eq!(ct2_offline_extension(14_400_000).horizon_ms, 14_400_000);
        assert_eq!(ct2_offline_extension(14_399_999).horizon_ms, 14_399_999);
        assert_eq!(ct2_offline_extension(14_400_001).horizon_ms, 14_400_000);
    }

    // §13.7.2, TI-RT5, SEC14, EP-7
    #[test]
    fn the_default_durations_are_the_policy_values() {
        assert_eq!(MINUTE_MS, 60_000);
        assert_eq!(HOUR_MS, 3_600_000);
        assert_eq!(METADATA_FRESHNESS_MS, 3_600_000);
        assert_eq!(REPORT_GRACE_MS, 86_400_000);
        assert_eq!(EXACT_INTENT_HORIZON_MS, 300_000);
        assert_eq!(CT2_OFFLINE_EXTENSION_MS, 14_400_000);
        assert_eq!(report_deadline(1_000), 86_401_000);
        assert_eq!(report_deadline(u64::MAX), u64::MAX);
    }

    fn row(horizon_ms: u64, staleness_ms: Option<u64>, checkpoint_ms: Option<u64>) -> Ceiling {
        Ceiling {
            horizon_ms,
            staleness_ms,
            checkpoint_ms,
            hardware: false,
        }
    }

    // §13.7.2, T20, U25, CR-K1
    #[test]
    fn every_open_cell_matches_the_connectivity_table() {
        const M: u64 = 60_000;
        const H: u64 = 3_600_000;
        let cases = [
            (
                ProfileVariant::OnlineStrict,
                Tier::Ct0,
                row(24 * H, None, None),
            ),
            (
                ProfileVariant::OnlineStrict,
                Tier::Ct1,
                row(24 * H, None, None),
            ),
            (
                ProfileVariant::OnlineStrict,
                Tier::Ct2,
                row(5 * M, None, None),
            ),
            (
                ProfileVariant::BoundedStaleness,
                Tier::Ct0,
                row(24 * H, Some(15 * M), None),
            ),
            (
                ProfileVariant::BoundedStaleness,
                Tier::Ct1,
                row(8 * H, Some(5 * M), None),
            ),
            (
                ProfileVariant::RevalidateOnReconnect,
                Tier::Ct0,
                row(24 * H, None, None),
            ),
            (
                ProfileVariant::RevalidateOnReconnect,
                Tier::Ct1,
                row(8 * H, None, None),
            ),
            (
                ProfileVariant::CheckpointedOffline,
                Tier::Ct0,
                row(72 * H, None, None),
            ),
            (
                ProfileVariant::CheckpointedOffline,
                Tier::Ct1,
                Ceiling {
                    hardware: true,
                    ..row(24 * H, None, None)
                },
            ),
            (
                ProfileVariant::CheckpointContinuation,
                Tier::Ct0,
                row(24 * H, None, Some(60 * M)),
            ),
            (
                ProfileVariant::CheckpointContinuation,
                Tier::Ct1,
                row(8 * H, None, Some(15 * M)),
            ),
            (
                ProfileVariant::CheckpointContinuation,
                Tier::Ct2,
                row(2 * H, None, Some(0)),
            ),
        ];
        for (variant, tier, want) in cases {
            assert_eq!(policy(variant, tier), Some(want), "{variant:?} {tier:?}");
        }
    }

    // §13.7.2, C33
    #[test]
    fn the_skew_tolerance_narrows_with_the_tier() {
        assert_eq!(skew_ms(Tier::Ct0), 120_000);
        assert_eq!(skew_ms(Tier::Ct1), 120_000);
        assert_eq!(skew_ms(Tier::Ct2), 60_000);
        assert_eq!(skew_ms(Tier::Ct3), 60_000);
    }

    // §13.7.2, T20
    #[test]
    fn each_tier_has_its_own_ceiling_key() {
        assert_eq!(
            [Tier::Ct0, Tier::Ct1, Tier::Ct2, Tier::Ct3].map(ct),
            [0, 1, 2, 3]
        );
    }
}
