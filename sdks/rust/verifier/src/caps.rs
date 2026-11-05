//! Connectivity ceilings (§13.7.2, PD; §9.10 step 2; T20, U25, CR-K1): the local acceptance
//! ceilings a conformant verifier applies by connectivity variant and consequence tier,
//! whatever the artefact declares.

use access_kernel::tier::{self, Tier};
use access_kernel::validity::ProfileVariant;

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
/// The clock source class a CT1 `checkpointed-offline` verifier declares (§13.7.2).
pub const SECURE_CLOCK_CLASS: &str = "monotonic_signed";

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
/// hardware duties as CT1 (§13.7.2).
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
