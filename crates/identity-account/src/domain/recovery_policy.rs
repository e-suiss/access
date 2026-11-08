//! The realm's account recovery policy (`idp.account.recovery_policy`, OP-153 m.3 (a), (e),
//! (f); TN-55, TN-61, TN-62): the cooling table, temporary access passes and reset intents, and
//! the rule that a change which loosens any of them is `idp.account.recovery_policy_loosen`
//! (CT3) and never goes below the floor of OP-153 m.3 (e). The identity plane reads it; the
//! management API's Exercises write it.

use serde::{Deserialize, Serialize};

use crate::domain::claim_classes::RecoveryPath;

const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 86_400_000;

/// OP-153 m.3 (f), TN-61: a reset intent lives one hour by default and never past 24.
pub const INTENT_TTL_MS: u64 = HOUR_MS;

/// TN-61: the longest reset intent.
pub const INTENT_TTL_MAX_MS: u64 = DAY_MS;

/// TN-62: a temporary access pass lives one hour by default, between 10 minutes and 30 days.
pub const TAP_TTL_MS: u64 = HOUR_MS;

/// TN-62: the shortest pass.
pub const TAP_TTL_MIN_MS: u64 = 10 * MINUTE_MS;

/// TN-62: the longest pass.
pub const TAP_TTL_MAX_MS: u64 = 30 * DAY_MS;

/// TN-62: a pass is 16 characters by default, between 8 and 48.
pub const TAP_LENGTH: usize = 16;

/// TN-62: the shortest pass.
pub const TAP_LENGTH_MIN: usize = 8;

/// TN-62: the longest pass.
pub const TAP_LENGTH_MAX: usize = 48;

/// TN-55, OP-153 m.3 (e): the identity plane's cooling table, inversely proportional to the
/// strength of the evidence and sensitive to risk. It is never shortened for one case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoolingTable {
    /// A registered recovery code.
    pub registered_code_ms: u64,
    /// An e-mail code alone, or a recovery contact alone.
    pub sent_code_ms: u64,
    /// Two channels.
    pub two_channels_ms: u64,
    /// Two channels at medium or high risk.
    pub two_channels_risky_ms: u64,
    /// Identity re-proofing.
    pub reproofing_ms: u64,
    /// A temporary access pass or a reset intent: approved out of band.
    pub out_of_band_ms: u64,
    /// A high-value account, whatever the method (at least).
    pub high_value_ms: u64,
}

impl CoolingTable {
    /// OP-153 m.3 (e).
    pub const DEFAULT: Self = Self {
        registered_code_ms: 0,
        sent_code_ms: DAY_MS,
        two_channels_ms: 4 * HOUR_MS,
        two_channels_risky_ms: DAY_MS,
        reproofing_ms: HOUR_MS,
        out_of_band_ms: 0,
        high_value_ms: DAY_MS,
    };

    fn entries(&self) -> [u64; 7] {
        [
            self.registered_code_ms,
            self.sent_code_ms,
            self.two_channels_ms,
            self.two_channels_risky_ms,
            self.reproofing_ms,
            self.out_of_band_ms,
            self.high_value_ms,
        ]
    }

    /// Whether every entry is at least `other`'s.
    #[must_use]
    pub fn at_least(&self, other: &Self) -> bool {
        self.entries()
            .iter()
            .zip(other.entries())
            .all(|(a, b)| *a >= b)
    }

    /// The cooling of an attempt that spent `evidence`: risky two channels wait longer; a
    /// high-value account waits at least its entry (OP-153 m.3 (e)).
    #[must_use]
    pub fn cooling(&self, evidence: &[RecoveryPath], risky: bool, high_value: bool) -> u64 {
        let mut distinct: Vec<RecoveryPath> = Vec::new();
        for e in evidence {
            if !distinct.contains(e) {
                distinct.push(*e);
            }
        }
        let channels: Vec<RecoveryPath> = distinct
            .iter()
            .copied()
            .filter(|p| *p != RecoveryPath::SecondAuthenticator)
            .collect();
        let base = if distinct.iter().any(|p| {
            matches!(
                p,
                RecoveryPath::ResetIntent | RecoveryPath::TemporaryAccessPass
            )
        }) {
            self.out_of_band_ms
        } else if distinct.contains(&RecoveryPath::IdentityReproofing) {
            self.reproofing_ms
        } else if channels.len() >= 2 {
            if risky {
                self.two_channels_risky_ms
            } else {
                self.two_channels_ms
            }
        } else if channels == [RecoveryPath::RegisteredCode] {
            self.registered_code_ms
        } else {
            self.sent_code_ms
        };
        if high_value {
            base.max(self.high_value_ms)
        } else {
            base
        }
    }
}

/// The realm's recovery policy (`idp.account.recovery_policy`, OP-153 m.3 (a), (e), (f)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicy {
    /// The cooling table.
    pub cooling: CoolingTable,
    /// Whether temporary access passes exist (TN-62: only if the realm opts in).
    pub tap: bool,
    /// A pass's default lifetime.
    pub tap_ttl_ms: u64,
    /// A pass's default length.
    pub tap_length: usize,
    /// A reset intent's default lifetime.
    pub intent_ttl_ms: u64,
    /// The extra AAL level (1 to 3) a rebind needs beyond the account's own, if the domain asks
    /// for one (§10.1.3: tighten only).
    pub rebind_aal: Option<u8>,
}

/// Why a recovery policy is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyRefusal {
    /// A value is outside its range, or below the floor of OP-153 m.3 (e).
    #[error("recovery policy out of range")]
    OutOfRange,
    /// The change loosens recovery: `idp.account.recovery_policy_loosen` (CT3, TN-55).
    #[error("recovery policy loosens")]
    Loosens,
}

impl RecoveryPolicy {
    /// OP-153 m.3 (e), (f): the default table, no passes, one-hour intents.
    pub const DEFAULT: Self = Self {
        cooling: CoolingTable::DEFAULT,
        tap: false,
        tap_ttl_ms: TAP_TTL_MS,
        tap_length: TAP_LENGTH,
        intent_ttl_ms: INTENT_TTL_MS,
        rebind_aal: None,
    };

    /// Checks the ranges: no entry below the m.3 (e) floor (a domain never loosens below it,
    /// §10.1.3), pass and intent values inside TN-61/TN-62.
    ///
    /// # Errors
    /// [`PolicyRefusal::OutOfRange`].
    pub fn validate(&self) -> Result<(), PolicyRefusal> {
        let ok = self.cooling.at_least(&CoolingTable::DEFAULT)
            && (TAP_TTL_MIN_MS..=TAP_TTL_MAX_MS).contains(&self.tap_ttl_ms)
            && (TAP_LENGTH_MIN..=TAP_LENGTH_MAX).contains(&self.tap_length)
            && (1..=INTENT_TTL_MAX_MS).contains(&self.intent_ttl_ms)
            && self.cooling.entries().iter().all(|e| *e <= 30 * DAY_MS)
            && self.rebind_aal.is_none_or(|a| (1..=3).contains(&a));
        if ok {
            Ok(())
        } else {
            Err(PolicyRefusal::OutOfRange)
        }
    }

    /// Whether moving from `current` to `self` loosens recovery anywhere: a shorter cooling,
    /// passes turned on or longer, longer intents, or a lower rebind term (TN-55).
    #[must_use]
    pub fn loosens(&self, current: &Self) -> bool {
        !self.cooling.at_least(&current.cooling)
            || (self.tap && !current.tap)
            || self.tap_ttl_ms > current.tap_ttl_ms
            || self.tap_length < current.tap_length
            || self.intent_ttl_ms > current.intent_ttl_ms
            || self.rebind_aal < current.rebind_aal
    }

    /// The change under the action it needs: `Ok(false)` tightens (CT1), `Ok(true)` loosens
    /// (CT3).
    ///
    /// # Errors
    /// [`PolicyRefusal::OutOfRange`].
    pub fn change(&self, current: &Self) -> Result<bool, PolicyRefusal> {
        self.validate()?;
        Ok(self.loosens(current))
    }

    /// The stored bytes.
    ///
    /// # Errors
    /// [`PolicyRefusal::OutOfRange`] when it cannot be encoded.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PolicyRefusal> {
        serde_json::to_vec(self).map_err(|_| PolicyRefusal::OutOfRange)
    }

    /// The policy of stored bytes.
    ///
    /// # Errors
    /// [`PolicyRefusal::OutOfRange`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PolicyRefusal> {
        let p: Self = serde_json::from_slice(bytes).map_err(|_| PolicyRefusal::OutOfRange)?;
        p.validate()?;
        Ok(p)
    }
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A temporary access pass of `length` characters from `random`, five bits a character in the
/// RFC 4648 base32 alphabet (TN-62).
#[must_use]
pub fn tap_code(random: &[u8; TAP_LENGTH_MAX], length: usize) -> String {
    random
        .iter()
        .take(length.min(random.len()))
        .map(|b| char::from(*BASE32.get(usize::from(b & 31)).unwrap_or(&b'A')))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // TN-55, TN-62, OP-153 m.3 (e)
    #[test]
    fn the_default_policy_is_the_floor() {
        assert_eq!(RecoveryPolicy::DEFAULT.validate(), Ok(()));
        const { assert!(!RecoveryPolicy::DEFAULT.tap) };
        assert_eq!(
            tap_code(&[0xff; TAP_LENGTH_MAX], TAP_LENGTH).len(),
            TAP_LENGTH
        );
        assert!(tap_code(&[0; TAP_LENGTH_MAX], 8).chars().all(|c| c == 'A'));
    }
}
