//! Payment-class sign-in rules (OP-156 m.3 (e), (f), IDP-4, IDP-9, §10.3.4): the restricted SMS
//! code (6 digits, 5 minutes, 3 tries, single use) and the SIM change rule. A line whose SIM
//! changed in the last 90 days takes no SIM-based step; under the TR payment profile a line with no
//! signal checked in the last 24 hours takes none either (fail closed).

use suiss_crypto::digest::sha256;

use crate::domain::assurance::AssuranceProfile;

/// How long a code lives.
pub const CODE_TTL_MS: u64 = 5 * 60_000;

/// Tries a code takes.
pub const MAX_TRIES: u8 = 3;

/// Digits of a code.
pub const CODE_DIGITS: usize = 6;

/// Codes one account is sent in [`SEND_WINDOW_MS`] (PD).
pub const MAX_SENDS: u64 = 5;

/// The window [`MAX_SENDS`] counts in.
pub const SEND_WINDOW_MS: u64 = 60 * 60_000;

/// No SIM-based step this long after the line's last SIM change (Ek B 5124).
pub const SIM_HOLD_MS: u64 = 90 * 24 * 60 * 60_000;

/// Under the TR payment profile the newest signal must be this fresh.
pub const SIGNAL_FRESH_MS: u64 = 24 * 60 * 60_000;

const CODE_CONTEXT: &[u8] = b"access/sms-code/v1\0";

/// Below this a 32-bit draw maps to every code equally often.
const UNIFORM_BELOW: u32 = 4_294_000_000;

/// What an SMS code is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmsPurpose {
    /// A sign-in's second step.
    SignIn,
    /// Enrolment or activation of the app-controlled factor.
    Activation,
}

impl SmsPurpose {
    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SignIn => "sign_in",
            Self::Activation => "activation",
        }
    }

    /// Whether the realm's profile lets a code serve this purpose (OP-156 m.3 (f)): under the TR
    /// payment profile only enrolment and activation take one.
    #[must_use]
    pub const fn allowed_in(self, profile: AssuranceProfile) -> bool {
        match self {
            Self::SignIn => profile.sms_signs_in(),
            Self::Activation => true,
        }
    }
}

/// The six digits of one 32-bit draw; `None` asks for another draw so every code is equally
/// likely.
#[must_use]
pub fn code_of(draw: [u8; 4]) -> Option<String> {
    let n = u32::from_be_bytes(draw);
    (n < UNIFORM_BELOW).then(|| format!("{:06}", n % 1_000_000))
}

/// The stored digest of `code` for the flow or session digest `binding`.
#[must_use]
pub fn code_digest(binding: &[u8; 32], code: &str) -> [u8; 32] {
    let mut m = CODE_CONTEXT.to_vec();
    m.extend_from_slice(binding);
    m.extend_from_slice(code.as_bytes());
    sha256(&m)
}

/// Whether `typed` is a well-formed code: exactly six ASCII digits.
#[must_use]
pub fn well_formed(typed: &str) -> bool {
    typed.len() == CODE_DIGITS && typed.bytes().all(|b| b.is_ascii_digit())
}

/// The SIM change signals about a line: the latest change any of them names and the newest
/// check, Unix ms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimSignals {
    /// The latest SIM change.
    pub last_change_ms: u64,
    /// The newest check.
    pub checked_ms: u64,
}

/// Why a SIM-based step is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimRefusal {
    /// The SIM changed less than 90 days ago; refused until then, Unix ms.
    Changed {
        /// When the hold ends.
        until_ms: u64,
    },
    /// The profile needs a signal checked in the last 24 hours and there is none.
    NoSignal,
}

impl SimRefusal {
    /// The telemetry reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Changed { .. } => "sim_changed",
            Self::NoSignal => "no_sim_signal",
        }
    }
}

/// IDP-9, §10.3.4, OP-156 m.3 (f): whether a SIM-based step may be used at `now_ms`.
///
/// # Errors
/// [`SimRefusal`].
pub fn sim_rule(
    signals: Option<SimSignals>,
    profile: AssuranceProfile,
    now_ms: u64,
) -> Result<(), SimRefusal> {
    if let Some(s) = signals {
        let until_ms = s.last_change_ms.saturating_add(SIM_HOLD_MS);
        if now_ms < until_ms {
            return Err(SimRefusal::Changed { until_ms });
        }
    }
    if profile == AssuranceProfile::TrPayment
        && signals.is_none_or(|s| s.checked_ms.saturating_add(SIGNAL_FRESH_MS) < now_ms)
    {
        return Err(SimRefusal::NoSignal);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, reason = "test code")]

    use super::*;

    const DAY: u64 = 24 * 60 * 60_000;

    // OP-156 m.3 (f)
    #[test]
    fn codes_are_six_uniform_digits() {
        assert_eq!(code_of(0_u32.to_be_bytes()).as_deref(), Some("000000"));
        assert_eq!(
            code_of((UNIFORM_BELOW - 1).to_be_bytes()).as_deref(),
            Some("999999")
        );
        assert_eq!(code_of(UNIFORM_BELOW.to_be_bytes()), None);
        assert_eq!(UNIFORM_BELOW % 1_000_000, 0);
        assert!(well_formed("012345"));
        assert!(!well_formed("12345") && !well_formed("12345a") && !well_formed("１２３４５６"));
        assert_ne!(
            code_digest(&[1; 32], "123456"),
            code_digest(&[2; 32], "123456")
        );
    }

    // IDP-9, §10.3.4, Ek B 5124
    #[test]
    fn sms_is_refused_thirty_days_after_a_sim_change() {
        let changed = SimSignals {
            last_change_ms: 100 * DAY,
            checked_ms: 130 * DAY,
        };
        for profile in [AssuranceProfile::Standard, AssuranceProfile::TrPayment] {
            assert_eq!(
                sim_rule(Some(changed), profile, 130 * DAY),
                Err(SimRefusal::Changed {
                    until_ms: 190 * DAY
                })
            );
        }
        let later = SimSignals {
            checked_ms: 190 * DAY,
            ..changed
        };
        assert_eq!(
            sim_rule(Some(later), AssuranceProfile::TrPayment, 190 * DAY),
            Ok(())
        );
    }

    // OP-156 m.3 (f)
    #[test]
    fn the_tr_profile_refuses_a_line_without_a_fresh_signal() {
        let old = SimSignals {
            last_change_ms: 0,
            checked_ms: 200 * DAY,
        };
        assert_eq!(
            sim_rule(None, AssuranceProfile::TrPayment, 300 * DAY),
            Err(SimRefusal::NoSignal)
        );
        assert_eq!(
            sim_rule(Some(old), AssuranceProfile::TrPayment, 201 * DAY + 1),
            Err(SimRefusal::NoSignal)
        );
        assert_eq!(
            sim_rule(Some(old), AssuranceProfile::TrPayment, 201 * DAY),
            Ok(())
        );
        assert_eq!(
            sim_rule(None, AssuranceProfile::Standard, 300 * DAY),
            Ok(())
        );
    }

    // OP-156 m.3 (f), MD-11
    #[test]
    fn the_tr_profile_takes_sms_only_for_activation() {
        assert!(!SmsPurpose::SignIn.allowed_in(AssuranceProfile::TrPayment));
        assert!(SmsPurpose::Activation.allowed_in(AssuranceProfile::TrPayment));
        assert!(SmsPurpose::SignIn.allowed_in(AssuranceProfile::Standard));
    }
}
