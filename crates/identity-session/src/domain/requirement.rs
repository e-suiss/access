//! The requirement model (TN-132, LFP-23): the realm picks what must be completed; the server
//! never looks at the order of the steps, only at whether the list is complete, and keeps the
//! unbreakable rules: required MFA cannot be skipped and resuming never raises assurance.

use serde::{Deserialize, Serialize};

use crate::domain::assurance::{Aal, Factor, MethodClass, vector};

/// Whether a second step is asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MfaPolicy {
    /// Only when the account has enrolled a second factor.
    WhenEnrolled,
    /// Always; an account without a second factor must enroll one first (§12.4.2).
    Required,
}

/// A realm's sign-in requirements (PD values; TN-132).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each first step the realm enables is one flag (TN-132)"
)]
pub struct AuthPolicy {
    /// MFA rule.
    pub mfa: MfaPolicy,
    /// Lowest AAL a sign-in reaches.
    pub min_aal: Aal,
    /// Passwords as a first step (TN-132: the realm enabled e-mail or username sign-in).
    pub password: bool,
    /// Passkeys as a first step (TN-132: the realm enabled passkey sign-in).
    pub passkey: bool,
    /// E-mail codes as a first step.
    pub email_otp: bool,
    /// E-mail links as a first step.
    pub magic_link: bool,
    /// Days a device marker skips the second step (X33); `None` disables it.
    pub remember_device_days: Option<u32>,
}

impl AuthPolicy {
    /// Password and passkey, a second step when enrolled, 30-day device markers.
    pub const DEFAULT: Self = Self {
        mfa: MfaPolicy::WhenEnrolled,
        min_aal: Aal::Aal1,
        password: true,
        passkey: true,
        email_otp: true,
        magic_link: true,
        remember_device_days: Some(30),
    };
}

/// What the account has enrolled, known only after the first step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrolled {
    /// An active TOTP credential.
    pub totp: bool,
    /// Active recovery codes.
    pub recovery_codes: bool,
    /// Live passkeys.
    pub passkeys: bool,
}

impl Enrolled {
    /// Whether any second factor is enrolled.
    #[must_use]
    pub const fn second_factor(&self) -> bool {
        self.totp || self.passkeys
    }
}

/// One thing still to complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    /// A first step: password, passkey, e-mail code or link.
    FirstFactor,
    /// A second, independent step.
    SecondFactor,
    /// MFA is required and the account has no second factor: enroll one.
    EnrollSecondFactor,
    /// The realm's minimum AAL is not reached.
    Aal(Aal),
}

/// Methods that may open a sign-in.
#[must_use]
pub const fn is_first_factor(m: MethodClass) -> bool {
    matches!(
        m,
        MethodClass::Password
            | MethodClass::Passkey
            | MethodClass::EmailOtp
            | MethodClass::MagicLink
            | MethodClass::Federated
            | MethodClass::SmartCard
            | MethodClass::Certificate
    )
}

/// Methods that may only follow a first step (§10.2: TOTP and recovery codes are second
/// factors).
#[must_use]
pub const fn is_second_factor(m: MethodClass) -> bool {
    matches!(
        m,
        MethodClass::Totp | MethodClass::RecoveryCode | MethodClass::Passkey | MethodClass::Push
    )
}

/// Whether the steps prove two factors: one multi-factor step, or two steps one of which is a
/// second factor.
#[must_use]
pub fn multi_factor(factors: &[Factor]) -> bool {
    let one_multi_factor = factors.iter().any(|f| f.kinds.len() >= 2);
    let two_steps = factors.len() >= 2 && factors.iter().any(|f| is_second_factor(f.method));
    one_multi_factor || two_steps
}

/// The requirements once SL2 asked for a step-up (TN-46, §12.2.4): a second step from what the
/// account has enrolled, which a device marker does not stand in for. An account without a second
/// factor is not offered enrolment here, so a stolen password cannot enrol the thief's own
/// factor; the flow stays incomplete and a review item waits for a person. Never a lock.
#[must_use]
pub fn with_step_up(mut needs: Vec<Requirement>, factors: &[Factor]) -> Vec<Requirement> {
    if needs.contains(&Requirement::FirstFactor) || multi_factor(factors) {
        return needs;
    }
    needs.retain(|r| *r != Requirement::EnrollSecondFactor);
    if !needs.contains(&Requirement::SecondFactor) {
        needs.insert(0, Requirement::SecondFactor);
    }
    needs
}

/// What is still missing. Empty means complete. `marker` is a valid device marker for the
/// subject (X33): it stands in for the second step, never for the AAL requirement.
#[must_use]
pub fn missing(
    policy: &AuthPolicy,
    enrolled: &Enrolled,
    factors: &[Factor],
    marker: bool,
) -> Vec<Requirement> {
    let mut out = Vec::new();
    let first = factors.iter().any(|f| is_first_factor(f.method));
    if !first {
        out.push(Requirement::FirstFactor);
        return out;
    }
    let multi = multi_factor(factors);
    let wants_second = match policy.mfa {
        MfaPolicy::Required => true,
        MfaPolicy::WhenEnrolled => enrolled.second_factor(),
    };
    if wants_second && !multi && !marker {
        if enrolled.second_factor() {
            out.push(Requirement::SecondFactor);
        } else {
            out.push(Requirement::EnrollSecondFactor);
        }
    }
    let reached = vector(factors).aal;
    if reached < policy.min_aal {
        out.push(Requirement::Aal(policy.min_aal));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1;

    fn pw() -> Factor {
        Factor::password(T)
    }

    // TN-46, MD-8
    #[test]
    fn sl2_step_up_adds_a_second_step() {
        let e = Enrolled {
            totp: true,
            ..Enrolled::default()
        };
        let skipped = missing(&AuthPolicy::DEFAULT, &e, &[pw()], true);
        assert_eq!(skipped, []);
        assert_eq!(with_step_up(skipped, &[pw()]), [Requirement::SecondFactor]);
        assert_eq!(
            with_step_up(vec![Requirement::EnrollSecondFactor], &[pw()]),
            [Requirement::SecondFactor]
        );
        assert_eq!(
            with_step_up(vec![], &[pw(), Factor::totp([2; 16], T)]),
            Vec::<Requirement>::new()
        );
        assert_eq!(
            with_step_up(vec![Requirement::FirstFactor], &[]),
            [Requirement::FirstFactor]
        );
    }

    // TN-132, LFP-23
    #[test]
    fn order_does_not_matter() {
        let e = Enrolled {
            totp: true,
            ..Enrolled::default()
        };
        let p = AuthPolicy::DEFAULT;
        let a = [pw(), Factor::totp([2; 16], T)];
        let b = [Factor::totp([2; 16], T), pw()];
        assert_eq!(missing(&p, &e, &a, false), []);
        assert_eq!(missing(&p, &e, &b, false), []);
    }

    // TN-132, §12.4.2
    #[test]
    fn required_mfa_cannot_be_skipped() {
        let p = AuthPolicy {
            mfa: MfaPolicy::Required,
            ..AuthPolicy::DEFAULT
        };
        let none = Enrolled::default();
        assert_eq!(missing(&p, &none, &[], false), [Requirement::FirstFactor]);
        assert_eq!(
            missing(&p, &none, &[pw()], false),
            [Requirement::EnrollSecondFactor]
        );
        let e = Enrolled {
            totp: true,
            ..Enrolled::default()
        };
        assert_eq!(missing(&p, &e, &[pw()], false), [Requirement::SecondFactor]);
        assert_eq!(
            missing(&p, &e, &[Factor::totp([2; 16], T)], false),
            [Requirement::FirstFactor]
        );
        let uv_passkey = Factor::passkey([3; 16], true, true, false, T);
        assert_eq!(missing(&p, &e, &[uv_passkey], false), []);
    }

    // X33
    #[test]
    fn a_marker_skips_the_second_step_but_not_the_aal() {
        let e = Enrolled {
            totp: true,
            ..Enrolled::default()
        };
        assert_eq!(missing(&AuthPolicy::DEFAULT, &e, &[pw()], true), []);
        let strict = AuthPolicy {
            min_aal: Aal::Aal2,
            ..AuthPolicy::DEFAULT
        };
        assert_eq!(
            missing(&strict, &e, &[pw()], true),
            [Requirement::Aal(Aal::Aal2)]
        );
    }

    // §10.2
    #[test]
    fn optional_mfa_without_enrollment_completes() {
        assert_eq!(
            missing(&AuthPolicy::DEFAULT, &Enrolled::default(), &[pw()], false),
            []
        );
    }
}
