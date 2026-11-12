//! Realm profile checks (OP-159 m.3 (ii), §10.3.4): a read-only report of a realm's settings
//! view against the authentication requirements of PCI DSS 4.0 Req 8 or OMB M-22-09. The
//! report is evidence for the operator's own assessment; it changes nothing and claims no
//! conformity (SA-53).

use std::collections::BTreeSet;

use access_identity_account::domain::password::MIN_CHARS;
use access_identity_account::domain::throttle::HARD_LOCK_AT;
use serde_json::{Value, json};

/// The longest idle time PCI DSS 4.0 8.2.8 allows, ms.
pub const PCI_IDLE_MAX_MS: u64 = 15 * 60 * 1000;

/// The shortest password PCI DSS 4.0 8.3.6 allows, characters.
pub const PCI_PASSWORD_MIN: usize = 12;

/// The most failed attempts PCI DSS 4.0 8.3.4 allows before a lockout.
pub const PCI_LOCKOUT_MAX: u32 = 10;

/// A profile the check knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// PCI DSS 4.0 Requirement 8.
    PciDss4,
    /// OMB M-22-09.
    M2209,
}

impl Profile {
    /// Every profile.
    pub const ALL: [Self; 2] = [Self::PciDss4, Self::M2209];

    /// Its name on the command line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PciDss4 => "pci-dss-4",
            Self::M2209 => "m-22-09",
        }
    }

    /// The profile of `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }
}

/// One check's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The setting meets the requirement.
    Pass,
    /// It does not, or the server did not report it.
    Fail,
}

/// One check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// The check's stable name.
    pub check: &'static str,
    /// The framework's control.
    pub control: &'static str,
    /// The outcome.
    pub result: Outcome,
    /// What the realm's settings say.
    pub observed: String,
}

/// The report of one realm under one profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The profile's name.
    pub profile: &'static str,
    /// Whether every check passed.
    pub passed: bool,
    /// The checks, in a fixed order.
    pub checks: Vec<Finding>,
}

impl Outcome {
    /// Its name in the report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

impl Report {
    /// The report as JSON, for `access-cli realm check`.
    #[must_use]
    pub fn to_json(&self, realm: &str) -> Value {
        json!({
            "profile": self.profile,
            "realm": realm,
            "passed": self.passed,
            "checks": self.checks.iter().map(|c| json!({
                "check": c.check,
                "control": c.control,
                "result": c.result.name(),
                "observed": c.observed,
            })).collect::<Vec<_>>(),
        })
    }
}

/// What the settings view says, or `None` where it is silent (fail-closed).
struct View {
    methods: Option<BTreeSet<String>>,
    mfa: Option<bool>,
    idle_ms: Option<u64>,
    push: Option<bool>,
    sms: Option<bool>,
}

impl View {
    fn read(settings: &Value) -> Self {
        let at = |path: &[&str]| {
            path.iter()
                .try_fold(settings, |v, k| v.get(*k))
                .unwrap_or(&Value::Null)
        };
        Self {
            methods: at(&["signin_policy", "methods"]).as_array().map(|m| {
                m.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            }),
            mfa: at(&["signin_policy", "mfa_required"]).as_bool(),
            idle_ms: at(&["session_policy", "idle_ms"]).as_u64(),
            push: at(&["push", "enabled"]).as_bool(),
            sms: at(&["sms_otp", "enabled"]).as_bool(),
        }
    }

    /// The enabled methods that can take a password: `email` and `username`.
    fn password_methods(&self) -> Option<Vec<String>> {
        self.methods.as_ref().map(|m| {
            m.iter()
                .filter(|x| *x == "email" || *x == "username")
                .cloned()
                .collect()
        })
    }
}

fn finding(check: &'static str, control: &'static str, ok: bool, observed: String) -> Finding {
    Finding {
        check,
        control,
        result: if ok { Outcome::Pass } else { Outcome::Fail },
        observed,
    }
}

const SILENT: &str = "not reported by the server";

fn mfa(v: &View, control: &'static str) -> Finding {
    match v.mfa {
        Some(m) => finding(
            "mfa-every-access",
            control,
            m,
            format!("signin_policy.mfa_required is {m}"),
        ),
        None => finding("mfa-every-access", control, false, SILENT.to_owned()),
    }
}

fn password(v: &View, check: &'static str, control: &'static str, product: &str) -> Finding {
    match v.password_methods() {
        Some(p) if p.is_empty() => finding(
            check,
            control,
            true,
            String::from("no password sign-in method is enabled"),
        ),
        Some(p) => finding(
            check,
            control,
            false,
            format!("password sign-in through {}; {product}", p.join(", ")),
        ),
        None => finding(check, control, false, SILENT.to_owned()),
    }
}

fn pci(v: &View) -> Vec<Finding> {
    vec![
        mfa(v, "8.4.2"),
        password(
            v,
            "password-length-12",
            "8.3.6",
            &format!(
                "the product's minimum is {MIN_CHARS} characters, {PCI_PASSWORD_MIN} are asked"
            ),
        ),
        password(
            v,
            "lockout-10-attempts",
            "8.3.4",
            &format!(
                "an account locks after {HARD_LOCK_AT} consecutive failures, at most {PCI_LOCKOUT_MAX} are asked"
            ),
        ),
        match v.idle_ms {
            Some(ms) => finding(
                "idle-15-minutes",
                "8.2.8",
                ms <= PCI_IDLE_MAX_MS,
                format!("session_policy.idle_ms is {ms}"),
            ),
            None => finding("idle-15-minutes", "8.2.8", false, SILENT.to_owned()),
        },
    ]
}

fn m2209(v: &View) -> Vec<Finding> {
    let phishing = match (&v.methods, v.push) {
        (Some(m), Some(push)) => {
            let others: Vec<&str> = m
                .iter()
                .map(String::as_str)
                .filter(|x| *x != "passkey")
                .collect();
            let ok = !m.is_empty() && others.is_empty() && !push;
            let mut seen = Vec::new();
            if !others.is_empty() {
                seen.push(format!("methods other than passkey: {}", others.join(", ")));
            }
            if push {
                seen.push(String::from("push verification is on"));
            }
            if seen.is_empty() {
                seen.push(String::from("passkeys only"));
            }
            finding(
                "phishing-resistant-only",
                "M-22-09 2.B",
                ok,
                seen.join("; "),
            )
        }
        _ => finding(
            "phishing-resistant-only",
            "M-22-09 2.B",
            false,
            SILENT.to_owned(),
        ),
    };
    let sms = match (&v.methods, v.sms) {
        (Some(m), Some(sms)) => {
            let phone = m.contains("phone");
            let mut seen = Vec::new();
            if sms {
                seen.push(String::from("the SMS code is on"));
            }
            if phone {
                seen.push(String::from("the phone sign-in method is enabled"));
            }
            if seen.is_empty() {
                seen.push(String::from("no SMS code and no voice factor"));
            }
            finding(
                "no-sms-or-voice",
                "M-22-09 2.B",
                !sms && !phone,
                seen.join("; "),
            )
        }
        _ => finding("no-sms-or-voice", "M-22-09 2.B", false, SILENT.to_owned()),
    };
    vec![mfa(v, "M-22-09 2.B"), phishing, sms]
}

/// The report of `settings`, a realm's settings view (`GET …/settings`), under `profile`.
#[must_use]
pub fn check(profile: Profile, settings: &Value) -> Report {
    let v = View::read(settings);
    let checks = match profile {
        Profile::PciDss4 => pci(&v),
        Profile::M2209 => m2209(&v),
    };
    Report {
        profile: profile.name(),
        passed: checks.iter().all(|c| c.result == Outcome::Pass),
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(methods: &[&str], mfa: bool, idle_ms: u64, push: bool, sms: bool) -> Value {
        json!({
            "signin_policy": { "methods": methods, "mfa_required": mfa },
            "session_policy": { "idle_ms": idle_ms },
            "push": { "enabled": push },
            "sms_otp": { "enabled": sms },
        })
    }

    fn failed(r: &Report) -> Vec<&'static str> {
        r.checks
            .iter()
            .filter(|c| c.result == Outcome::Fail)
            .map(|c| c.check)
            .collect()
    }

    // OP-159 m.3 (ii), §10.3.4
    #[test]
    fn a_weak_realm_fails_req_8_and_a_hardened_one_passes() {
        let weak = view(&["email", "passkey"], false, 1_800_000, true, true);
        let r = check(Profile::PciDss4, &weak);
        assert!(!r.passed);
        assert_eq!(
            failed(&r),
            [
                "mfa-every-access",
                "password-length-12",
                "lockout-10-attempts",
                "idle-15-minutes"
            ]
        );
        assert_eq!(
            failed(&check(Profile::M2209, &weak)),
            [
                "mfa-every-access",
                "phishing-resistant-only",
                "no-sms-or-voice"
            ]
        );
        let hard = view(&["passkey"], true, PCI_IDLE_MAX_MS, false, false);
        for p in Profile::ALL {
            let r = check(p, &hard);
            assert!(r.passed, "{r:?}");
        }
    }

    // OP-159 m.3 (ii)
    #[test]
    fn a_setting_the_server_does_not_report_fails() {
        let r = check(
            Profile::M2209,
            &json!({"signin_policy": {"methods": ["passkey"]}}),
        );
        assert_eq!(
            failed(&r),
            [
                "mfa-every-access",
                "phishing-resistant-only",
                "no-sms-or-voice"
            ]
        );
        assert!(r.checks.iter().all(|c| c.observed == SILENT));
        assert_eq!(Profile::parse("pci-dss-4"), Some(Profile::PciDss4));
        assert_eq!(Profile::parse("m-22-09"), Some(Profile::M2209));
        assert_eq!(Profile::parse("soc2"), None);
    }
}
