//! The realm's protection mode, `idp.realm.protection_mode` (TN-46, TN-108, OP-151 m.3 (o)):
//! per attack protection `monitor` or `enforce`, and the SL2 stage `shadow`, `stepup` or
//! `stepup_caep`. A new realm learns for 14 days, during which SL2 stays in `shadow` whatever is
//! set. Tightening is CT1, loosening CT2.

use std::collections::BTreeSet;

/// The `idp.*` label of the setting.
pub const PROTECTION_MODE_ACTION: &str = "idp.realm.protection_mode";

/// The learning window from realm creation (OP-151 m.3 (o)).
pub const LEARNING_WINDOW_MS: u64 = 14 * 86_400_000;

/// Most ASNs a realm can deny.
pub const MAX_DENIED_ASNS: usize = 1024;

/// An attack protection with a mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protection {
    /// Bot detection. No detector feeds it in this stage; the mode is kept.
    Bot,
    /// Addresses of denied ASNs.
    SuspiciousIp,
    /// Breached passwords at sign-in.
    BreachedPassword,
    /// The login throttle (OP-35): always enforced.
    BruteForce,
}

impl Protection {
    /// Every protection.
    pub const ALL: [Self; 4] = [
        Self::Bot,
        Self::SuspiciousIp,
        Self::BreachedPassword,
        Self::BruteForce,
    ];

    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bot => "bot",
            Self::SuspiciousIp => "suspicious_ip",
            Self::BreachedPassword => "breached_password",
            Self::BruteForce => "brute_force",
        }
    }
}

/// What a protection does when it fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Enforcement {
    /// Only a log line and the risk signal (the Auth0 pattern).
    Monitor,
    /// Asks for a step-up; never a lock.
    Enforce,
}

impl Enforcement {
    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Monitor => "monitor",
            Self::Enforce => "enforce",
        }
    }

    /// The value of a name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Monitor, Self::Enforce]
            .into_iter()
            .find(|e| e.name() == name)
    }
}

/// The SL2 stage (staged exit: shadow → step-up only → step-up and CAEP).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sl2Mode {
    /// Scored, recorded and reviewed; nothing asked of the user.
    Shadow,
    /// A medium or high level asks for a step-up.
    StepUp,
    /// As `stepup`, and level changes go out as CAEP `risk-level-change`.
    StepUpCaep,
}

impl Sl2Mode {
    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::StepUp => "stepup",
            Self::StepUpCaep => "stepup_caep",
        }
    }

    /// The value of a name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Shadow, Self::StepUp, Self::StepUpCaep]
            .into_iter()
            .find(|m| m.name() == name)
    }
}

/// The realm's setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectionMode {
    /// Bot detection.
    pub bot: Enforcement,
    /// Denied ASNs.
    pub suspicious_ip: Enforcement,
    /// Breached passwords at sign-in.
    pub breached_password: Enforcement,
    /// SL2 stage.
    pub sl2: Sl2Mode,
    /// ASNs whose addresses are suspicious.
    pub denied_asns: BTreeSet<u32>,
}

impl Default for ProtectionMode {
    /// `monitor` for every protection, `shadow` for SL2, no denied ASN (OP-151 m.3 (o)).
    fn default() -> Self {
        Self {
            bot: Enforcement::Monitor,
            suspicious_ip: Enforcement::Monitor,
            breached_password: Enforcement::Monitor,
            sl2: Sl2Mode::Shadow,
            denied_asns: BTreeSet::new(),
        }
    }
}

/// The setting is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InvalidMode {
    /// An unknown protection, mode or stage name.
    #[error("unknown protection mode value")]
    Unknown,
    /// The login throttle cannot be set to monitor (TI-9: no weakening switch).
    #[error("brute-force protection is always enforced")]
    BruteForceMonitor,
    /// Too many ASNs, or ASN 0.
    #[error("invalid ASN list")]
    Asns,
}

impl InvalidMode {
    /// The stable problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unknown => "invalid-protection-mode",
            Self::BruteForceMonitor => "brute-force-always-enforced",
            Self::Asns => "invalid-denied-asns",
        }
    }
}

impl ProtectionMode {
    /// A protection's enforcement. Brute force is always enforced (OP-35).
    #[must_use]
    pub const fn of(&self, p: Protection) -> Enforcement {
        match p {
            Protection::Bot => self.bot,
            Protection::SuspiciousIp => self.suspicious_ip,
            Protection::BreachedPassword => self.breached_password,
            Protection::BruteForce => Enforcement::Enforce,
        }
    }

    /// Builds a setting from its names; `brute_force`, when given, must be `enforce`.
    ///
    /// # Errors
    /// [`InvalidMode`].
    pub fn parse(
        values: &[(&str, &str)],
        sl2: &str,
        denied_asns: &[u32],
    ) -> Result<Self, InvalidMode> {
        let mut m = Self {
            sl2: Sl2Mode::parse(sl2).ok_or(InvalidMode::Unknown)?,
            ..Self::default()
        };
        for (name, value) in values {
            let e = Enforcement::parse(value).ok_or(InvalidMode::Unknown)?;
            match *name {
                "bot" => m.bot = e,
                "suspicious_ip" => m.suspicious_ip = e,
                "breached_password" => m.breached_password = e,
                "brute_force" if e == Enforcement::Enforce => {}
                "brute_force" => return Err(InvalidMode::BruteForceMonitor),
                _ => return Err(InvalidMode::Unknown),
            }
        }
        if denied_asns.len() > MAX_DENIED_ASNS || denied_asns.contains(&0) {
            return Err(InvalidMode::Asns);
        }
        m.denied_asns = denied_asns.iter().copied().collect();
        Ok(m)
    }

    /// The SL2 stage in force at `now_ms` for a realm created at `created_ms`: `shadow` in the
    /// learning window, and when the creation time is unknown.
    #[must_use]
    pub const fn effective_sl2(&self, created_ms: Option<u64>, now_ms: u64) -> Sl2Mode {
        match created_ms {
            Some(c) if now_ms.saturating_sub(c) >= LEARNING_WINDOW_MS => self.sl2,
            _ => Sl2Mode::Shadow,
        }
    }
}

/// The Consequence Tier of a change of the setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Narrowing only.
    Ct1,
    /// Something loosens.
    Ct2,
}

/// The tier of changing `from` to `to`: loosening anything (enforce → monitor, a lower SL2
/// stage, an ASN taken off the deny list) is CT2; anything else is CT1 (OP-151 m.3 (o)).
#[must_use]
pub fn tier(from: &ProtectionMode, to: &ProtectionMode) -> Tier {
    let loosens = Protection::ALL.iter().any(|p| to.of(*p) < from.of(*p))
        || to.sl2 < from.sl2
        || !from.denied_asns.is_subset(&to.denied_asns);
    if loosens { Tier::Ct2 } else { Tier::Ct1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-151 m.3 (o), TN-46, TN-108
    #[test]
    fn defaults_and_brute_force() {
        let m = ProtectionMode::default();
        for p in [
            Protection::Bot,
            Protection::SuspiciousIp,
            Protection::BreachedPassword,
        ] {
            assert_eq!(m.of(p), Enforcement::Monitor);
        }
        assert_eq!(m.of(Protection::BruteForce), Enforcement::Enforce);
        assert_eq!(m.sl2, Sl2Mode::Shadow);
        assert_eq!(
            ProtectionMode::parse(&[("brute_force", "monitor")], "shadow", &[]),
            Err(InvalidMode::BruteForceMonitor)
        );
        assert_eq!(
            ProtectionMode::parse(&[("captcha", "enforce")], "shadow", &[]),
            Err(InvalidMode::Unknown)
        );
        assert_eq!(
            ProtectionMode::parse(&[], "block", &[]),
            Err(InvalidMode::Unknown)
        );
        assert_eq!(
            ProtectionMode::parse(&[], "shadow", &[0]),
            Err(InvalidMode::Asns)
        );
    }

    // OP-151 m.3 (o)
    #[test]
    fn learning_window_forces_shadow() {
        let m = ProtectionMode::parse(&[], "stepup_caep", &[]).unwrap();
        let day = 86_400_000;
        assert_eq!(m.effective_sl2(Some(0), 13 * day), Sl2Mode::Shadow);
        assert_eq!(m.effective_sl2(Some(0), 14 * day), Sl2Mode::StepUpCaep);
        assert_eq!(m.effective_sl2(None, 400 * day), Sl2Mode::Shadow);
    }

    // OP-151 m.3 (o)
    #[test]
    fn tiers() {
        let base = ProtectionMode::default();
        let tight = ProtectionMode::parse(
            &[
                ("suspicious_ip", "enforce"),
                ("breached_password", "enforce"),
            ],
            "stepup",
            &[64_496],
        )
        .unwrap();
        assert_eq!(tier(&base, &tight), Tier::Ct1);
        assert_eq!(tier(&tight, &base), Tier::Ct2);
        assert_eq!(tier(&base, &base), Tier::Ct1);
        let fewer = ProtectionMode {
            denied_asns: BTreeSet::new(),
            ..tight.clone()
        };
        assert_eq!(tier(&tight, &fewer), Tier::Ct2);
        let shadow = ProtectionMode {
            sl2: Sl2Mode::Shadow,
            ..tight.clone()
        };
        assert_eq!(tier(&tight, &shadow), Tier::Ct2);
    }
}
