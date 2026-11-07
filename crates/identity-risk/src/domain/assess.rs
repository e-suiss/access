//! One SL2 assessment (§12.2.4, TN-46): from the inputs of a sign-in to its signals, level and
//! effects. Pure: no clock, no I/O. Risk only narrows (CI-2): the effects are a step-up request,
//! a CAEP `risk-level-change`, a review item and log lines; never an allow, never a lock.

use std::collections::BTreeSet;

use crate::domain::geo::{GeoAnswer, Place, impossible_travel};
use crate::domain::mode::{Enforcement, Protection, ProtectionMode, Sl2Mode};
use crate::domain::score::{Level, level};
use crate::domain::signal::{RiskSignal, Source};

/// Prior failed password attempts of the account from which brute force fires (PD).
pub const BRUTE_FORCE_AT: u32 = 5;

/// The breached-password check of this sign-in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Breach {
    /// No password was presented: nothing to check.
    #[default]
    NotChecked,
    /// The range does not list it.
    Clean,
    /// The range lists it.
    Listed,
    /// The range could not be read: never "not breached" (G50, MD-8).
    Unavailable,
}

impl Breach {
    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Clean => "clean",
            Self::Listed => "listed",
            Self::Unavailable => "unavailable",
        }
    }

    /// The value of a name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [
            Self::NotChecked,
            Self::Clean,
            Self::Listed,
            Self::Unavailable,
        ]
        .into_iter()
        .find(|b| b.name() == name)
    }
}

/// What SL2 reads of one sign-in. Each field names a [`Source`]; `None` means the source does
/// not apply to this sign-in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Inputs {
    /// The client address's place; `None` when the request carried no address.
    pub client_place: Option<GeoAnswer>,
    /// The account's last sign-in place.
    pub last_place: Option<Place>,
    /// The account's last sign-in time.
    pub last_at_ms: Option<u64>,
    /// Now.
    pub now_ms: u64,
    /// Whether the browser has a valid device marker; `None` when the realm has no markers.
    pub device_known: Option<bool>,
    /// Failed password attempts counted before this sign-in; `None` without a password step.
    pub prior_failures: Option<u32>,
    /// The breached-password check.
    pub breach: Breach,
    /// The account is a canary.
    pub canary: bool,
}

/// What an assessment found and asks for.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is a separate effect of one assessment"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assessment {
    /// The level, the `risk_level` Claim's value.
    pub level: Level,
    /// The signals that fired.
    pub signals: BTreeSet<RiskSignal>,
    /// The sources that could not answer.
    pub missing: BTreeSet<Source>,
    /// The SL2 stage in force.
    pub mode: Sl2Mode,
    /// A step-up is asked of the user now (SL1 path; never a block).
    pub step_up: bool,
    /// A step-up would have been asked outside shadow mode.
    pub shadow_step_up: bool,
    /// Protections that fired in monitor mode: logged only.
    pub monitored: BTreeSet<Protection>,
    /// The level goes out as CAEP `risk-level-change`.
    pub caep: bool,
    /// A review item is opened for a person (`REQUIRE_ACTION`; GDPR art. 22).
    pub review: bool,
}

fn network(
    i: &Inputs,
    mode: &ProtectionMode,
    fired: &mut BTreeSet<RiskSignal>,
    missing: &mut BTreeSet<Source>,
) {
    let place = match i.client_place {
        Some(GeoAnswer::Found(p)) => p,
        Some(GeoAnswer::Unavailable) | None => {
            missing.insert(Source::Network);
            return;
        }
    };
    if let (Some(last), Some(at)) = (i.last_place, i.last_at_ms) {
        match (last.point, place.point) {
            (Some(from), Some(to)) => {
                if impossible_travel(from, at, to, i.now_ms) {
                    fired.insert(RiskSignal::ImpossibleTravel);
                }
            }
            (_, None) => {
                missing.insert(Source::Network);
            }
            (None, Some(_)) => {}
        }
    }
    if !mode.denied_asns.is_empty() {
        match place.asn {
            Some(asn) if mode.denied_asns.contains(&asn) => {
                fired.insert(RiskSignal::SuspiciousIp);
            }
            Some(_) => {}
            None => {
                missing.insert(Source::Network);
            }
        }
    }
}

/// Assesses one sign-in under `mode` in stage `sl2` (the stage in force, after the learning
/// window).
#[must_use]
pub fn assess(i: &Inputs, mode: &ProtectionMode, sl2: Sl2Mode) -> Assessment {
    let mut fired = BTreeSet::new();
    let mut missing = BTreeSet::new();
    network(i, mode, &mut fired, &mut missing);
    if i.device_known == Some(false) {
        fired.insert(RiskSignal::NewDevice);
    }
    match i.breach {
        Breach::Listed => {
            fired.insert(RiskSignal::BreachedPassword);
        }
        Breach::Unavailable => {
            missing.insert(Source::Breach);
        }
        Breach::Clean | Breach::NotChecked => {}
    }
    if i.prior_failures.is_some_and(|f| f >= BRUTE_FORCE_AT) {
        fired.insert(RiskSignal::BruteForce);
    }
    if i.canary {
        fired.insert(RiskSignal::CanaryHit);
    }
    let level = level(&fired, missing.is_empty());
    let protections = [
        (RiskSignal::SuspiciousIp, Protection::SuspiciousIp),
        (RiskSignal::BreachedPassword, Protection::BreachedPassword),
    ];
    let mut monitored = BTreeSet::new();
    let mut enforced = false;
    for (signal, p) in protections {
        if fired.contains(&signal) {
            match mode.of(p) {
                Enforcement::Monitor => {
                    monitored.insert(p);
                }
                Enforcement::Enforce => enforced = true,
            }
        }
    }
    let wants = level >= Level::Medium;
    let step_up = enforced || (wants && sl2 != Sl2Mode::Shadow);
    let shadow_step_up = wants && sl2 == Sl2Mode::Shadow;
    Assessment {
        level,
        caep: sl2 == Sl2Mode::StepUpCaep && level.caep().is_some(),
        review: level == Level::High || step_up || shadow_step_up,
        signals: fired,
        missing,
        mode: sl2,
        step_up,
        shadow_step_up,
        monitored,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::geo::Point;

    const HOUR: u64 = 3_600_000;

    fn place(lat: f64, lon: f64, asn: u32) -> Place {
        Place {
            country: None,
            asn: Some(asn),
            point: Point::from_degrees(lat, lon),
        }
    }

    fn calm() -> Inputs {
        Inputs {
            client_place: Some(GeoAnswer::Found(place(41.0, 29.0, 100))),
            last_place: Some(place(41.0, 29.0, 100)),
            last_at_ms: Some(0),
            now_ms: 10 * HOUR,
            device_known: Some(true),
            prior_failures: Some(0),
            breach: Breach::Clean,
            canary: false,
        }
    }

    // TN-46: shadow by default asks nothing of the user but is reviewed; risk only narrows
    #[test]
    fn shadow_asks_nothing() {
        let i = Inputs {
            client_place: Some(GeoAnswer::Found(place(40.7, -74.0, 100))),
            now_ms: HOUR,
            ..calm()
        };
        let a = assess(&i, &ProtectionMode::default(), Sl2Mode::Shadow);
        assert_eq!(a.level, Level::High);
        assert!(a.signals.contains(&RiskSignal::ImpossibleTravel));
        assert!(!a.step_up && a.shadow_step_up && a.review && !a.caep);
        let b = assess(&i, &ProtectionMode::default(), Sl2Mode::StepUp);
        assert!(b.step_up && !b.caep && b.review);
        let c = assess(&i, &ProtectionMode::default(), Sl2Mode::StepUpCaep);
        assert!(c.step_up && c.caep);
    }

    // TN-46: a calm sign-in is low and asks nothing
    #[test]
    fn calm_is_low() {
        let a = assess(&calm(), &ProtectionMode::default(), Sl2Mode::StepUpCaep);
        assert_eq!(a.level, Level::Low);
        assert!(a.signals.is_empty() && a.missing.is_empty());
        assert!(!a.step_up && !a.review);
    }

    // MD-8: a missing source makes the level unavailable, not low, and asks no step-up of its
    // own; what the other sources fired still counts
    #[test]
    fn missing_sources_fail_closed_without_blocking() {
        let i = Inputs {
            client_place: Some(GeoAnswer::Unavailable),
            ..calm()
        };
        let a = assess(&i, &ProtectionMode::default(), Sl2Mode::StepUp);
        assert_eq!(a.level, Level::Unavailable);
        assert!(a.missing.contains(&Source::Network));
        assert!(!a.step_up && !a.caep);
        let b = Inputs {
            breach: Breach::Unavailable,
            prior_failures: Some(BRUTE_FORCE_AT),
            ..i
        };
        let b = assess(&b, &ProtectionMode::default(), Sl2Mode::StepUp);
        assert_eq!(b.level, Level::Medium);
        assert!(b.step_up);
        let none = Inputs {
            client_place: None,
            ..calm()
        };
        assert_eq!(
            assess(&none, &ProtectionMode::default(), Sl2Mode::StepUp).level,
            Level::Unavailable
        );
    }

    // TN-108, OP-151 m.3 (o): a protection in monitor mode only logs; in enforce mode it asks
    // for a step-up even while SL2 is in shadow; never a lock
    #[test]
    fn monitor_logs_enforce_steps_up() {
        let listed = Inputs {
            breach: Breach::Listed,
            ..calm()
        };
        let a = assess(&listed, &ProtectionMode::default(), Sl2Mode::Shadow);
        assert!(a.monitored.contains(&Protection::BreachedPassword));
        assert!(!a.step_up);
        let enforce =
            ProtectionMode::parse(&[("breached_password", "enforce")], "shadow", &[]).unwrap();
        let b = assess(&listed, &enforce, Sl2Mode::Shadow);
        assert!(b.monitored.is_empty() && b.step_up);
        let deny =
            ProtectionMode::parse(&[("suspicious_ip", "enforce")], "shadow", &[100]).unwrap();
        let c = assess(&calm(), &deny, Sl2Mode::Shadow);
        assert!(c.signals.contains(&RiskSignal::SuspiciousIp) && c.step_up);
    }

    // §4.4: a canary match is high whatever else
    #[test]
    fn canary_is_high() {
        let i = Inputs {
            canary: true,
            ..calm()
        };
        let a = assess(&i, &ProtectionMode::default(), Sl2Mode::Shadow);
        assert_eq!(a.level, Level::High);
        assert!(a.signals.contains(&RiskSignal::CanaryHit) && a.review);
    }

    #[test]
    fn breach_names() {
        for b in [
            Breach::NotChecked,
            Breach::Clean,
            Breach::Listed,
            Breach::Unavailable,
        ] {
            assert_eq!(Breach::parse(b.name()), Some(b));
        }
    }
}
