//! The SL2 signals (§12.2.4, IDP-39) and the sources they are computed from. The input set is
//! closed: network, device, history, counters and the breach corpus. Behavioural biometrics and
//! emotion inference are never an input (TN-47).

/// What SL2 can observe about a sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskSignal {
    /// The distance from the last sign-in's place cannot be covered in the time between them.
    ImpossibleTravel,
    /// No valid device marker for the account on this browser (X33).
    NewDevice,
    /// The address's ASN is on the realm's deny list (no third-party reputation feed).
    SuspiciousIp,
    /// The presented password is in the breach corpus (IDP-3).
    BreachedPassword,
    /// The account counted failed password attempts before this one (OP-35).
    BruteForce,
    /// A canary credential matched (§4.4).
    CanaryHit,
}

impl RiskSignal {
    /// Every signal.
    pub const ALL: [Self; 6] = [
        Self::ImpossibleTravel,
        Self::NewDevice,
        Self::SuspiciousIp,
        Self::BreachedPassword,
        Self::BruteForce,
        Self::CanaryHit,
    ];

    /// The signal's name: the value of its `risk_signal` Claim.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ImpossibleTravel => "impossible_travel",
            Self::NewDevice => "new_device",
            Self::SuspiciousIp => "suspicious_ip",
            Self::BreachedPassword => "breached_password",
            Self::BruteForce => "brute_force",
            Self::CanaryHit => "canary_hit",
        }
    }

    /// The signal of a name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }

    /// Where it comes from.
    #[must_use]
    pub const fn source(self) -> Source {
        match self {
            Self::ImpossibleTravel | Self::SuspiciousIp => Source::Network,
            Self::NewDevice => Source::Device,
            Self::BreachedPassword => Source::Breach,
            Self::BruteForce => Source::Counters,
            Self::CanaryHit => Source::Canary,
        }
    }

    /// Its weight in the score (PD, OP-151 m.3 (o)).
    #[must_use]
    pub const fn weight(self) -> u32 {
        match self {
            Self::CanaryHit => 100,
            Self::ImpossibleTravel => 60,
            Self::SuspiciousIp | Self::BreachedPassword => 40,
            Self::BruteForce => 30,
            Self::NewDevice => 20,
        }
    }
}

/// An input source of SL2. None of them observes how a person types, moves or feels (TN-47).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// The client address through the `GeoResolver`, and the account's last sign-in place.
    Network,
    /// The device marker of the browser.
    Device,
    /// The k-anonymity breach range.
    Breach,
    /// The login throttle counters.
    Counters,
    /// The realm's canary accounts.
    Canary,
}

impl Source {
    /// Every source.
    pub const ALL: [Self; 5] = [
        Self::Network,
        Self::Device,
        Self::Breach,
        Self::Counters,
        Self::Canary,
    ];

    /// The source's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Device => "device",
            Self::Breach => "breach",
            Self::Counters => "counters",
            Self::Canary => "canary",
        }
    }
}

/// The names of every field an assessment reads ([`crate::domain::assess::Inputs`]).
pub const INPUT_FIELDS: [&str; 8] = [
    "client_place",
    "last_place",
    "last_at_ms",
    "now_ms",
    "device_known",
    "prior_failures",
    "breach",
    "canary",
];

/// Words that would name a behavioural biometric or an emotion inference (TN-47).
pub const FORBIDDEN_INPUTS: [&str; 12] = [
    "keystroke",
    "typing",
    "mouse",
    "cursor",
    "gait",
    "touch",
    "swipe",
    "emotion",
    "sentiment",
    "face",
    "voice",
    "biometric",
];

#[cfg(test)]
mod tests {
    use super::*;

    // TN-47: no signal, source or input is a behavioural biometric or an emotion inference;
    // the set is closed, so a new input has to pass this list
    #[test]
    fn no_behavioural_biometrics_or_emotion_input() {
        let names: Vec<&str> = RiskSignal::ALL
            .iter()
            .map(|s| s.name())
            .chain(Source::ALL.iter().map(|s| s.name()))
            .chain(INPUT_FIELDS)
            .collect();
        for n in &names {
            for f in FORBIDDEN_INPUTS {
                assert!(!n.contains(f), "{n} names {f}");
            }
        }
        assert_eq!(
            RiskSignal::ALL.map(RiskSignal::name),
            [
                "impossible_travel",
                "new_device",
                "suspicious_ip",
                "breached_password",
                "brute_force",
                "canary_hit"
            ]
        );
        for s in RiskSignal::ALL {
            assert_eq!(RiskSignal::from_name(s.name()), Some(s));
        }
    }
}
