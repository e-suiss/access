//! Non-interactive bot defence (OP-153 m.1 (b), m.3 (h)): what a bot signal says about a
//! registration or recovery request. No CAPTCHA puzzle is ever shown and reCAPTCHA is never an
//! adapter. Privacy Pass (RFC 9577) is a positive signal only; a score feeds step-up, never a
//! refusal; with no provider the signal is `Unavailable` and the request goes on through the
//! cheap gate and an out-of-band code.

/// The providers a deployment can configure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BotProvider {
    /// Friendly Captcha, the default score adapter.
    FriendlyCaptcha,
    /// Cloudflare Turnstile, optional.
    Turnstile,
    /// A Privacy Pass token issuer (RFC 9577): positive only.
    PrivacyPass,
}

impl BotProvider {
    /// The configuration name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::FriendlyCaptcha => "friendly_captcha",
            Self::Turnstile => "turnstile",
            Self::PrivacyPass => "privacy_pass",
        }
    }

    /// The provider of a configuration name; reCAPTCHA has none (OP-153 m.1 (b)).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::FriendlyCaptcha, Self::Turnstile, Self::PrivacyPass]
            .into_iter()
            .find(|p| p.name() == name)
    }
}

/// What the signal says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BotSignal {
    /// A valid Privacy Pass token: positive evidence of a human client.
    Positive,
    /// A provider's score, 0 (bot) to 100 (human).
    Score(u8),
    /// No provider, no token or the provider could not answer.
    Unavailable,
}

/// The score at or above which a request needs no extra step.
pub const STEP_UP_BELOW: u8 = 50;

impl BotSignal {
    /// Whether the request should take an extra step (an out-of-band code); a signal never
    /// refuses on its own (OP-153 m.3 (h)).
    #[must_use]
    pub const fn step_up(self) -> bool {
        match self {
            Self::Positive => false,
            Self::Score(s) => s < STEP_UP_BELOW,
            Self::Unavailable => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-153 m.1 (b), m.3 (h)
    #[test]
    fn a_signal_steps_up_and_never_refuses_and_recaptcha_is_no_provider() {
        assert!(!BotSignal::Positive.step_up());
        assert!(!BotSignal::Score(90).step_up());
        assert!(BotSignal::Score(10).step_up());
        assert!(BotSignal::Unavailable.step_up());
        assert_eq!(BotProvider::parse("recaptcha"), None);
        assert_eq!(
            BotProvider::parse("friendly_captcha"),
            Some(BotProvider::FriendlyCaptcha)
        );
    }
}
