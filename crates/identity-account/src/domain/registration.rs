//! Self-service registration rules (§12.3.6, TN-80, TN-81, TN-82, TN-83, OP-153 m.3 (g), (h)):
//! the address check, the canonical form used only for abuse scoring and per-person limits, the
//! privacy relay allowlist, disposable-domain scoring and the cheap gate's rates. Nothing here
//! refuses on a score: a score only feeds step-up.

use std::collections::BTreeSet;

use suiss_crypto::digest::sha256;

use crate::domain::bot::BotSignal;
use crate::domain::gcra::Gcra;
use crate::domain::identifier::normalize;

/// The out-of-band code's lifetime (OP-153 m.3 (g)): 15 minutes, after which a pending
/// registration expires softly.
pub const CODE_TTL_MS: u64 = 15 * 60_000;

/// Wrong codes a pending registration takes before it dies (OP-153 m.3 (g)).
pub const CODE_ATTEMPTS: u8 = 5;

/// Digits of the registration code (OP-153 m.3 (g)).
pub const CODE_DIGITS: usize = 8;

/// The response floor of every registration answer (TN-80 invariant 4, OP-153 m.3 (g)).
pub const FLOOR_MS: u64 = 250;

/// Cheap gate per address prefix (/24, /48): 20 an hour, bursts of 5, before any hashing or
/// lookup (TN-80 invariant 5, TN-83, OP-153 m.3 (g)).
pub const IP_RATE: Gcra = Gcra {
    interval_ms: 180_000,
    burst: 5,
};

/// Codes per canonical address: 3 an hour (OP-153 m.3 (g)).
pub const EMAIL_HOURLY: Gcra = Gcra {
    interval_ms: 1_200_000,
    burst: 3,
};

/// Codes per canonical address: 10 a day (OP-153 m.3 (g)).
pub const EMAIL_DAILY: Gcra = Gcra {
    interval_ms: 8_640_000,
    burst: 10,
};

/// Privacy relays: never disposable, treated as ordinary addresses (TN-81, OP-153 m.3 (h)).
pub const RELAY_ALLOWLIST: [&str; 5] = [
    "privaterelay.appleid.com",
    "mozmail.com",
    "duck.com",
    "simplelogin.com",
    "addy.io",
];

/// Providers whose `+tag` is stripped for the canonical form (OP-153 m.3 (g)).
const PLUS_PROVIDERS: [&str; 14] = [
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "icloud.com",
    "me.com",
    "fastmail.com",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "yandex.com",
    "yandex.ru",
    "yandex.com.tr",
];

/// The only domains whose local part loses its dots (TN-80 invariant 9).
const DOT_PROVIDERS: [&str; 2] = ["gmail.com", "googlemail.com"];

/// Why an address cannot receive mail at all (TN-80 step 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EmailError {
    /// Not `local@domain` with a host name domain.
    #[error("not an e-mail address")]
    Syntax,
}

fn label_ok(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !l.starts_with('-')
        && !l.ends_with('-')
}

fn domain_ok(d: &str) -> bool {
    d.len() <= 253 && d.contains('.') && d.split('.').all(label_ok)
}

/// An address as typed, checked for syntax (TN-80 step 1). The raw form is stored and used for
/// delivery; [`Email::canonical`] never reaches the user (TN-80 invariants 7, 8).
#[derive(Clone, PartialEq, Eq)]
pub struct Email {
    raw: String,
    domain: String,
}

impl core::fmt::Debug for Email {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Email([redacted])")
    }
}

impl Email {
    /// Normalizes (NFKC, trim) and checks `raw`.
    ///
    /// # Errors
    /// [`EmailError::Syntax`].
    pub fn parse(raw: &str) -> Result<Self, EmailError> {
        let raw = normalize(raw);
        let (local, domain) = raw.rsplit_once('@').ok_or(EmailError::Syntax)?;
        let local_ok = !local.is_empty()
            && local.chars().count() <= 64
            && !local.contains('@')
            && !local.chars().any(|c| c.is_control() || c.is_whitespace());
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if !local_ok || raw.chars().count() > 320 || !domain_ok(&domain) {
            return Err(EmailError::Syntax);
        }
        Ok(Self {
            raw: raw.clone(),
            domain,
        })
    }

    /// The address as typed, normalized.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The domain, lower case.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The canonical form (OP-153 m.3 (g)): lower case; dots dropped only on Gmail; the `+tag`
    /// dropped only at the listed providers. For abuse scoring and per-person limits only.
    #[must_use]
    pub fn canonical(&self) -> String {
        let (local, _) = self.raw.rsplit_once('@').unwrap_or((&self.raw, ""));
        let mut local = local.to_lowercase();
        let mut domain = self.domain.clone();
        if PLUS_PROVIDERS.contains(&domain.as_str())
            && let Some((head, _)) = local.split_once('+')
        {
            local = head.to_owned();
        }
        if DOT_PROVIDERS.contains(&domain.as_str()) {
            local.retain(|c| c != '.');
            domain = String::from("gmail.com");
        }
        format!("{local}@{domain}")
    }

    /// Whether the domain is a privacy relay (TN-81).
    #[must_use]
    pub fn relay(&self) -> bool {
        RELAY_ALLOWLIST.iter().any(|r| under(&self.domain, r))
    }
}

fn under(domain: &str, listed: &str) -> bool {
    domain == listed
        || domain
            .strip_suffix(listed)
            .is_some_and(|p| p.ends_with('.'))
}

const DISPOSABLE: &str = include_str!("../../../../conformance/data/disposable-email-domains.txt");

/// The disposable-domain list (`conformance/data/disposable-email-domains.txt`, TN-81): scored,
/// never refused.
#[derive(Clone, Debug, Default)]
pub struct DisposableDomains(BTreeSet<String>);

/// A line of the disposable list outside its format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("line {0}: not a lower-case domain")]
pub struct DisposableListError(pub usize);

impl DisposableDomains {
    /// The list Access ships.
    ///
    /// # Errors
    /// [`DisposableListError`] when the shipped file is outside its format.
    pub fn embedded() -> Result<Self, DisposableListError> {
        let mut set = BTreeSet::new();
        for (n, line) in DISPOSABLE.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !domain_ok(line) || line.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(DisposableListError(n.saturating_add(1)));
            }
            set.insert(line.to_owned());
        }
        Ok(Self(set))
    }

    /// Whether `domain` or a domain above it is listed; a privacy relay never is.
    #[must_use]
    pub fn contains(&self, domain: &str) -> bool {
        if RELAY_ALLOWLIST.iter().any(|r| under(domain, r)) {
            return false;
        }
        let mut d = domain;
        loop {
            if self.0.contains(d) {
                return true;
            }
            match d.split_once('.') {
                Some((_, rest)) if rest.contains('.') => d = rest,
                _ => return false,
            }
        }
    }

    /// How many domains the list holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What the abuse score saw (TN-80 step 6, TN-81). A decision input for step-up only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assessment {
    /// The bot signal.
    pub bot: BotSignal,
    /// The domain is on the disposable list.
    pub disposable: bool,
}

impl Assessment {
    /// 0 (likely abuse) to 100 (likely a person).
    #[must_use]
    pub const fn score(&self) -> u8 {
        let base: u8 = match self.bot {
            BotSignal::Positive => 100,
            BotSignal::Score(s) => {
                if s > 100 {
                    100
                } else {
                    s
                }
            }
            BotSignal::Unavailable => 50,
        };
        if self.disposable { base / 2 } else { base }
    }

    /// Whether the request takes the extra step; never a refusal (OP-153 m.3 (h)).
    #[must_use]
    pub const fn step_up(&self) -> bool {
        self.disposable || self.bot.step_up()
    }

    /// The score's band, a telemetry label without personal data (OP-47).
    #[must_use]
    pub const fn band(&self) -> &'static str {
        match self.score() {
            0..=24 => "low",
            25..=74 => "medium",
            _ => "high",
        }
    }
}

/// A profile field the realm may require at registration (TN-132; the console's
/// `REQUIRED_FIELDS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileField {
    /// `email`: always present on this flow.
    Email,
    /// `name`: the display name.
    Name,
}

impl ProfileField {
    /// The field of a stored name; `None` for one the hosted sign-up cannot collect.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "email" => Some(Self::Email),
            "name" => Some(Self::Name),
            _ => None,
        }
    }
}

/// The counter key of the registration gate: a digest, so the counters keep no personal data.
#[must_use]
pub fn gate_key(tag: u8, tenant: &[u8; 16], realm: &[u8; 16], part: &[u8]) -> [u8; 32] {
    let mut m = b"access/registration-gate/v1\0".to_vec();
    m.push(tag);
    m.extend_from_slice(tenant);
    m.extend_from_slice(realm);
    m.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
    m.extend_from_slice(part);
    sha256(&m)
}

/// Gate key tags.
pub mod tag {
    /// One address prefix.
    pub const IP: u8 = 1;
    /// One canonical address, hourly.
    pub const EMAIL_HOUR: u8 = 2;
    /// One canonical address, daily.
    pub const EMAIL_DAY: u8 = 3;
    /// One account's e-mail sends (TN-83 (6), §10.2.1).
    pub const ACCOUNT_MAIL: u8 = 4;
}

/// Sends to one account per hour, a mail-bomb amplifier's cap (TN-83 (6), IDP-3).
pub const ACCOUNT_MAIL_RATE: Gcra = Gcra {
    interval_ms: 1_200_000,
    burst: 3,
};

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // TN-80
    #[test]
    fn only_deliverable_shapes_parse() {
        assert!(Email::parse(" Ａda@Example.COM ").is_ok());
        for bad in [
            "",
            "ada",
            "@x.com",
            "ada@",
            "ada@localhost",
            "a da@x.com",
            "ada@-x.com",
        ] {
            assert_eq!(Email::parse(bad), Err(EmailError::Syntax), "{bad}");
        }
        assert_eq!(
            Email::parse("Ada@Example.COM").unwrap().domain(),
            "example.com"
        );
    }

    // TN-80, OP-153 m.3 (g)
    #[test]
    fn the_canonical_form_drops_dots_only_on_gmail_and_tags_only_at_listed_providers() {
        let c = |s: &str| Email::parse(s).unwrap().canonical();
        assert_eq!(c("A.Da+news@GoogleMail.com"), "ada@gmail.com");
        assert_eq!(c("a.da+x@outlook.com"), "a.da@outlook.com");
        assert_eq!(c("a.da+x@acme.example"), "a.da+x@acme.example");
        assert_eq!(c("ada+x@yandex.com.tr"), "ada@yandex.com.tr");
        assert_eq!(
            Email::parse("A.Da@gmail.com").unwrap().raw(),
            "A.Da@gmail.com"
        );
    }

    // TN-81, OP-153 m.3 (h)
    #[test]
    fn disposable_is_scored_relays_are_not_disposable() {
        let list = DisposableDomains::embedded().unwrap();
        assert!(list.len() > 5_000);
        assert!(list.contains("mailinator.com"));
        assert!(list.contains("x.mailinator.com"));
        for relay in RELAY_ALLOWLIST {
            assert!(!list.contains(relay));
            assert!(Email::parse(&format!("a@{relay}")).unwrap().relay());
        }
        assert!(!list.contains("gmail.com"));
        let a = Assessment {
            bot: BotSignal::Score(90),
            disposable: true,
        };
        assert!(a.step_up());
        assert_eq!(a.score(), 45);
        let clean = Assessment {
            bot: BotSignal::Positive,
            disposable: false,
        };
        assert!(!clean.step_up());
        assert_eq!(clean.band(), "high");
    }
}
