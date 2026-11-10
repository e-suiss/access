//! The hosts a custom domain may be (OP-156 m.3 (i), TN-20): a lower-case DNS name of at least
//! three labels below a registrable domain, outside the deployment's base domain, never
//! `localhost` and never a public suffix. The registration names its DNS records: the TXT
//! challenge at `_access-challenge.<host>` and a CNAME to the realm's own `<slug>.<base>`.

use access_identity_webauthn::domain::psl::Psl;
use access_identity_webauthn::domain::rp::PublicSuffix as _;

/// The label of the TXT challenge record (OP-156 m.3 (i)).
pub const CHALLENGE_LABEL: &str = "_access-challenge";

/// Longest host (RFC 1035 §2.3.4).
pub const MAX_HOST: usize = 253;

/// Why a host cannot be a custom domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HostError {
    /// Not a lower-case DNS name of letters, digits and hyphens.
    #[error("not a DNS name")]
    Syntax,
    /// A public suffix, or a registrable domain itself, which cannot carry the CNAME.
    #[error("not below a registrable domain")]
    Registrable,
    /// The deployment's base domain, a name under it or above it.
    #[error("the deployment's own domain")]
    Base,
    /// `localhost` or a name under it (RFC 6761 §6.3).
    #[error("localhost")]
    Localhost,
}

impl HostError {
    /// Stable reason code (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Syntax => "domain-syntax",
            Self::Registrable => "domain-not-below-registrable",
            Self::Base => "domain-is-base",
            Self::Localhost => "domain-localhost",
        }
    }
}

fn label_ok(label: &str) -> bool {
    let b = label.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b.first().is_some_and(|c| *c != b'-')
        && b.last().is_some_and(|c| *c != b'-')
}

/// Whether `host` is a lower-case DNS name whose last label is not numeric.
#[must_use]
pub fn dns_name(host: &str) -> bool {
    host.len() <= MAX_HOST
        && host.split('.').count() >= 2
        && host.split('.').all(label_ok)
        && host
            .rsplit('.')
            .next()
            .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `host` is `localhost` or a name under it (RFC 6761 §6.3).
#[must_use]
pub fn localhost(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

/// Whether `a` is `b` or a name under it.
#[must_use]
pub fn at_or_under(a: &str, b: &str) -> bool {
    a == b || a.strip_suffix(b).is_some_and(|head| head.ends_with('.'))
}

/// Whether `host` is under the special-use `test` name (RFC 6761 §6.2), which never resolves
/// publicly and no public CA certifies.
#[must_use]
pub fn test_name(host: &str) -> bool {
    host.rsplit('.').next() == Some("test")
}

/// The deployment's base host: realm hostnames are `<slug>.<base>` (TN-10). A base under
/// `localhost` is the local profile's, and one under `test` exists only in test runs; neither
/// is a Suiss domain (OP-156 m.3 (i), RFC 6761).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Base(String);

impl Base {
    /// The base of the realm base host `host` (no port).
    #[must_use]
    pub fn new(host: &str) -> Self {
        Self(host.to_ascii_lowercase())
    }

    /// The host.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this base is a Suiss domain: any base a public deployment can have, that is any
    /// but a `localhost` or `test` name (RFC 6761).
    #[must_use]
    pub fn is_suiss(&self) -> bool {
        !localhost(&self.0) && !test_name(&self.0)
    }

    /// Whether `host` is the base, under it, or above it.
    #[must_use]
    pub fn touches(&self, host: &str) -> bool {
        at_or_under(host, &self.0) || at_or_under(&self.0, host)
    }

    /// The realm hostname a custom domain's CNAME must name: `<slug>.<base>`.
    #[must_use]
    pub fn realm_host(&self, slug: &str) -> String {
        format!("{slug}.{}", self.0)
    }
}

/// A host a realm may register as its custom domain.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CustomHost(String);

impl CustomHost {
    /// Checks `text` against the rules above for the deployment's `base`.
    ///
    /// # Errors
    /// [`HostError`].
    pub fn parse(text: &str, base: &Base) -> Result<Self, HostError> {
        if !dns_name(text) {
            return Err(HostError::Syntax);
        }
        if localhost(text) {
            return Err(HostError::Localhost);
        }
        if base.touches(text) {
            return Err(HostError::Base);
        }
        match Psl.registrable(text) {
            Some(reg) if reg.len() < text.len() => Ok(Self(text.to_owned())),
            _ => Err(HostError::Registrable),
        }
    }

    /// A host read back from the store, already checked when it was registered.
    #[must_use]
    pub fn stored(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The host.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name of its TXT challenge record.
    #[must_use]
    pub fn challenge_name(&self) -> String {
        format!("{CHALLENGE_LABEL}.{}", self.0)
    }

    /// Its registrable domain.
    #[must_use]
    pub fn registrable(&self) -> Option<&str> {
        Psl.registrable(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-156 m.3 (i), TN-20
    #[test]
    fn only_hosts_below_a_registrable_domain_outside_the_base_are_custom_domains() {
        let base = Base::new("suiss.id");
        for (text, want) in [
            ("login.acme.example", Ok(())),
            ("id.acme.co.uk", Ok(())),
            ("acme.example", Err(HostError::Registrable)),
            ("co.uk", Err(HostError::Registrable)),
            ("acme.suiss.id", Err(HostError::Base)),
            ("suiss.id", Err(HostError::Base)),
            ("id", Err(HostError::Syntax)),
            ("Login.acme.example", Err(HostError::Syntax)),
            ("login.acme.example.", Err(HostError::Syntax)),
            ("10.0.0.1", Err(HostError::Syntax)),
            ("acme.localhost", Err(HostError::Localhost)),
            ("-x.acme.example", Err(HostError::Syntax)),
        ] {
            assert_eq!(CustomHost::parse(text, &base).map(drop), want, "{text}");
        }
        let h = CustomHost::parse("login.acme.example", &base).unwrap();
        assert_eq!(h.challenge_name(), "_access-challenge.login.acme.example");
        assert_eq!(base.realm_host("acme"), "acme.suiss.id");
        assert!(base.is_suiss());
        assert!(!Base::new("localhost").is_suiss());
        assert!(!Base::new("access.test").is_suiss());
    }
}
