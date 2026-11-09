//! Hierarchical workload identifiers and the selectors over them (§11.12.1, §11.12.2,
//! §11.21.1 #15, AG-30).
//!
//! A workload identifier is a `spiffe://<trust-domain>/<path>` SPIFFE ID or a
//! `wimse://<trust-domain>/<path>` WIMSE identifier: no query, fragment, user info or port, at
//! most 2048 bytes, compared as an exact string. It is a Claim value and an actor-binding
//! input, never authority: the SPIFFE trust domain is neither an Access identity domain nor an
//! `AuthorityDomain`.
//!
//! A [`Selector`] is rule-shaped (MD-4): an exact identifier, or every identifier below a path
//! written `…/*`, matched on whole path segments. It names the set of workloads a registration
//! admits; it grants nothing. Any other wildcard is not a pattern and matches no holder.

use suiss_crypto::digest::context_digest;

/// Longest identifier (WIMSE identifier §3, SPIFFE ID §2).
pub const MAX_URI: usize = 2048;

/// Digest context of a trust domain's issuer id.
pub const TRUST_DOMAIN_CONTEXT: &str = "access/workload-trust-domain/v1";

/// The two identifier schemes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scheme {
    /// `spiffe://`.
    Spiffe,
    /// `wimse://`.
    Wimse,
}

impl Scheme {
    /// The scheme prefix, `spiffe://` or `wimse://`.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Spiffe => "spiffe://",
            Self::Wimse => "wimse://",
        }
    }
}

/// Why an identifier is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WorkloadError {
    /// Longer than [`MAX_URI`].
    #[error("too long")]
    Length,
    /// Neither `spiffe://` nor `wimse://`.
    #[error("scheme")]
    Scheme,
    /// The trust domain is empty or holds a character outside `[a-z0-9._-]`.
    #[error("trust domain")]
    TrustDomain,
    /// No path, an empty, `.` or `..` segment, a trailing slash or a character outside
    /// `[A-Za-z0-9._-]`.
    #[error("path")]
    Path,
}

/// A workload identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkloadId {
    uri: String,
    scheme: Scheme,
    path_at: usize,
}

fn trust_domain_ok(td: &str) -> bool {
    !td.is_empty()
        && td.len() <= 255
        && td
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b".-_".contains(&c))
}

fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
}

fn split(uri: &str) -> Result<(Scheme, &str, &str), WorkloadError> {
    if uri.len() > MAX_URI {
        return Err(WorkloadError::Length);
    }
    let (scheme, rest) = if let Some(r) = uri.strip_prefix(Scheme::Spiffe.prefix()) {
        (Scheme::Spiffe, r)
    } else if let Some(r) = uri.strip_prefix(Scheme::Wimse.prefix()) {
        (Scheme::Wimse, r)
    } else {
        return Err(WorkloadError::Scheme);
    };
    let (td, path) = rest.split_once('/').ok_or(WorkloadError::Path)?;
    if !trust_domain_ok(td) {
        return Err(WorkloadError::TrustDomain);
    }
    Ok((scheme, td, path))
}

impl WorkloadId {
    /// Parses `uri` (SPIFFE ID §2.1–2.3, WIMSE identifier §3).
    ///
    /// # Errors
    /// [`WorkloadError`].
    pub fn parse(uri: &str) -> Result<Self, WorkloadError> {
        let (scheme, td, path) = split(uri)?;
        if !path.split('/').all(segment_ok) {
            return Err(WorkloadError::Path);
        }
        let path_at = scheme
            .prefix()
            .len()
            .checked_add(td.len())
            .ok_or(WorkloadError::Length)?;
        Ok(Self {
            uri: String::from(uri),
            scheme,
            path_at,
        })
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    /// Its scheme.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Its trust domain.
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        self.uri
            .get(self.scheme.prefix().len()..self.path_at)
            .unwrap_or_default()
    }

    /// Its path, from the slash after the trust domain.
    #[must_use]
    pub fn path(&self) -> &str {
        self.uri.get(self.path_at..).unwrap_or_default()
    }
}

/// The issuer id the domain root's actor-binding Acceptance of a trust domain names
/// (OP-154 m.3 (r)): `SHA-256(context ‖ 0x00 ‖ scheme ‖ trust domain)`, its first 16 bytes. The
/// trust domain is accepted by that Acceptance alone; it is never an `AuthorityDomain`.
#[must_use]
pub fn trust_domain_issuer(scheme: Scheme, trust_domain: &str) -> [u8; 16] {
    let mut input = Vec::from(scheme.prefix().as_bytes());
    input.extend_from_slice(trust_domain.as_bytes());
    let d = context_digest(TRUST_DOMAIN_CONTEXT, &input).0;
    let mut id = [0; 16];
    for (o, b) in id.iter_mut().zip(d) {
        *o = b;
    }
    id
}

/// A rule-shaped selector over workload identifiers (§11.12.1, MD-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    /// Exactly one identifier.
    Exact(WorkloadId),
    /// Every identifier below a path, on whole segments: `prefix` ends with `/`.
    Below {
        /// The scheme.
        scheme: Scheme,
        /// The trust domain.
        trust_domain: String,
        /// The identifier prefix, ending with `/`.
        prefix: String,
    },
    /// A wildcard that is not a trailing `/*`: it matches no holder.
    Nothing,
}

impl Selector {
    /// Parses `text`: an identifier, or one ending in `/*` for everything below it
    /// (`draft-ietf-oauth-spiffe-client-auth` §5.1). A `*` anywhere else makes a selector that
    /// matches nothing.
    ///
    /// # Errors
    /// [`WorkloadError`] for text that is no identifier even without its wildcard.
    pub fn parse(text: &str) -> Result<Self, WorkloadError> {
        if let Some(base) = text.strip_suffix("/*")
            && !base.contains('*')
        {
            let prefix = format!("{base}/");
            let (scheme, td, path) = split(&prefix)?;
            let path = path.strip_suffix('/').unwrap_or(path);
            if !path.is_empty() && !path.split('/').all(segment_ok) {
                return Err(WorkloadError::Path);
            }
            return Ok(Self::Below {
                scheme,
                trust_domain: String::from(td),
                prefix: prefix.clone(),
            });
        }
        if text.contains('*') {
            split(text)?;
            return Ok(Self::Nothing);
        }
        WorkloadId::parse(text).map(Self::Exact)
    }

    /// Whether `id` is selected.
    #[must_use]
    pub fn matches(&self, id: &WorkloadId) -> bool {
        match self {
            Self::Exact(e) => e == id,
            Self::Below { prefix, .. } => id.as_str().starts_with(prefix.as_str()),
            Self::Nothing => false,
        }
    }

    /// The scheme and trust domain it selects in; `None` for [`Self::Nothing`].
    #[must_use]
    pub fn trust_domain(&self) -> Option<(Scheme, &str)> {
        match self {
            Self::Exact(e) => Some((e.scheme(), e.trust_domain())),
            Self::Below {
                scheme,
                trust_domain,
                ..
            } => Some((*scheme, trust_domain)),
            Self::Nothing => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // §11.12.2, Ek B 4136
    #[test]
    fn identifiers_follow_the_spiffe_and_wimse_grammar() {
        let id = WorkloadId::parse("spiffe://acme.example/agent/finance/a1").unwrap();
        assert_eq!(id.trust_domain(), "acme.example");
        assert_eq!(id.path(), "/agent/finance/a1");
        assert_eq!(id.scheme(), Scheme::Spiffe);
        let w = WorkloadId::parse("wimse://acme.example/svc/billing").unwrap();
        assert_eq!(w.scheme(), Scheme::Wimse);
        for bad in [
            "https://acme.example/agent",
            "spiffe://Acme.example/agent",
            "spiffe://acme.example",
            "spiffe://acme.example/",
            "spiffe://acme.example/agent/",
            "spiffe://acme.example//agent",
            "spiffe://acme.example/agent/../root",
            "spiffe://acme.example/agent?x=1",
            "spiffe://acme.example/agent#f",
            "spiffe://user@acme.example/agent",
            "spiffe://acme.example:443/agent",
            "spiffe://acme.example/a%20b",
        ] {
            assert!(WorkloadId::parse(bad).is_err(), "{bad}");
        }
        let long = format!("spiffe://acme.example/{}", "a".repeat(MAX_URI));
        assert_eq!(WorkloadId::parse(&long), Err(WorkloadError::Length));
        assert_ne!(
            WorkloadId::parse("spiffe://acme.example/Agent").unwrap(),
            WorkloadId::parse("spiffe://acme.example/agent").unwrap()
        );
    }

    // §11.12.1, MD-4, Ek B 4136, 4258
    #[test]
    fn a_wildcard_selector_matches_no_holder() {
        let a1 = WorkloadId::parse("spiffe://acme.example/agent/finance/a1").unwrap();
        for nothing in [
            "spiffe://acme.example/agent/*/a1",
            "spiffe://acme.example/agent/fin*",
            "spiffe://acme.example/agent/finance/a*",
            "spiffe://acme.example/*/*",
            "spiffe://acme.example/agent/finance/**",
        ] {
            let s = Selector::parse(nothing).unwrap();
            assert_eq!(s, Selector::Nothing, "{nothing}");
            assert!(!s.matches(&a1), "{nothing}");
        }
        assert!(Selector::parse("spiffe://*.example/agent").is_err());
    }

    // §11.12.1, MD-4, Ek B 4258
    #[test]
    fn a_rule_shaped_selector_matches_whole_segments() {
        let below = Selector::parse("spiffe://acme.example/agent/finance/*").unwrap();
        let yes = WorkloadId::parse("spiffe://acme.example/agent/finance/a1").unwrap();
        let deeper = WorkloadId::parse("spiffe://acme.example/agent/finance/eu/a2").unwrap();
        let sibling = WorkloadId::parse("spiffe://acme.example/agent/financex/a1").unwrap();
        let other_td = WorkloadId::parse("spiffe://beta.example/agent/finance/a1").unwrap();
        let wimse = WorkloadId::parse("wimse://acme.example/agent/finance/a1").unwrap();
        assert!(below.matches(&yes));
        assert!(below.matches(&deeper));
        assert!(!below.matches(&sibling));
        assert!(!below.matches(&other_td));
        assert!(!below.matches(&wimse));
        let exact = Selector::parse("spiffe://acme.example/agent/finance/a1").unwrap();
        assert!(exact.matches(&yes));
        assert!(!exact.matches(&deeper));
        assert_eq!(below.trust_domain(), Some((Scheme::Spiffe, "acme.example")));
    }

    // OP-154 m.3 (r), §11.12
    #[test]
    fn each_trust_domain_has_its_own_issuer_id() {
        let a = trust_domain_issuer(Scheme::Spiffe, "acme.example");
        assert_eq!(a, trust_domain_issuer(Scheme::Spiffe, "acme.example"));
        assert_ne!(a, trust_domain_issuer(Scheme::Spiffe, "beta.example"));
        assert_ne!(a, trust_domain_issuer(Scheme::Wimse, "acme.example"));
    }
}
