//! Organization rules that need no I/O (TN-89, TN-90, OP-153 m.3 (o)): when a verified domain may
//! carry an autojoin rule, and what an invitation's first acceptance may grant.

use access_identity_account::domain::consumer_domains::ConsumerDomains;
use access_store::orgs::DomainRow;

/// Why a domain may not carry an autojoin rule (TN-90).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AutojoinRefused {
    /// A consumer, free mail, ISP or university domain (OP-153 m.1 (d)).
    #[error("consumer domain")]
    ConsumerDomain,
    /// Another organization of the realm claims it too.
    #[error("domain contested")]
    Contested,
    /// This organization's claim is not verified now.
    #[error("domain not verified")]
    Unverified,
}

impl AutojoinRefused {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConsumerDomain => "consumer-domain",
            Self::Contested => "domain-contested",
            Self::Unverified => "domain-not-verified",
        }
    }
}

/// Whether organization `org` may turn autojoin on for `domain`, given every open claim of the
/// domain in the realm (TN-90, OP-153 m.3 (o)): never on a consumer domain, never while another
/// organization claims it, only on this organization's live verification.
///
/// # Errors
/// [`AutojoinRefused`].
pub fn autojoin(
    domain: &str,
    org: [u8; 16],
    claims: &[DomainRow],
    consumer: &ConsumerDomains,
) -> Result<(), AutojoinRefused> {
    if consumer.contains(domain) {
        return Err(AutojoinRefused::ConsumerDomain);
    }
    if claims.iter().any(|c| c.org != org) {
        return Err(AutojoinRefused::Contested);
    }
    if !claims.iter().any(|c| c.org == org && c.verified) {
        return Err(AutojoinRefused::Unverified);
    }
    Ok(())
}

/// Most days an invitation lives; seven by default (OP-153 m.3 (o)).
pub const INVITATION_MAX_DAYS: u32 = 30;

/// How long a domain verification holds before it must be verified again: 90 days
/// (OP-153 m.3 (o), PD).
pub const REVERIFY_S: i64 = 90 * 86_400;

/// How long after an MX or registrar change the verification lapses unless verified again:
/// 72 hours (OP-153 m.3 (o), PD).
pub const CHANGE_GRACE_S: i64 = 72 * 3_600;

/// How often the watch reads a verified domain's MX and registrar: daily (OP-153 m.3 (o)).
pub const WATCH_EVERY_S: i64 = 86_400;

/// How early before its re-verification time a verified domain is probed again (PD).
pub const REVERIFY_LEAD_S: i64 = 7 * 86_400;

/// The DNS name a TXT challenge is published at (OP-153 m.3 (o)).
#[must_use]
pub fn txt_name(domain: &str) -> String {
    format!("_suiss-access.{domain}")
}

/// The URL an HTTPS challenge is published at (OP-153 m.3 (o)).
#[must_use]
pub fn well_known(domain: &str) -> String {
    format!("https://{domain}/.well-known/suiss-access-verify")
}

/// The text a challenge is published as, in the TXT record or the HTTPS body.
pub const CHALLENGE_PREFIX: &str = "suiss-access-verify=";

/// Whether `domain` is a lower-case DNS name with at least two labels (TN-90).
#[must_use]
pub fn domain_ok(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    domain.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// How an organization proves control of a domain (TN-90).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// A TXT record at [`txt_name`].
    DnsTxt,
    /// A document at [`well_known`].
    Https,
    /// The upstream identity provider's `hd` or `tid`.
    Idp,
}

impl Method {
    /// The stored word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::DnsTxt => "dns_txt",
            Self::Https => "https",
            Self::Idp => "idp",
        }
    }

    /// The method of a stored word.
    #[must_use]
    pub fn parse(w: &str) -> Option<Self> {
        [Self::DnsTxt, Self::Https, Self::Idp]
            .into_iter()
            .find(|m| m.word() == w)
    }
}

/// A domain an organization claims, to be verified (TN-90, OP-153 m.3 (o)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainClaim {
    /// The organization's Party.
    pub org: [u8; 16],
    /// The domain, lower case.
    pub domain: String,
    /// How it will be verified.
    pub method: Method,
}

impl DomainClaim {
    pub(crate) fn check(&self) -> Result<(), crate::domain::Invalid> {
        if domain_ok(&self.domain) {
            Ok(())
        } else {
            Err(crate::domain::Invalid::DomainClaim)
        }
    }

    pub(crate) fn to_value(&self) -> suiss_crypto::dcbor::Value {
        use suiss_crypto::dcbor::Value;
        Value::Map(vec![
            (Value::text("org"), Value::Bytes(self.org.to_vec())),
            (Value::text("domain"), Value::text(&self.domain)),
            (Value::text("method"), Value::text(self.method.word())),
        ])
    }
}

/// An enterprise connection the connection manager drafts (TN-120, OP-153 m.3 (p)): it takes
/// effect only through `idp.upstream.register` (CT3) at the organization's root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsoDraft {
    /// The organization's Party.
    pub org: [u8; 16],
    /// The upstream OIDC issuer.
    pub issuer: String,
    /// The client id at the upstream.
    pub client_id: String,
}

impl SsoDraft {
    pub(crate) fn check(&self) -> Result<(), crate::domain::Invalid> {
        let host = self.issuer.strip_prefix("https://").unwrap_or("");
        if host.is_empty()
            || self.issuer.len() > 2048
            || self
                .issuer
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '#' || c == '?')
            || self.client_id.is_empty()
            || self.client_id.chars().count() > 256
            || self.client_id.chars().any(char::is_control)
        {
            return Err(crate::domain::Invalid::SsoDraft);
        }
        Ok(())
    }

    pub(crate) fn to_value(&self) -> suiss_crypto::dcbor::Value {
        use suiss_crypto::dcbor::Value;
        Value::Map(vec![
            (Value::text("org"), Value::Bytes(self.org.to_vec())),
            (Value::text("issuer"), Value::text(&self.issuer)),
            (Value::text("client_id"), Value::text(&self.client_id)),
        ])
    }
}

/// Days the enterprise connection manager template Grant lives (TN-120, PD).
pub const SSO_MANAGER_DAYS: u64 = 7;

/// The Named `AuthoritySet` of the enterprise connection manager template (TN-120).
pub const SSO_MANAGER_ROLE: &str = "enterprise-connection-manager";

/// Whether a published challenge `text` answers the claim's challenge hash: the text is the
/// token itself or [`CHALLENGE_PREFIX`] and the token, surrounding space ignored.
#[must_use]
pub fn answers(text: &str, challenge_hash: &[u8; 32]) -> bool {
    let t = text.trim();
    let token = t.strip_prefix(CHALLENGE_PREFIX).unwrap_or(t).trim();
    !token.is_empty()
        && suiss_crypto::secret::Secret::new(*challenge_hash)
            .ct_eq_bytes(&suiss_crypto::digest::sha256(token.as_bytes()))
}

/// The digest the watch compares an MX set by: the hosts lower-cased, sorted and unique.
#[must_use]
pub fn mx_digest(hosts: &[String]) -> [u8; 32] {
    let mut v: Vec<String> = hosts
        .iter()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    v.sort();
    v.dedup();
    suiss_crypto::digest::sha256(v.join("\n").as_bytes())
}

/// The digest the watch compares a registrar by; no registrar is a fixed digest of nothing.
#[must_use]
pub fn rdap_digest(registrar: Option<&str>) -> [u8; 32] {
    suiss_crypto::digest::sha256(registrar.unwrap_or("").trim().as_bytes())
}

/// What the watch does with one claim at `now_ms` (TN-90).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Watch {
    /// Not verified yet: probe the challenge.
    Verify,
    /// Verified and due its daily MX and registrar read, or near its re-verification time.
    Check {
        /// Probe the challenge again too.
        reverify: bool,
    },
    /// Nothing today.
    Rest,
}

/// The watch's step for a claim verified at `verified_ms` (none: unverified), due again at
/// `reverify_ms`, last checked at `checked_ms`, with an unconfirmed change since `changed_ms`.
#[must_use]
pub fn watch(
    verified_ms: Option<i64>,
    reverify_ms: Option<i64>,
    checked_ms: Option<i64>,
    changed_ms: Option<i64>,
    now_ms: i64,
) -> Watch {
    if verified_ms.is_none() {
        return Watch::Verify;
    }
    let near = reverify_ms
        .is_some_and(|r| r.saturating_sub(REVERIFY_LEAD_S.saturating_mul(1000)) <= now_ms);
    let due =
        checked_ms.is_none_or(|c| c.saturating_add(WATCH_EVERY_S.saturating_mul(1000)) <= now_ms);
    if near || changed_ms.is_some() {
        Watch::Check { reverify: true }
    } else if due {
        Watch::Check { reverify: false }
    } else {
        Watch::Rest
    }
}

/// Whether a role may be granted at an invitation's first acceptance (TN-89, OP-153 m.3 (o)): no
/// `anchor_*` meta-action and no reserved action — never owner or administrator at first accept.
#[must_use]
pub fn first_accept_allowed(actions: &[(String, String)], reserved: &[(String, String)]) -> bool {
    !actions.iter().any(|(ns, name)| {
        (ns == access_kernel::meta::NAMESPACE && name.starts_with("anchor_"))
            || reserved.iter().any(|(rn, rname)| rn == ns && rname == name)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn claim(org: u8, verified: bool) -> DomainRow {
        DomainRow {
            id: [org; 16],
            org: [org; 16],
            domain: String::from("acme.example"),
            verified,
            autojoin: false,
            changed_ms: None,
        }
    }

    // TN-90, OP-153 m.1 (d), Ek B 3612, 4039
    #[test]
    fn autojoin_is_refused_on_consumer_and_contested_domains() {
        let list = ConsumerDomains::embedded().unwrap();
        for d in ["gmail.com", "yandex.com.tr", "metu.edu.tr"] {
            assert_eq!(
                autojoin(d, [1; 16], &[claim(1, true)], &list),
                Err(AutojoinRefused::ConsumerDomain),
                "{d}"
            );
        }
        assert_eq!(
            autojoin(
                "acme.example",
                [1; 16],
                &[claim(1, true), claim(2, false)],
                &list
            ),
            Err(AutojoinRefused::Contested)
        );
        assert_eq!(
            autojoin("acme.example", [1; 16], &[claim(1, false)], &list),
            Err(AutojoinRefused::Unverified)
        );
        assert_eq!(
            autojoin("acme.example", [1; 16], &[claim(1, true)], &list),
            Ok(())
        );
    }

    // TN-90, OP-153 m.3 (o), Ek B 3611
    #[test]
    fn a_challenge_is_answered_only_by_its_own_token() {
        let h = suiss_crypto::digest::sha256(b"tok-123");
        assert!(answers("suiss-access-verify=tok-123", &h));
        assert!(answers("  tok-123\n", &h));
        assert!(!answers("suiss-access-verify=tok-124", &h));
        assert!(!answers("", &h));
        assert!(domain_ok("acme.example"));
        for d in [
            "acme",
            "Acme.example",
            "-a.example",
            "a..example",
            "a_b.example",
        ] {
            assert!(!domain_ok(d), "{d}");
        }
        assert_eq!(
            mx_digest(&[String::from("B.example."), String::from("a.example")]),
            mx_digest(&[String::from("a.example"), String::from("b.example")])
        );
    }

    // TN-90, OP-153 m.3 (o)
    #[test]
    fn the_watch_verifies_checks_daily_and_reverifies_early() {
        let day = 86_400_000;
        assert_eq!(watch(None, None, None, None, 0), Watch::Verify);
        assert_eq!(
            watch(Some(0), Some(90 * day), Some(0), None, day / 2),
            Watch::Rest
        );
        assert_eq!(
            watch(Some(0), Some(90 * day), Some(0), None, day),
            Watch::Check { reverify: false }
        );
        assert_eq!(
            watch(Some(0), Some(90 * day), Some(0), None, 84 * day),
            Watch::Check { reverify: true }
        );
        assert_eq!(
            watch(Some(0), Some(90 * day), Some(0), Some(1), day / 2),
            Watch::Check { reverify: true }
        );
    }

    // TN-89, Ek B 4038
    #[test]
    fn a_first_acceptance_never_grants_ownership_or_reserved_actions() {
        let a = |ns: &str, n: &str| (ns.to_owned(), n.to_owned());
        let reserved = [a("idp.account", "delete")];
        assert!(first_accept_allowed(
            &[a("idp.account", "suspend")],
            &reserved
        ));
        assert!(!first_accept_allowed(
            &[a("access", "anchor_transfer")],
            &reserved
        ));
        assert!(!first_accept_allowed(
            &[a("idp.account", "delete")],
            &reserved
        ));
    }
}
