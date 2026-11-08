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
