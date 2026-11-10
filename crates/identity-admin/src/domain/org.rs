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

/// The upstream an enterprise connection draft names (OP-153 m.3 (p), OP-155 m.3 (i)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DraftConnection {
    /// An OIDC issuer and the client id at it.
    Oidc {
        /// The upstream OIDC issuer.
        issuer: String,
        /// The client id at the upstream.
        client_id: String,
    },
    /// A SAML identity provider: its entity ID and metadata URL.
    Saml {
        /// The entity ID.
        entity_id: String,
        /// The `https` metadata URL.
        metadata_url: String,
    },
}

impl DraftConnection {
    /// Whether the draft is well formed: an `https` OIDC issuer with a bounded client id, or a
    /// bounded SAML entity ID with an `https` metadata URL.
    #[must_use]
    pub fn ok(&self) -> bool {
        let https = |u: &str, query: bool| {
            u.strip_prefix("https://")
                .and_then(|r| r.split(['/', '?']).next())
                .is_some_and(|h| !h.is_empty() && !h.contains('@'))
                && u.len() <= 2048
                && !u.chars().any(|c| {
                    c.is_whitespace() || c.is_control() || c == '#' || (!query && c == '?')
                })
        };
        match self {
            Self::Oidc { issuer, client_id } => {
                https(issuer, false)
                    && !client_id.is_empty()
                    && client_id.chars().count() <= 256
                    && !client_id.chars().any(char::is_control)
            }
            Self::Saml {
                entity_id,
                metadata_url,
            } => {
                https(metadata_url, true)
                    && !entity_id.is_empty()
                    && entity_id.len() <= 1024
                    && !entity_id
                        .chars()
                        .any(|c| c.is_whitespace() || c.is_control())
            }
        }
    }
}

/// An enterprise connection the connection manager drafts (TN-120, OP-153 m.3 (p)): it takes
/// effect only through `idp.upstream.register` (CT3) at the organization's root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsoDraft {
    /// The organization's Party.
    pub org: [u8; 16],
    /// The upstream it names.
    pub connection: DraftConnection,
}

impl SsoDraft {
    pub(crate) fn check(&self) -> Result<(), crate::domain::Invalid> {
        if self.connection.ok() {
            Ok(())
        } else {
            Err(crate::domain::Invalid::SsoDraft)
        }
    }

    pub(crate) fn to_value(&self) -> suiss_crypto::dcbor::Value {
        use suiss_crypto::dcbor::Value;
        let mut m = vec![(Value::text("org"), Value::Bytes(self.org.to_vec()))];
        match &self.connection {
            DraftConnection::Oidc { issuer, client_id } => {
                m.push((Value::text("issuer"), Value::text(issuer)));
                m.push((Value::text("client_id"), Value::text(client_id)));
            }
            DraftConnection::Saml {
                entity_id,
                metadata_url,
            } => {
                m.push((Value::text("protocol"), Value::text("saml")));
                m.push((Value::text("entity_id"), Value::text(entity_id)));
                m.push((Value::text("metadata_url"), Value::text(metadata_url)));
            }
        }
        Value::Map(m)
    }
}

/// The holder of an organization's rule-shaped Grants, such as its autojoin role Grant (C13,
/// TN-90): every Party with a live `org_member` Claim naming the organization's Party `org`
/// (OP-153 m.17 (c), m.25 (a)).
#[must_use]
pub fn org_members(org: [u8; 16]) -> access_kernel::model::SubjectSelector {
    access_kernel::model::SubjectSelector::Pred(std::collections::BTreeSet::from([
        access_kernel::model::Conjunct {
            claim_class: access_kernel::claim::body::Class::OrgMember.name(),
            value: Some(access_kernel::model::EqValue::Bytes(org.to_vec())),
        },
    ]))
}

/// Days the enterprise connection manager template Grant lives (TN-120, PD).
pub const SSO_MANAGER_DAYS: u64 = 7;

/// The Named `AuthoritySet` of the enterprise connection manager template (TN-120): a Kernel
/// identifier, so the Grant that pins it reads back (OP-153 m.17 (h)).
pub const SSO_MANAGER_ROLE: &str = "enterprise_connection_manager";

/// The enterprise connection manager's Named `AuthoritySet` in realm `slug` for organization
/// Party `org` (TN-120): `idp.org.sso_draft` on that organization only.
#[must_use]
pub fn sso_manager_set(slug: &str, org: [u8; 16]) -> access_kernel::model::AuthoritySet {
    use access_kernel::model::{ActionSet, AuthoritySet, ResourceSelector, Structural};
    AuthoritySet {
        actions: ActionSet {
            exact: std::collections::BTreeSet::from([
                access_internal_api::idp::IdpAction::OrgSsoDraft.action_ref(),
            ]),
            prefix: std::collections::BTreeSet::new(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: String::from(access_internal_api::idp::RESOURCE_NAMESPACE),
            prefix: vec![
                String::from(slug),
                String::from("org"),
                access_kernel::json::b64url_encode(&org),
            ],
            kind: None,
            attrs: std::collections::BTreeMap::new(),
        }),
        params: std::collections::BTreeMap::new(),
        recipient: None,
        purpose: None,
    }
}

/// The enterprise connection manager template Grant (TN-120, OP-153 m.3 (p)): narrow
/// ([`sso_manager_set`] at `version`), [`SSO_MANAGER_DAYS`] from `from_ms`, not delegable
/// (depth 0), held by `holder` in its own capacity only.
#[must_use]
pub fn sso_manager_grant(
    (slug, org): (&str, [u8; 16]),
    holder: access_kernel::model::Id,
    basis: access_kernel::meta::GrantBasis,
    version: u64,
    from_ms: u64,
) -> access_kernel::meta::GrantContent {
    use access_kernel::model::{
        CanonicalAuthority, ConstraintSet, DelegationTerms, SubjectSelector,
    };
    let set = sso_manager_set(slug, org);
    access_kernel::meta::GrantContent {
        basis,
        holder: SubjectSelector::Party(holder),
        authority: CanonicalAuthority {
            authority: set.clone(),
            constraints: ConstraintSet {
                validity: access_kernel::model::Window {
                    from: from_ms,
                    until: from_ms.saturating_add(SSO_MANAGER_DAYS.saturating_mul(86_400_000)),
                },
                conditions: std::collections::BTreeSet::new(),
                budget: std::collections::BTreeSet::new(),
            },
            delegation: DelegationTerms {
                depth: 0,
                downstream_holder_class: None,
            },
            requirements: std::collections::BTreeSet::new(),
        },
        agency: std::collections::BTreeSet::from([access_kernel::combinator::Capacity::Own]),
        named: Some((
            String::from(SSO_MANAGER_ROLE),
            version,
            access_kernel::meta::authority_set_digest(&set),
        )),
    }
}

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

    // OP-153 m.17 (c), m.25 (a), C13
    #[test]
    fn an_organizations_members_are_selected_by_its_own_party() {
        use access_kernel::codec::Canonical as _;
        let a = org_members([1; 16]);
        assert_ne!(a, org_members([2; 16]));
        assert_eq!(
            access_kernel::model::SubjectSelector::from_value(&a.to_value()).unwrap(),
            a
        );
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
