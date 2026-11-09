//! The dynamic client registration profile (RFC 7591, OP-154 m.3 (j), §11.4.5 #31-35, AS-A1):
//! kept only for backward compatibility, off by default. `/register` opens only with an initial
//! access token the realm's decided policy names (a gate, never authority); a registration is
//! checked as a CIMD document is, with no secret, no fetched URL, no wildcard redirect and an
//! explicit error for an `application_type` its redirects do not fit.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde_json::{Map, Value};

use crate::domain::cimd::{self, ApplicationType, CimdError, Document, is_loopback};

/// Registrations one IP prefix may make in an hour (OP-154 m.3 (j)).
pub const PER_PREFIX_PER_HOUR: u64 = 10;
/// Registrations a realm takes in a day.
pub const PER_REALM_PER_DAY: u64 = 100;
/// Live DCR clients a realm keeps.
pub const MAX_LIVE: u64 = 1000;
/// A DCR client unused this long retires (soft).
pub const UNUSED_MS: u64 = 30 * 86_400_000;
/// Most initial access tokens and redirect domains a policy names.
pub const MAX_TOKENS: usize = 16;
/// Most redirect domains a policy names.
pub const MAX_DOMAINS: usize = 64;
/// The prefix of every DCR `client_id`.
pub const CLIENT_PREFIX: &str = "dcr_";

/// The realm's DCR policy as decided (`idp.client.dcr_policy`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DcrPolicy {
    /// Whether `/register` is open.
    pub enabled: bool,
    /// The hosts redirect URIs may name; empty is any host.
    pub domains: BTreeSet<String>,
    /// SHA-256 digests of the initial access tokens that open `/register`.
    pub tokens: BTreeSet<[u8; 32]>,
}

impl DcrPolicy {
    /// Whether this policy admits only what `old` admitted (`dcr_policy_tighten`, CT1): closed,
    /// or open with fewer tokens and redirect domains; anything else is `dcr_policy` (CT2).
    #[must_use]
    pub fn narrows(&self, old: &Self) -> bool {
        if !self.enabled {
            return true;
        }
        let domains = if old.domains.is_empty() {
            true
        } else {
            !self.domains.is_empty() && self.domains.is_subset(&old.domains)
        };
        old.enabled && self.tokens.is_subset(&old.tokens) && domains
    }

    /// Whether the policy still admits a client registered with `token` whose redirects go to
    /// `hosts` (§11.4.5 #35: a tightened policy is applied retroactively).
    #[must_use]
    pub fn admits(&self, token: &[u8; 32], hosts: &[String]) -> bool {
        let domains: Vec<String> = self.domains.iter().cloned().collect();
        self.enabled
            && self.tokens.contains(token)
            && (domains.is_empty() || hosts.iter().all(|h| cimd::domain_admitted(&domains, h)))
    }

    /// Checks the sizes and that every domain is a lower-case DNS name.
    #[must_use]
    pub fn check(&self) -> bool {
        self.domains.len() <= MAX_DOMAINS
            && self.tokens.len() <= MAX_TOKENS
            && self.domains.iter().all(|d| {
                let d = d.strip_prefix("*.").unwrap_or(d);
                (1..=253).contains(&d.len())
                    && d.split('.').all(|l| {
                        (1..=63).contains(&l.len())
                            && l.bytes()
                                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                    })
            })
            && (!self.enabled || !self.tokens.is_empty())
    }
}

/// Why a registration is refused (RFC 7591 §3.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A redirect URI that is malformed, a wildcard, or not one the `application_type` allows.
    RedirectUri,
    /// Any other metadata Access does not take.
    Metadata,
}

impl Refused {
    /// The RFC 7591 error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RedirectUri => "invalid_redirect_uri",
            Self::Metadata => "invalid_client_metadata",
        }
    }

    /// The description, explicit about what to fix (§11.4.5 #34).
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::RedirectUri => {
                "redirect_uris must be https for application_type web, or loopback http or a private scheme for native; no wildcard, fragment or query"
            }
            Self::Metadata => {
                "client_name, redirect_uris and an application_type that fits them are required; only token_endpoint_auth_method none is registered, without secrets or fetched URLs"
            }
        }
    }
}

const FETCHED: [&str; 6] = [
    "jwks_uri",
    "logo_uri",
    "client_uri",
    "policy_uri",
    "tos_uri",
    "sector_identifier_uri",
];

/// The registration `body` as the client `client_id` will be known: checked as a CIMD document
/// is, plus the DCR rules. Returns the stored metadata and its parse.
///
/// # Errors
/// [`Refused`].
pub fn register(body: &[u8], client_id: &str) -> Result<(Vec<u8>, Document), Refused> {
    let Ok(Value::Object(mut doc)) = serde_json::from_slice::<Value>(body) else {
        return Err(Refused::Metadata);
    };
    if doc.contains_key("client_id") || FETCHED.iter().any(|f| doc.contains_key(*f)) {
        return Err(Refused::Metadata);
    }
    // §11.4.5 #34, SEP-837
    let loopback = matches!(doc.get("redirect_uris"), Some(Value::Array(u))
        if u.iter().filter_map(Value::as_str).any(is_loopback));
    if loopback && doc.get("application_type").and_then(Value::as_str) != Some("native") {
        return Err(Refused::RedirectUri);
    }
    if !matches!(
        doc.get("token_endpoint_auth_method")
            .and_then(Value::as_str),
        None | Some("none")
    ) {
        return Err(Refused::Metadata);
    }
    for (field, allowed) in [
        ("grant_types", &["authorization_code", "refresh_token"][..]),
        ("response_types", &["code"][..]),
    ] {
        if let Some(v) = doc.get(field) {
            let ok = matches!(v, Value::Array(a)
                if a.iter().all(|x| x.as_str().is_some_and(|s| allowed.contains(&s))));
            if !ok {
                return Err(Refused::Metadata);
            }
        }
    }
    let kept: Map<String, Value> = [
        "client_name",
        "redirect_uris",
        "application_type",
        "token_endpoint_auth_method",
    ]
    .iter()
    .filter_map(|k| doc.remove(*k).map(|v| (String::from(*k), v)))
    .chain([(String::from("client_id"), Value::from(client_id))])
    .collect();
    let bytes = serde_json::to_vec(&Value::Object(kept)).map_err(|_| Refused::Metadata)?;
    match cimd::parse(&bytes, client_id) {
        Ok(d) if d.application_type == ApplicationType::Native || !loopback => Ok((bytes, d)),
        Ok(_) | Err(CimdError::Redirect) => Err(Refused::RedirectUri),
        Err(_) => Err(Refused::Metadata),
    }
}

/// The prefix a registration's rate is counted by: the /24 of an IPv4 address, the /56 of an
/// IPv6 one.
#[must_use]
pub fn ip_prefix(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v) => {
            let [first, second, third, fourth, ..] = v.segments();
            format!("{first:x}:{second:x}:{third:x}:{:x}::/56", fourth & 0xff00)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(enabled: bool, domains: &[&str], tokens: &[u8]) -> DcrPolicy {
        DcrPolicy {
            enabled,
            domains: domains.iter().map(|d| String::from(*d)).collect(),
            tokens: tokens.iter().map(|t| [*t; 32]).collect(),
        }
    }

    // OP-154 m.3 (a), (j): closing or dropping tokens and domains is the CT1 tighten
    #[test]
    fn only_a_narrower_policy_is_a_tighten() {
        let old = p(true, &["app.example"], &[1, 2]);
        assert!(p(false, &[], &[]).narrows(&old));
        assert!(p(true, &["app.example"], &[1]).narrows(&old));
        assert!(!p(true, &["app.example"], &[1, 3]).narrows(&old));
        assert!(!p(true, &[], &[1]).narrows(&old), "any host is wider");
        assert!(!p(true, &["app.example"], &[1]).narrows(&p(false, &[], &[])));
    }

    // §11.4.5 #31
    #[test]
    fn registrations_are_counted_by_network_prefix() {
        assert_eq!(ip_prefix("192.0.2.77".parse().unwrap()), "192.0.2.0/24");
        assert_eq!(
            ip_prefix("2001:db8:1:2ff::1".parse().unwrap()),
            "2001:db8:1:200::/56"
        );
    }

    // §11.4.5 #32, #34
    #[test]
    fn a_registration_is_refused_explicitly() {
        let id = "dcr_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let ok = br#"{"client_name":"A","redirect_uris":["https://a.example/cb"]}"#;
        assert!(register(ok, id).is_ok());
        let star = br#"{"client_name":"A","redirect_uris":["https://*.a.example/cb"]}"#;
        assert_eq!(register(star, id).err(), Some(Refused::RedirectUri));
        let native =
            br#"{"client_name":"A","redirect_uris":["http://127.0.0.1:9/cb"],"application_type":"native"}"#;
        assert!(register(native, id).is_ok());
        let silent = br#"{"client_name":"A","redirect_uris":["http://127.0.0.1:9/cb"]}"#;
        assert_eq!(register(silent, id).err(), Some(Refused::RedirectUri));
        let jwks = br#"{"client_name":"A","redirect_uris":["https://a.example/cb"],"jwks_uri":"https://a.example/j"}"#;
        assert_eq!(register(jwks, id).err(), Some(Refused::Metadata));
    }
}
