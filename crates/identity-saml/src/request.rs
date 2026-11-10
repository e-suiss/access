//! What an identity provider decides about one `AuthnRequest` (§10.6.1, SAML Profiles §4.1.4.1,
//! IDP-15): the requester is a registered service provider, the request is fresh, signed when
//! the registration says so and addressed here, its ACS matches the registration exactly, and
//! its `NameID` policy can be met. A refusal before the ACS is known is shown to the user and never
//! sent to the service provider; one after it is a SAML status sent to that exact ACS.

use access_edge_core::saml::{Facts, Kind, Signed};

use crate::sp::{Acs, NameIdFormat, Protocol, Sp};
use crate::time;
use crate::uri;

/// A refusal shown to the user; nothing is sent to the service provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The requester is not a live registration of the realm.
    UnknownSp,
    /// The message is not an `AuthnRequest`.
    Message,
    /// The registration requires a signed request and this one is not.
    Unsigned,
    /// `Destination` is not this identity provider's endpoint.
    Destination,
    /// `IssueInstant` is outside the window.
    Stale,
    /// The request identifier was seen before.
    Replay,
    /// The ACS URL or index is not registered exactly, or its binding differs (IDP-15).
    Acs,
    /// IdP-initiated SSO is not allowed for this registration (IDP-15).
    Unsolicited,
    /// `RelayState` is longer than 80 bytes or its HMAC does not hold.
    RelayState,
    /// The registration speaks another protocol.
    Protocol,
}

impl Refusal {
    /// The stable code of the error page.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownSp => "saml-unknown-sp",
            Self::Message => "saml-message",
            Self::Unsigned => "saml-unsigned-request",
            Self::Destination => "saml-destination",
            Self::Stale => "saml-stale-request",
            Self::Replay => "saml-replay",
            Self::Acs => "saml-acs-mismatch",
            Self::Unsolicited => "saml-unsolicited",
            Self::RelayState => "saml-relay-state",
            Self::Protocol => "saml-protocol",
        }
    }
}

/// A SAML status sent to the validated ACS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// `NoPassive`: `IsPassive` and the user would have to interact.
    NoPassive,
    /// `InvalidNameIDPolicy`: the format or qualifier cannot be met, or `AllowCreate="false"`
    /// with no persistent identifier for this service provider yet.
    InvalidNameIdPolicy,
}

impl Status {
    /// Top- and second-level status codes.
    #[must_use]
    pub const fn codes(self) -> (&'static str, &'static str) {
        match self {
            Self::NoPassive => (uri::STATUS_RESPONDER, uri::STATUS_NO_PASSIVE),
            Self::InvalidNameIdPolicy => (uri::STATUS_REQUESTER, uri::STATUS_INVALID_NAMEID_POLICY),
        }
    }
}

/// Longest `RelayState` (SAML Bindings §3.4.3).
pub const MAX_RELAY_STATE: usize = 80;

/// What the request asks once it is accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The exact registered ACS.
    pub acs: Acs,
    /// `InResponseTo`.
    pub in_response_to: String,
    /// The user may not be asked anything: `IsPassive` wins over `ForceAuthn`.
    pub passive: bool,
    /// A new authentication is required (and the request is not passive).
    pub force: bool,
    /// The `NameID` format to use.
    pub format: NameIdFormat,
    /// `AllowCreate`; `false` only when the request says so.
    pub allow_create: bool,
    /// `RequesterID`s, for the audit log.
    pub requesters: Vec<String>,
    /// `ProxyCount`, stored; Access never proxies.
    pub proxy_count: Option<u64>,
    /// A status to send instead of an assertion, decided without the session.
    pub status: Option<Status>,
}

/// The ACS `facts` name, matched exactly against the registration.
///
/// # Errors
/// [`Refusal::Acs`].
pub fn acs<'a>(sp: &'a Sp, facts: &Facts) -> Result<&'a Acs, Refusal> {
    let found = match (&facts.acs_url, facts.acs_index) {
        (Some(url), None) => sp.acs.iter().find(|a| &a.url == url),
        (None, Some(i)) => sp.acs.iter().find(|a| u64::from(a.index) == i),
        (None, None) => sp.default_acs(),
        (Some(_), Some(_)) => None,
    }
    .ok_or(Refusal::Acs)?;
    let wanted = if facts.soap {
        uri::BINDING_PAOS
    } else {
        facts
            .protocol_binding
            .as_deref()
            .unwrap_or(found.binding.uri())
    };
    if wanted != found.binding.uri() {
        return Err(Refusal::Acs);
    }
    Ok(found)
}

/// Decides an `AuthnRequest` from the worker's facts. `redirect_signed` is the verified
/// HTTP-Redirect signature, if any; `endpoints` are this identity provider's SSO URLs.
///
/// # Errors
/// [`Refusal`], shown to the user.
pub fn decide(
    sp: &Sp,
    facts: &Facts,
    redirect_signed: bool,
    endpoints: &[String],
    now: u64,
) -> Result<Accepted, Refusal> {
    if facts.kind != Kind::Authn {
        return Err(Refusal::Message);
    }
    if sp.protocol != Protocol::Saml2 {
        return Err(Refusal::Protocol);
    }
    if facts.issuer != sp.entity_id {
        return Err(Refusal::UnknownSp);
    }
    let signed = redirect_signed || matches!(facts.signed, Signed::Verified(_));
    if sp.authn_requests_signed && !signed {
        return Err(Refusal::Unsigned);
    }
    match &facts.destination {
        Some(d) if !endpoints.iter().any(|e| e == d) => return Err(Refusal::Destination),
        None if signed && !facts.soap => return Err(Refusal::Destination),
        _ => {}
    }
    let issued = time::parse(&facts.issue_instant).ok_or(Refusal::Stale)?;
    if !time::request_fresh(issued, now) {
        return Err(Refusal::Stale);
    }
    let acs = acs(sp, facts)?.clone();
    let passive = facts.is_passive;
    let mut status = None;
    let format = match facts.nameid_format.as_deref() {
        None => sp.nameid_format,
        Some(u) if u == uri::NAMEID_UNSPECIFIED => sp.nameid_format,
        Some(u) => match NameIdFormat::of_uri(u) {
            Some(f) if f == sp.nameid_format => f,
            _ => {
                status = Some(Status::InvalidNameIdPolicy);
                sp.nameid_format
            }
        },
    };
    if let Some(q) = &facts.sp_name_qualifier {
        let own = sp.affiliation.as_deref().unwrap_or(&sp.entity_id);
        if q != own {
            status = Some(Status::InvalidNameIdPolicy);
        }
    }
    Ok(Accepted {
        acs,
        in_response_to: facts.id.clone(),
        passive,
        force: facts.force_authn && !passive,
        format,
        allow_create: facts.allow_create.unwrap_or(true),
        requesters: facts.requester_ids.clone(),
        proxy_count: facts.proxy_count,
        status,
    })
}

/// The ACS of an IdP-initiated exchange: only the `isDefault` one, and only when the
/// registration opted in (IDP-15).
///
/// # Errors
/// [`Refusal::Unsolicited`].
pub fn unsolicited(sp: &Sp) -> Result<&Acs, Refusal> {
    if !sp.allow_idp_initiated || sp.protocol != Protocol::Saml2 {
        return Err(Refusal::Unsolicited);
    }
    sp.acs
        .iter()
        .find(|a| a.default && a.binding != crate::sp::Binding::Paos)
        .or_else(|| {
            (sp.acs.len() == 1)
                .then(|| sp.acs.first())
                .flatten()
                .filter(|a| a.binding != crate::sp::Binding::Paos)
        })
        .ok_or(Refusal::Unsolicited)
}

/// Checks a `RelayState` length.
///
/// # Errors
/// [`Refusal::RelayState`].
pub fn relay_state(r: Option<&str>) -> Result<(), Refusal> {
    match r {
        Some(r) if r.len() > MAX_RELAY_STATE || r.chars().any(char::is_control) => {
            Err(Refusal::RelayState)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    pub(crate) fn sp() -> Sp {
        Sp::from_json(&serde_json::json!({
            "entity_id": "https://sp.test",
            "acs": [
                { "url": "https://sp.test/acs", "index": 0, "binding": "post", "default": true },
                { "url": "https://sp.test/acs2", "index": 3, "binding": "post" },
                { "url": "https://sp.test/ecp", "index": 4, "binding": "paos" },
            ],
        }))
        .unwrap()
    }

    pub(crate) const NOW: u64 = 1_794_304_800_000;

    pub(crate) fn facts() -> Facts {
        Facts {
            kind: Kind::Authn,
            id: String::from("_r1"),
            issue_instant: time::format(NOW),
            destination: Some(String::from("https://idp.test/saml/sso")),
            issuer: String::from("https://sp.test"),
            acs_url: Some(String::from("https://sp.test/acs")),
            acs_index: None,
            protocol_binding: Some(String::from(uri::BINDING_POST)),
            force_authn: false,
            is_passive: false,
            nameid_format: None,
            allow_create: None,
            sp_name_qualifier: None,
            requester_ids: vec![],
            proxy_count: None,
            signed: Signed::Absent,
            name_id: None,
            session_indexes: vec![],
            soap: false,
        }
    }

    fn ep() -> Vec<String> {
        vec![String::from("https://idp.test/saml/sso")]
    }

    // IDP-15, SAMLProf §4.1.4.1, Ek B 4771: the ACS matches exactly, by URL or index.
    #[test]
    fn the_acs_matches_the_registration_exactly() {
        let s = sp();
        assert_eq!(
            decide(&s, &facts(), false, &ep(), NOW).unwrap().acs.index,
            0
        );
        for url in [
            "https://sp.test/acs/",
            "https://SP.test/acs",
            "https://sp.test/acs?x=1",
            "https://evil.test/acs",
        ] {
            let f = Facts {
                acs_url: Some(String::from(url)),
                ..facts()
            };
            assert_eq!(
                decide(&s, &f, false, &ep(), NOW),
                Err(Refusal::Acs),
                "{url}"
            );
        }
        let f = Facts {
            acs_url: None,
            acs_index: Some(3),
            protocol_binding: None,
            ..facts()
        };
        assert_eq!(
            decide(&s, &f, false, &ep(), NOW).unwrap().acs.url,
            "https://sp.test/acs2"
        );
        let f = Facts {
            acs_url: None,
            acs_index: Some(9),
            ..facts()
        };
        assert_eq!(decide(&s, &f, false, &ep(), NOW), Err(Refusal::Acs));
        let f = Facts {
            protocol_binding: Some(String::from(uri::BINDING_REDIRECT)),
            ..facts()
        };
        assert_eq!(decide(&s, &f, false, &ep(), NOW), Err(Refusal::Acs));
    }

    // §10.6.1: IsPassive wins over ForceAuthn.
    #[test]
    fn is_passive_wins_over_force_authn() {
        let f = Facts {
            force_authn: true,
            is_passive: true,
            ..facts()
        };
        let a = decide(&sp(), &f, false, &ep(), NOW).unwrap();
        assert!(a.passive && !a.force);
        let f = Facts {
            force_authn: true,
            ..facts()
        };
        assert!(decide(&sp(), &f, false, &ep(), NOW).unwrap().force);
    }

    // §10.6.1: AuthnRequestsSigned, Destination, freshness.
    #[test]
    fn signature_destination_and_freshness_are_required() {
        let mut s = sp();
        s.authn_requests_signed = true;
        s.certificates = vec![String::from("MAA=")];
        assert_eq!(
            decide(&s, &facts(), false, &ep(), NOW),
            Err(Refusal::Unsigned)
        );
        assert!(decide(&s, &facts(), true, &ep(), NOW).is_ok());
        let f = Facts {
            destination: Some(String::from("https://other.test/sso")),
            ..facts()
        };
        assert_eq!(
            decide(&sp(), &f, false, &ep(), NOW),
            Err(Refusal::Destination)
        );
        let f = Facts {
            destination: None,
            signed: Signed::Verified(String::new()),
            ..facts()
        };
        assert_eq!(
            decide(&sp(), &f, false, &ep(), NOW),
            Err(Refusal::Destination)
        );
        let f = Facts {
            issue_instant: time::format(NOW - 11 * 60_000 - time::SKEW_MS),
            ..facts()
        };
        assert_eq!(decide(&sp(), &f, false, &ep(), NOW), Err(Refusal::Stale));
    }

    // §10.6.1: NameIDPolicy that cannot be met is a status to the ACS.
    #[test]
    fn an_unmeetable_nameid_policy_is_a_status() {
        let f = Facts {
            nameid_format: Some(String::from(uri::NAMEID_EMAIL)),
            ..facts()
        };
        assert_eq!(
            decide(&sp(), &f, false, &ep(), NOW).unwrap().status,
            Some(Status::InvalidNameIdPolicy)
        );
        let f = Facts {
            sp_name_qualifier: Some(String::from("urn:other")),
            ..facts()
        };
        assert_eq!(
            decide(&sp(), &f, false, &ep(), NOW).unwrap().status,
            Some(Status::InvalidNameIdPolicy)
        );
        let f = Facts {
            allow_create: Some(false),
            ..facts()
        };
        let a = decide(&sp(), &f, false, &ep(), NOW).unwrap();
        assert!(!a.allow_create && a.status.is_none());
    }

    // IDP-15: IdP-initiated only when opted in, and only to the isDefault ACS.
    #[test]
    fn unsolicited_needs_the_opt_in() {
        let mut s = sp();
        assert_eq!(unsolicited(&s), Err(Refusal::Unsolicited));
        s.allow_idp_initiated = true;
        assert_eq!(unsolicited(&s).unwrap().url, "https://sp.test/acs");
        assert_eq!(relay_state(Some(&"x".repeat(81))), Err(Refusal::RelayState));
        assert!(relay_state(Some(&"x".repeat(80))).is_ok());
    }
}
