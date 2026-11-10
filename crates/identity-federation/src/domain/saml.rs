//! Access as a SAML 2.0 service provider of an enterprise upstream, sans I/O (OP-155 m.3 (h),
//! §10.6.1, §10.2.6). The `AuthnRequest` is written in canonical form and signed in the
//! HTTP-Redirect binding with the realm's SAML key; the Response is read and its assertion's
//! signature verified in the parser worker against the identity provider's pinned certificates; what comes
//! back is checked here: issuer, audience, recipient, time and `InResponseTo`. An unsolicited
//! Response is refused unless the connection opens it, and then only while fresh.

use access_identity_saml::time::{IDP_INITIATED_MS, SKEW_MS, parse};
use access_identity_saml::xml::El;
use access_internal_api::saml::AssertionFacts;

use super::connection::Declared;

/// The SAML 2.0 protocol namespace.
pub const SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// The SAML 2.0 assertion namespace.
pub const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// The HTTP-POST binding the identity provider answers with.
pub const HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// The persistent `NameID` format asked for (TN-66: a stable, pairwise subject).
pub const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

/// The SP's view of one connection.
#[derive(Clone, Copy, Debug)]
pub struct Sp<'a> {
    /// Access's entity ID for the connection: its metadata URL.
    pub entity_id: &'a str,
    /// The assertion consumer service.
    pub acs: &'a str,
}

/// The canonical `AuthnRequest` `id` at `instant` (`xs:dateTime`) to the identity provider's SSO service.
#[must_use]
pub fn authn_request(sp: &Sp<'_>, id: &str, instant: &str, sso_url: &str) -> String {
    El::new("samlp", SAMLP, "AuthnRequest")
        .attr("AssertionConsumerServiceURL", sp.acs)
        .attr("Destination", sso_url)
        .attr("ID", id)
        .attr("IssueInstant", instant)
        .attr("ProtocolBinding", HTTP_POST)
        .attr("Version", "2.0")
        .child(El::new("saml", SAML, "Issuer").text(sp.entity_id))
        .child(
            El::new("samlp", SAMLP, "NameIDPolicy")
                .attr("AllowCreate", "true")
                .attr("Format", PERSISTENT),
        )
        .canonical()
}

/// The SP metadata of one connection (SAML Metadata §2.4.4): it asks for signed assertions.
#[must_use]
pub fn metadata(sp: &Sp<'_>) -> String {
    const MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
    El::new("md", MD, "EntityDescriptor")
        .attr("entityID", sp.entity_id)
        .child(
            El::new("md", MD, "SPSSODescriptor")
                .attr("AuthnRequestsSigned", "true")
                .attr("WantAssertionsSigned", "true")
                .attr("protocolSupportEnumeration", SAMLP)
                .child(El::new("md", MD, "NameIDFormat").text(PERSISTENT))
                .child(
                    El::new("md", MD, "AssertionConsumerService")
                        .attr("Binding", HTTP_POST)
                        .attr("Location", sp.acs)
                        .attr("index", "0"),
                ),
        )
        .canonical()
}

/// What a verified assertion must match.
#[derive(Clone, Copy, Debug)]
pub struct Expect<'a> {
    /// The identity provider's entity ID, as the connection names it.
    pub idp: &'a str,
    /// The audience: Access's entity ID for the connection, or the token endpoint (RFC 7522).
    pub audience: &'a str,
    /// The bearer recipient required, when the assertion arrives at an ACS.
    pub recipient: Option<&'a str>,
    /// The ID of the `AuthnRequest` this answers; `None` for an unsolicited Response.
    pub in_response_to: Option<&'a str>,
    /// Whether the connection opens unsolicited Responses.
    pub allow_unsolicited: bool,
    /// Trusted now.
    pub now_ms: u64,
}

/// Why a verified assertion is not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SamlCheck {
    /// Another identity provider issued it.
    #[error("issuer")]
    Issuer,
    /// Not addressed to Access's entity for the connection, or to this ACS.
    #[error("audience")]
    Audience,
    /// Before its time or past it.
    #[error("time")]
    Time,
    /// Answers no request of this browser, or an unsolicited Response the connection does not
    /// open (§10.6.1, §10.2.6).
    #[error("unsolicited")]
    Unsolicited,
}

fn instant(s: Option<&str>) -> Result<Option<u64>, SamlCheck> {
    s.map(|v| parse(v).ok_or(SamlCheck::Time)).transpose()
}

/// Checks `f` against `e` (§10.6.1, OP-155 m.3 (e), (h)); returns its declarations.
///
/// # Errors
/// [`SamlCheck`].
pub fn check(f: &AssertionFacts, e: &Expect<'_>) -> Result<Declared, SamlCheck> {
    if f.issuer != e.idp {
        return Err(SamlCheck::Issuer);
    }
    if !f.audiences.iter().any(|a| a == e.audience) {
        return Err(SamlCheck::Audience);
    }
    if let Some(r) = e.recipient
        && f.recipient.as_deref() != Some(r)
    {
        return Err(SamlCheck::Audience);
    }
    let now = e.now_ms;
    let issued = parse(&f.issue_instant).ok_or(SamlCheck::Time)?;
    if issued > now.saturating_add(SKEW_MS) {
        return Err(SamlCheck::Time);
    }
    if let Some(nb) = instant(f.not_before.as_deref())?
        && nb > now.saturating_add(SKEW_MS)
    {
        return Err(SamlCheck::Time);
    }
    let ends = [
        instant(f.not_on_or_after.as_deref())?,
        instant(f.confirmation_not_on_or_after.as_deref())?,
    ];
    if ends.iter().all(Option::is_none)
        || ends
            .iter()
            .flatten()
            .any(|end| end.saturating_add(SKEW_MS) <= now)
    {
        return Err(SamlCheck::Time);
    }
    match (e.in_response_to, f.in_response_to.as_deref()) {
        (Some(want), Some(got)) if want == got => {}
        // §10.6.1
        (None, None) if e.allow_unsolicited && issued.saturating_add(IDP_INITIATED_MS) > now => {}
        _ => return Err(SamlCheck::Unsolicited),
    }
    Ok(Declared {
        acr: f.authn_context.clone(),
        amr: Vec::new(),
        auth_time_ms: instant(f.authn_instant.as_deref())?,
    })
}

/// The bearer confirmation's end, Unix milliseconds (RFC 7522 §3).
#[must_use]
pub fn bearer_end(f: &AssertionFacts) -> Option<u64> {
    f.confirmation_not_on_or_after
        .as_deref()
        .or(f.not_on_or_after.as_deref())
        .and_then(parse)
}

/// The value of attribute `name`, its first one.
#[must_use]
pub fn attribute<'a>(f: &'a AssertionFacts, name: &str) -> Option<&'a str> {
    f.attributes
        .iter()
        .find(|(n, _)| n == name)
        .and_then(|(_, v)| v.first())
        .map(String::as_str)
}

#[cfg(test)]
mod tests;
