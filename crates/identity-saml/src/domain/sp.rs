//! A SAML service provider or WS-Federation relying party as the realm registers it
//! (`idp.saml.sp_register`/`sp_update`, OP-155 m.3 (a), (e); §10.6.1; IDP-15, IDP-28, MD-10): its
//! entity ID, exact ACS list, pinned certificates, `NameID` format, attribute release, signing and
//! encryption options and catalog template. A registration is checked before any decision.

use serde::{Deserialize, Serialize};

use crate::alg::SigAlg;
use crate::uri;

/// Most ACS endpoints (or WS-Federation reply URLs).
pub const MAX_ACS: usize = 16;

/// Most pinned certificates.
pub const MAX_CERTS: usize = access_internal_api::saml::MAX_CERTS;

/// Most released attributes.
pub const MAX_ATTRIBUTES: usize = 64;

/// Longest entity ID or URL.
pub const MAX_URI: usize = 1024;

/// Which protocol the relying party speaks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// SAML 2.0 Web SSO.
    #[default]
    Saml2,
    /// WS-Federation passive requestor with a SAML 1.1 token.
    WsfedSaml11,
    /// WS-Federation passive requestor with a SAML 2.0 token.
    WsfedSaml2,
}

impl Protocol {
    /// Whether it is a WS-Federation relying party.
    #[must_use]
    pub const fn wsfed(self) -> bool {
        matches!(self, Self::WsfedSaml11 | Self::WsfedSaml2)
    }
}

/// An endpoint binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Binding {
    /// HTTP-POST.
    Post,
    /// HTTP-Redirect.
    Redirect,
    /// PAOS (ECP).
    Paos,
}

impl Binding {
    /// The binding URI.
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::Post => uri::BINDING_POST,
            Self::Redirect => uri::BINDING_REDIRECT,
            Self::Paos => uri::BINDING_PAOS,
        }
    }
}

/// One assertion consumer service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acs {
    /// The exact URL.
    pub url: String,
    /// Its `index`.
    pub index: u16,
    /// Its binding.
    pub binding: Binding,
    /// `isDefault`.
    #[serde(default)]
    pub default: bool,
}

/// A single logout endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// The exact URL.
    pub url: String,
    /// Its binding.
    pub binding: Binding,
}

/// The `NameID` format of the service provider (MD-10).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NameIdFormat {
    /// Random 32 bytes per subject and service provider (or affiliation), kept (IDP-24).
    #[default]
    Persistent,
    /// New for every assertion.
    Transient,
    /// The verified e-mail address; only when the template asks for it.
    Email,
    /// Legacy: the persistent value under the unspecified format.
    Unspecified,
}

impl NameIdFormat {
    /// The format URI (persistent and transient are SAML 2.0 names, the others SAML 1.1).
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::Persistent => uri::NAMEID_PERSISTENT,
            Self::Transient => uri::NAMEID_TRANSIENT,
            Self::Email => uri::NAMEID_EMAIL,
            Self::Unspecified => uri::NAMEID_UNSPECIFIED,
        }
    }

    /// The format of a URI.
    #[must_use]
    pub fn of_uri(u: &str) -> Option<Self> {
        [
            Self::Persistent,
            Self::Transient,
            Self::Email,
            Self::Unspecified,
        ]
        .into_iter()
        .find(|f| f.uri() == u)
    }
}

/// An attribute's `NameFormat`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NameFormat {
    /// URI, the default.
    #[default]
    Uri,
    /// Basic.
    Basic,
    /// Unspecified.
    Unspecified,
}

impl NameFormat {
    /// The URI.
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::Uri => uri::ATTR_URI,
            Self::Basic => uri::ATTR_BASIC,
            Self::Unspecified => uri::ATTR_UNSPECIFIED,
        }
    }
}

/// Where a released attribute's values come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// The subject's verified e-mail address.
    Email,
    /// The `NameID` value of the assertion.
    NameId,
    /// The subject's opaque realm identifier.
    Subject,
}

/// One released attribute. Its `name` (and format) is what a service provider matches on;
/// `friendly_name` is only ever written, never matched (§10.6.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attribute {
    /// `Name`, case-sensitive.
    pub name: String,
    /// `NameFormat`.
    #[serde(default)]
    pub name_format: Option<NameFormat>,
    /// `FriendlyName`, written only.
    #[serde(default)]
    pub friendly_name: Option<String>,
    /// Values from the subject.
    #[serde(default)]
    pub source: Option<Source>,
    /// Fixed values, e.g. an AWS role pair.
    #[serde(default)]
    pub values: Vec<String>,
}

/// How the AAL3 class is named.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Aal3Class {
    /// `…:ac:classes:X509`.
    #[default]
    X509,
    /// REFEDS MFA.
    RefedsMfa,
}

fn yes() -> bool {
    true
}

/// A registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the registration body's switches, each a field of the admin contract"
)]
pub struct Sp {
    /// The entity ID (WS-Federation: `wtrealm`).
    pub entity_id: String,
    /// The protocol.
    #[serde(default)]
    pub protocol: Protocol,
    /// The SSO catalog template whose interop profile applies.
    #[serde(default)]
    pub template: Option<String>,
    /// ACS endpoints (WS-Federation: `wreply` URLs).
    pub acs: Vec<Acs>,
    /// Single logout endpoints.
    #[serde(default)]
    pub slo: Vec<Endpoint>,
    /// Pinned signing certificates, base64 DER.
    #[serde(default)]
    pub certificates: Vec<String>,
    /// The encryption certificate, base64 DER (RSA).
    #[serde(default)]
    pub encryption_certificate: Option<String>,
    /// The `NameID` format.
    #[serde(default)]
    pub nameid_format: NameIdFormat,
    /// The affiliation (`SPNameQualifier`) whose members share persistent `NameID`s.
    #[serde(default)]
    pub affiliation: Option<String>,
    /// `AuthnRequestsSigned`: an unsigned request is refused.
    #[serde(default)]
    pub authn_requests_signed: bool,
    /// Sign the Response.
    #[serde(default = "yes")]
    pub sign_response: bool,
    /// Sign the Assertion.
    #[serde(default = "yes")]
    pub sign_assertion: bool,
    /// Encrypt the Assertion (sign, then encrypt).
    #[serde(default)]
    pub encrypt_assertion: bool,
    /// The signature algorithm.
    #[serde(default)]
    pub signature_alg: Option<SigAlg>,
    /// IdP-initiated SSO is allowed (off by default, IDP-15).
    #[serde(default)]
    pub allow_idp_initiated: bool,
    /// Released attributes.
    #[serde(default)]
    pub attributes: Vec<Attribute>,
    /// An audience other than the entity ID, when the template names one.
    #[serde(default)]
    pub audience: Option<String>,
    /// How AAL3 is named.
    #[serde(default)]
    pub aal3_class: Aal3Class,
    /// The default attribute `NameFormat`.
    #[serde(default)]
    pub attribute_name_format: NameFormat,
    /// Whether the signing certificate is written in `KeyInfo`.
    #[serde(default = "yes")]
    pub key_info_certificate: bool,
}

/// Why a registration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SpError {
    /// The entity ID is not a bounded absolute URI.
    #[error("invalid entity ID")]
    EntityId,
    /// An ACS is missing, not exact `https`, duplicated, or more than one is the default.
    #[error("invalid ACS")]
    Acs,
    /// A logout endpoint is not exact `https`.
    #[error("invalid SLO endpoint")]
    Slo,
    /// A certificate is not base64 DER of a bounded size, or too many are pinned.
    #[error("invalid certificate")]
    Certificate,
    /// Signed requests are required but no certificate is pinned.
    #[error("signed requests need a pinned certificate")]
    NoCertificate,
    /// Encryption is asked for without an encryption certificate, or for WS-Federation.
    #[error("invalid encryption")]
    Encryption,
    /// Nothing would be signed.
    #[error("unsigned output")]
    Unsigned,
    /// An attribute is invalid or duplicated.
    #[error("invalid attribute")]
    Attribute,
    /// The e-mail `NameID` is asked for without a template that asks for it (MD-10).
    #[error("e-mail NameID needs a template that asks for it")]
    EmailNameId,
    /// The audience or affiliation is not a bounded absolute URI.
    #[error("invalid audience")]
    Audience,
    /// The template names no shipped interop profile.
    #[error("unknown template")]
    Template,
    /// The template's profile asks for something the registration refuses.
    #[error("the registration does not meet its template's profile")]
    Profile,
}

impl SpError {
    /// The stable problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EntityId => "saml-sp-entity-id",
            Self::Acs => "saml-sp-acs",
            Self::Slo => "saml-sp-slo",
            Self::Certificate => "saml-sp-certificate",
            Self::NoCertificate => "saml-sp-no-certificate",
            Self::Encryption => "saml-sp-encryption",
            Self::Unsigned => "saml-sp-unsigned",
            Self::Attribute => "saml-sp-attribute",
            Self::EmailNameId => "saml-sp-email-nameid",
            Self::Audience => "saml-sp-audience",
            Self::Template => "saml-sp-template",
            Self::Profile => "saml-sp-profile",
        }
    }
}

fn bounded_uri(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_URI
        && s.contains(':')
        && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn https(s: &str) -> bool {
    bounded_uri(s) && s.starts_with("https://") && !s.contains('#') && s.len() > "https://".len()
}

/// Standard base64 with padding (the encoding of certificates in XML and in registrations).
pub mod b64 {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Encodes `data`.
    #[must_use]
    pub fn encode(data: &[u8]) -> String {
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk.first().copied().unwrap_or(0);
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
            for (i, shift) in [18_u32, 12, 6, 0].into_iter().enumerate() {
                if i <= chunk.len() {
                    let idx = usize::try_from((n >> shift) & 63).unwrap_or(0);
                    out.push(char::from(A.get(idx).copied().unwrap_or(b'A')));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn value(c: u8) -> Option<u32> {
        A.iter()
            .position(|a| *a == c)
            .and_then(|p| u32::try_from(p).ok())
    }

    /// Decodes padded standard base64, ignoring ASCII whitespace; `None` for anything else.
    #[must_use]
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let b: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
        if !b.len().is_multiple_of(4) {
            return None;
        }
        let (chunks, _) = b.as_chunks::<4>();
        let last = chunks.len().checked_sub(1);
        let mut out = Vec::new();
        for (n, chunk) in chunks.iter().enumerate() {
            let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
            if pad > 2 || (pad > 0 && Some(n) != last) {
                return None;
            }
            let keep = 4_usize.checked_sub(pad)?;
            let mut acc: u32 = 0;
            for (i, c) in chunk.iter().enumerate() {
                let v = if i < keep { value(*c)? } else { 0 };
                acc = (acc << 6) | v;
            }
            out.extend_from_slice(acc.to_be_bytes().get(1..keep)?);
        }
        Some(out)
    }
}

fn cert(s: &str) -> Result<Vec<u8>, SpError> {
    let der = b64::decode(s).ok_or(SpError::Certificate)?;
    if der.is_empty()
        || der.len() > access_internal_api::saml::MAX_CERT
        || der.first() != Some(&0x30)
    {
        return Err(SpError::Certificate);
    }
    Ok(der)
}

impl Sp {
    /// The registration in a JSON body.
    ///
    /// # Errors
    /// [`SpError`] when it does not read or does not check.
    pub fn from_json(v: &serde_json::Value) -> Result<Self, SpError> {
        let sp: Self = serde_json::from_value(v.clone()).map_err(|_| SpError::EntityId)?;
        sp.check()?;
        Ok(sp)
    }

    /// The stored form.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }

    /// The pinned signing certificates, DER.
    #[must_use]
    pub fn certs(&self) -> Vec<Vec<u8>> {
        self.certificates
            .iter()
            .filter_map(|c| cert(c).ok())
            .collect()
    }

    /// The encryption certificate, DER.
    #[must_use]
    pub fn encryption_cert(&self) -> Option<Vec<u8>> {
        self.encryption_certificate
            .as_deref()
            .and_then(|c| cert(c).ok())
    }

    /// The signature algorithm, RSA-SHA256 by default.
    #[must_use]
    pub fn alg(&self) -> SigAlg {
        self.signature_alg.unwrap_or(SigAlg::RsaSha256)
    }

    /// The audience: the template's value, else the entity ID.
    #[must_use]
    pub fn audience(&self) -> &str {
        self.audience.as_deref().unwrap_or(&self.entity_id)
    }

    /// The `isDefault` ACS, else the lowest index.
    #[must_use]
    pub fn default_acs(&self) -> Option<&Acs> {
        self.acs
            .iter()
            .find(|a| a.default)
            .or_else(|| self.acs.iter().min_by_key(|a| a.index))
    }

    /// Checks the registration (§10.6.1, MD-10).
    ///
    /// # Errors
    /// [`SpError`].
    pub fn check(&self) -> Result<(), SpError> {
        if !bounded_uri(&self.entity_id) {
            return Err(SpError::EntityId);
        }
        if self.acs.is_empty() || self.acs.len() > MAX_ACS {
            return Err(SpError::Acs);
        }
        let mut indexes = std::collections::BTreeSet::new();
        for a in &self.acs {
            let binding_ok = match self.protocol {
                Protocol::Saml2 => matches!(a.binding, Binding::Post | Binding::Paos),
                Protocol::WsfedSaml11 | Protocol::WsfedSaml2 => a.binding == Binding::Post,
            };
            if !https(&a.url) || !binding_ok || !indexes.insert(a.index) {
                return Err(SpError::Acs);
            }
        }
        if self.acs.iter().filter(|a| a.default).count() > 1 {
            return Err(SpError::Acs);
        }
        if self
            .slo
            .iter()
            .any(|e| !https(&e.url) || e.binding == Binding::Paos)
            || self.slo.len() > MAX_ACS
        {
            return Err(SpError::Slo);
        }
        if self.certificates.len() > MAX_CERTS {
            return Err(SpError::Certificate);
        }
        for c in &self.certificates {
            cert(c)?;
        }
        if self.authn_requests_signed && self.certificates.is_empty() {
            return Err(SpError::NoCertificate);
        }
        match (&self.encryption_certificate, self.encrypt_assertion) {
            (Some(c), _) => {
                cert(c).map_err(|_| SpError::Encryption)?;
            }
            (None, true) => return Err(SpError::Encryption),
            (None, false) => {}
        }
        if self.protocol.wsfed() && (self.encrypt_assertion || !self.sign_assertion) {
            return Err(SpError::Encryption);
        }
        if !self.sign_response && !self.sign_assertion {
            return Err(SpError::Unsigned);
        }
        if self.nameid_format == NameIdFormat::Email && self.template.is_none() {
            return Err(SpError::EmailNameId);
        }
        for u in [&self.audience, &self.affiliation].into_iter().flatten() {
            if !bounded_uri(u) {
                return Err(SpError::Audience);
            }
        }
        self.check_attributes()
    }

    fn check_attributes(&self) -> Result<(), SpError> {
        if self.attributes.len() > MAX_ATTRIBUTES {
            return Err(SpError::Attribute);
        }
        let mut names = std::collections::BTreeSet::new();
        for a in &self.attributes {
            let format = a.name_format.unwrap_or(self.attribute_name_format);
            let ok = !a.name.is_empty()
                && a.name.len() <= 256
                && !a.name.chars().any(char::is_control)
                && a.friendly_name.as_ref().is_none_or(|f| f.len() <= 256)
                && (a.source.is_some() == a.values.is_empty())
                && a.values.len() <= 16
                && a.values.iter().all(|v| v.len() <= 2048)
                && names.insert((a.name.clone(), format.uri()));
            if !ok {
                return Err(SpError::Attribute);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    pub(crate) fn minimal() -> serde_json::Value {
        serde_json::json!({
            "entity_id": "https://sp.test/metadata",
            "acs": [{ "url": "https://sp.test/acs", "index": 0, "binding": "post" }],
        })
    }

    // §10.6.1, IDP-15, MD-10
    #[test]
    fn a_minimal_registration_has_the_safe_defaults() {
        let sp = Sp::from_json(&minimal()).unwrap();
        assert!(sp.sign_response && sp.sign_assertion);
        assert!(!sp.allow_idp_initiated && !sp.encrypt_assertion);
        assert_eq!(sp.nameid_format, NameIdFormat::Persistent);
        assert_eq!(sp.alg(), SigAlg::RsaSha256);
        assert_eq!(sp.audience(), "https://sp.test/metadata");
        assert_eq!(Sp::from_json(&sp.to_json()).unwrap(), sp);
    }

    // §10.6.1
    #[test]
    fn registrations_are_checked() {
        let bad = |patch: serde_json::Value| {
            let mut v = minimal();
            for (k, x) in patch.as_object().unwrap() {
                v[k] = x.clone();
            }
            Sp::from_json(&v).err()
        };
        assert_eq!(
            bad(
                serde_json::json!({"acs": [{"url": "http://sp.test/acs", "index": 0, "binding": "post"}]})
            ),
            Some(SpError::Acs)
        );
        assert_eq!(
            bad(
                serde_json::json!({"acs": [{"url": "https://sp.test/acs", "index": 0, "binding": "redirect"}]})
            ),
            Some(SpError::Acs)
        );
        assert_eq!(
            bad(serde_json::json!({"sign_response": false, "sign_assertion": false})),
            Some(SpError::Unsigned)
        );
        assert_eq!(
            bad(serde_json::json!({"authn_requests_signed": true})),
            Some(SpError::NoCertificate)
        );
        assert_eq!(
            bad(serde_json::json!({"encrypt_assertion": true})),
            Some(SpError::Encryption)
        );
        assert_eq!(
            bad(serde_json::json!({"nameid_format": "email"})),
            Some(SpError::EmailNameId)
        );
        assert_eq!(
            bad(serde_json::json!({"signature_alg": "rsa-sha1"})),
            Some(SpError::EntityId)
        );
        assert_eq!(
            bad(serde_json::json!({"attributes": [
                {"name": "mail", "source": "email", "friendly_name": "a"},
                {"name": "mail", "source": "email", "friendly_name": "b"}
            ]})),
            Some(SpError::Attribute)
        );
        assert_eq!(
            bad(serde_json::json!({"certificates": ["!!"]})),
            Some(SpError::Certificate)
        );
        assert_eq!(
            bad(serde_json::json!({"unknown": 1})),
            Some(SpError::EntityId)
        );
    }

    #[test]
    fn base64_round_trips() {
        for n in 0..10_u8 {
            let data: Vec<u8> = (0..n).collect();
            assert_eq!(b64::decode(&b64::encode(&data)).unwrap(), data);
        }
        assert!(b64::decode("Y=Q=").is_none());
    }
}
