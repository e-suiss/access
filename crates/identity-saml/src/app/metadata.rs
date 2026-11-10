//! The identity provider's SAML metadata (§10.6.1, Ek B 4763, 4994): every published signing
//! certificate (two during a rotation), the SSO and SLO endpoints, the `NameID` formats,
//! `validUntil` 14 days ahead and `cacheDuration` PT6H, signed with the active key and re-signed
//! whenever it is served. Also the WS-Federation passive requestor metadata and the manual setup
//! facts (PEM certificate, SSO URL) for service providers that read no metadata.

use crate::alg::SigAlg;
use crate::assertion::{Random, new_id};
use crate::dsig::{SignError, XmlSigner, sign};
use crate::sp::b64;
use crate::time;
use crate::uri;
use crate::xml::El;

/// `validUntil` is this far ahead.
pub const VALID_MS: u64 = 14 * 24 * 3_600_000;

/// `cacheDuration`.
pub const CACHE: &str = "PT6H";

/// Largest metadata document Access serves (AWS IAM Identity Center reads 75 000 characters).
pub const MAX_CHARS: usize = 75_000;

/// The identity provider's endpoints, below its issuer URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoints {
    /// The entity ID.
    pub entity_id: String,
    /// `…/saml/sso`.
    pub sso: String,
    /// `…/saml/slo`.
    pub slo: String,
    /// `…/saml/ecp`.
    pub ecp: String,
    /// `…/wsfed`.
    pub wsfed: String,
}

impl Endpoints {
    /// The endpoints of the realm whose issuer URL is `issuer` (no trailing slash).
    #[must_use]
    pub fn of(issuer: &str) -> Self {
        let issuer = issuer.trim_end_matches('/');
        Self {
            entity_id: format!("{issuer}/saml/metadata"),
            sso: format!("{issuer}/saml/sso"),
            slo: format!("{issuer}/saml/slo"),
            ecp: format!("{issuer}/saml/ecp"),
            wsfed: format!("{issuer}/wsfed"),
        }
    }
}

fn md(local: &'static str) -> El {
    El::new("md", uri::MD, local)
}

fn key_descriptor(cert: &[u8]) -> El {
    md("KeyDescriptor").attr("use", "signing").child(
        El::new("ds", uri::DS, "KeyInfo").child(
            El::new("ds", uri::DS, "X509Data")
                .child(El::new("ds", uri::DS, "X509Certificate").text(b64::encode(cert))),
        ),
    )
}

/// The unsigned `EntityDescriptor`.
#[must_use]
pub fn descriptor(e: &Endpoints, certs: &[Vec<u8>], id: &str, now: u64) -> El {
    let service = |local: &'static str, binding: &'static str, at: &str| {
        md(local).attr("Binding", binding).attr("Location", at)
    };
    let idp = md("IDPSSODescriptor")
        .attr("WantAuthnRequestsSigned", "false")
        .attr("protocolSupportEnumeration", uri::SAMLP)
        .children(certs.iter().map(|c| key_descriptor(c)))
        .child(service(
            "SingleLogoutService",
            uri::BINDING_REDIRECT,
            &e.slo,
        ))
        .child(service("SingleLogoutService", uri::BINDING_POST, &e.slo))
        .children(
            [
                uri::NAMEID_PERSISTENT,
                uri::NAMEID_TRANSIENT,
                uri::NAMEID_EMAIL,
                uri::NAMEID_UNSPECIFIED,
            ]
            .into_iter()
            .map(|f| md("NameIDFormat").text(f)),
        )
        .child(service(
            "SingleSignOnService",
            uri::BINDING_REDIRECT,
            &e.sso,
        ))
        .child(service("SingleSignOnService", uri::BINDING_POST, &e.sso))
        .child(service("SingleSignOnService", uri::BINDING_SOAP, &e.ecp));
    md("EntityDescriptor")
        .attr("ID", id)
        .attr("cacheDuration", CACHE)
        .attr("entityID", e.entity_id.clone())
        .attr("validUntil", time::format(now.saturating_add(VALID_MS)))
        .child(idp)
}

/// The signed metadata document: re-signed each time it is made (operational, §10.1.7).
///
/// # Errors
/// [`SignError`].
pub async fn signed<S: XmlSigner, R: Random + ?Sized>(
    e: &Endpoints,
    certs: &[Vec<u8>],
    now: u64,
    signer: &S,
    random: &R,
) -> Result<String, SignError> {
    let id = new_id(random)?;
    let mut d = descriptor(e, certs, &id, now);
    sign(signer, &mut d, "ID", Some(0), SigAlg::RsaSha256, true).await?;
    let out = d.canonical();
    if out.chars().count() > MAX_CHARS {
        return Err(SignError(String::from("metadata too large")));
    }
    Ok(out)
}

/// The WS-Federation passive requestor metadata: the token signing certificates and the passive
/// endpoint (unsigned; the relying party pins the certificate at setup).
#[must_use]
pub fn wsfed(e: &Endpoints, certs: &[Vec<u8>]) -> String {
    let mut out = String::from(
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"",
    );
    crate::xml::attr_value(&mut out, &e.entity_id);
    out.push_str("\"><md:RoleDescriptor xmlns:fed=\"http://docs.oasis-open.org/wsfed/federation/200706\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" protocolSupportEnumeration=\"http://docs.oasis-open.org/wsfed/federation/200706\" xsi:type=\"fed:SecurityTokenServiceType\">");
    for c in certs {
        out.push_str(&key_descriptor(c).canonical());
    }
    out.push_str("<fed:PassiveRequestorEndpoint><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\"><wsa:Address>");
    out.push_str(&crate::xml::html(&e.wsfed));
    out.push_str("</wsa:Address></wsa:EndpointReference></fed:PassiveRequestorEndpoint></md:RoleDescriptor></md:EntityDescriptor>");
    out
}

/// A certificate as PEM, for manual setup (Ek B 4781).
#[must_use]
pub fn pem(cert: &[u8]) -> String {
    let b = b64::encode(cert);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // §10.6.1, Ek B 4763
    #[test]
    fn metadata_lists_every_certificate_and_its_windows() {
        let e = Endpoints::of("https://acme.id.test/");
        assert_eq!(e.sso, "https://acme.id.test/saml/sso");
        let certs = vec![vec![0x30, 0x01, 0x01], vec![0x30, 0x01, 0x02]];
        let d = descriptor(&e, &certs, "_m", 0).canonical();
        assert_eq!(d.matches("<md:KeyDescriptor").count(), 2);
        assert!(d.contains("validUntil=\"1970-01-15T00:00:00Z\""));
        assert!(d.contains("cacheDuration=\"PT6H\""));
        assert!(d.contains("Location=\"https://acme.id.test/saml/sso\""));
        assert!(!d.starts_with('\u{feff}') && d.len() < MAX_CHARS);
        let p = pem(&[0x30; 100]);
        assert!(
            p.starts_with("-----BEGIN CERTIFICATE-----\n")
                && p.ends_with("-----END CERTIFICATE-----\n")
        );
        assert!(p.lines().all(|l| l.len() <= 64));
        assert!(wsfed(&e, &certs).contains("https://acme.id.test/wsfed"));
    }
}
