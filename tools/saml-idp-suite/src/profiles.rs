//! Service provider profiles: what well-known SPs require of an IdP's response beyond the
//! standard, from each vendor's published SAML setup guide. A profile only ever adds a
//! requirement; none excuses a standards check.

use crate::response::{Finding, attributes};
use crate::xml;
use crate::{DS, SAML};

/// Where the SP requires the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signing {
    /// Response or assertion.
    Either,
    /// The assertion.
    Assertion,
    /// The response.
    Response,
}

/// One SP's requirements.
#[derive(Clone, Copy, Debug)]
pub struct SpProfile {
    /// The profile name.
    pub name: &'static str,
    /// The product.
    pub counterpart: &'static str,
    /// The required `NameID` format, if one.
    pub name_id_format: Option<&'static str>,
    /// Attribute names the SP needs.
    pub attributes: &'static [&'static str],
    /// The signature it verifies.
    pub signing: Signing,
    /// A fixed audience it expects, if one.
    pub audience: Option<&'static str>,
    /// The signature must carry the certificate in `KeyInfo`.
    pub key_info_certificate: bool,
    /// Where the requirements come from.
    pub source: &'static str,
}

const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

/// The shipped profiles.
pub const PROFILES: &[SpProfile] = &[
    SpProfile {
        name: "salesforce",
        counterpart: "Salesforce",
        name_id_format: None,
        attributes: &[],
        signing: Signing::Assertion,
        audience: Some("https://saml.salesforce.com"),
        key_info_certificate: false,
        source: "Salesforce Help: SAML SSO validation errors",
    },
    SpProfile {
        name: "aws",
        counterpart: "Amazon Web Services console federation",
        name_id_format: None,
        attributes: &[
            "https://aws.amazon.com/SAML/Attributes/Role",
            "https://aws.amazon.com/SAML/Attributes/RoleSessionName",
        ],
        signing: Signing::Either,
        audience: Some("urn:amazon:webservices"),
        key_info_certificate: false,
        source: "AWS IAM User Guide: configuring SAML assertions for the authentication response",
    },
    SpProfile {
        name: "aws-identity-center",
        counterpart: "AWS IAM Identity Center",
        name_id_format: Some(EMAIL),
        attributes: &[],
        signing: Signing::Either,
        audience: None,
        key_info_certificate: false,
        source: "AWS IAM Identity Center User Guide: SAML 2.0 identity providers",
    },
    SpProfile {
        name: "google-workspace",
        counterpart: "Google Workspace",
        name_id_format: Some(EMAIL),
        attributes: &[],
        signing: Signing::Either,
        audience: None,
        key_info_certificate: false,
        source: "Google Workspace Admin Help: SSO assertion requirements",
    },
    SpProfile {
        name: "slack",
        counterpart: "Slack",
        name_id_format: Some(PERSISTENT),
        attributes: &["User.Email"],
        signing: Signing::Response,
        audience: Some("https://slack.com"),
        key_info_certificate: false,
        source: "Slack Help Center: custom SAML single sign-on",
    },
    SpProfile {
        name: "zoom",
        counterpart: "Zoom",
        name_id_format: None,
        attributes: &[],
        signing: Signing::Response,
        audience: None,
        key_info_certificate: false,
        source: "Zoom Support: configuring single sign-on",
    },
    SpProfile {
        name: "atlassian",
        counterpart: "Atlassian Cloud",
        name_id_format: Some(EMAIL),
        attributes: &[],
        signing: Signing::Assertion,
        audience: None,
        key_info_certificate: false,
        source: "Atlassian Support: configure SAML single sign-on with an identity provider",
    },
    SpProfile {
        name: "servicenow",
        counterpart: "ServiceNow",
        name_id_format: None,
        attributes: &[],
        signing: Signing::Either,
        audience: None,
        key_info_certificate: false,
        source: "ServiceNow Docs: SAML 2.0 single sign-on",
    },
    SpProfile {
        name: "workday",
        counterpart: "Workday",
        name_id_format: None,
        attributes: &[],
        signing: Signing::Either,
        audience: None,
        key_info_certificate: true,
        source: "Workday Community: SAML setup",
    },
    SpProfile {
        name: "entra",
        counterpart: "Microsoft Entra ID / Microsoft 365",
        name_id_format: Some(PERSISTENT),
        attributes: &["IDPEmail"],
        signing: Signing::Either,
        audience: None,
        key_info_certificate: false,
        source: "Microsoft Learn: use a SAML 2.0 IdP for single sign-on",
    },
    SpProfile {
        name: "shibboleth-sp",
        counterpart: "Shibboleth SP 3",
        name_id_format: None,
        attributes: &[],
        signing: Signing::Either,
        audience: None,
        key_info_certificate: false,
        source: "Shibboleth SP 3 documentation: SAML 2.0 Web Browser SSO",
    },
    SpProfile {
        name: "simplesamlphp",
        counterpart: "SimpleSAMLphp",
        name_id_format: None,
        attributes: &[],
        signing: Signing::Either,
        audience: None,
        key_info_certificate: false,
        source: "SimpleSAMLphp documentation: service provider quick start",
    },
];

/// The profile `name`.
#[must_use]
pub fn profile(name: &str) -> Option<&'static SpProfile> {
    PROFILES.iter().find(|p| p.name == name)
}

fn finding(rule: &'static str, ok: bool, detail: String) -> Finding {
    Finding { rule, ok, detail }
}

/// Checks a response against an SP profile; run [`crate::response::check_response`] first.
#[must_use]
pub fn check_profile(p: &SpProfile, response_xml: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(doc) = xml::parse(response_xml) else {
        out.push(finding("message.well_formed", false, String::new()));
        return out;
    };
    let r = &doc.root;
    let a = r.child(SAML, "Assertion");
    if let Some(format) = p.name_id_format {
        let seen = a
            .and_then(|a| a.child(SAML, "Subject"))
            .and_then(|s| s.child(SAML, "NameID"))
            .and_then(|n| n.attr("Format"));
        out.push(finding(
            "profile.name_id_format",
            seen == Some(format),
            format!("{seen:?}"),
        ));
    }
    let names: Vec<String> = attributes(response_xml)
        .into_iter()
        .map(|(n, _, _)| n)
        .collect();
    for want in p.attributes {
        out.push(finding(
            "profile.attribute",
            names.iter().any(|n| n == want),
            (*want).to_owned(),
        ));
    }
    let response_signed = r.child(DS, "Signature").is_some();
    let assertion_signed = a.is_some_and(|a| a.child(DS, "Signature").is_some());
    let ok = match p.signing {
        Signing::Either => response_signed || assertion_signed || a.is_none(),
        Signing::Assertion => assertion_signed || a.is_none(),
        Signing::Response => response_signed,
    };
    out.push(finding(
        "profile.signing",
        ok,
        format!("response {response_signed}, assertion {assertion_signed}"),
    ));
    if let Some(aud) = p.audience {
        let seen: Vec<String> = a
            .and_then(|a| a.child(SAML, "Conditions"))
            .map(|c| {
                c.children_named(SAML, "AudienceRestriction")
                    .flat_map(|x| x.children_named(SAML, "Audience"))
                    .map(|x| x.text().trim().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        out.push(finding(
            "profile.audience",
            seen.iter().any(|s| s == aud),
            format!("{seen:?}"),
        ));
    }
    if p.key_info_certificate {
        let has = r
            .descendants()
            .iter()
            .filter(|e| e.is(DS, "Signature"))
            .all(|s| {
                s.child(DS, "KeyInfo")
                    .and_then(|k| k.child(DS, "X509Data"))
                    .and_then(|d| d.child(DS, "X509Certificate"))
                    .is_some()
            });
        out.push(finding("profile.key_info_certificate", has, String::new()));
    }
    out
}
