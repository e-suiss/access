//! Standards checks on an IdP's `samlp:Response` (SAML 2.0 Core, Bindings, Profiles and the
//! Web Browser SSO profile) and on its metadata. Cryptographic verification is left to a real
//! XML signature implementation (`xmlsec1`, a service provider); these checks look at what
//! signature verifiers commonly get wrong to accept: where the signature sits, what it covers,
//! which transforms and algorithms it uses.

use crate::time::parse_instant;
use crate::xml::{self, Element};
use crate::{DS, MD, SAML, SAMLP};

/// One finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// The rule, `<area>.<name>`.
    pub rule: &'static str,
    /// Whether the message holds it.
    pub ok: bool,
    /// What was seen.
    pub detail: String,
}

/// What the response must match.
#[derive(Clone, Debug)]
pub struct Expectations {
    /// The IdP entity ID.
    pub idp_entity: String,
    /// The service provider entity ID (the audience).
    pub sp_entity: String,
    /// The ACS URL the response is posted to.
    pub acs: String,
    /// The request ID, for a solicited response.
    pub request_id: Option<String>,
    /// Now, in seconds since the Unix epoch.
    pub now: i64,
    /// Allowed clock skew in seconds.
    pub skew: i64,
    /// The longest acceptable assertion validity in seconds.
    pub max_validity: i64,
}

const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const ENTITY_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

/// Signature and digest algorithms a modern IdP must not use.
pub const WEAK_ALGORITHMS: &[&str] = &[
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
    "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
    "http://www.w3.org/2000/09/xmldsig#sha1",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-md5",
    "http://www.w3.org/2001/04/xmldsig-more#md5",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
];

struct Out(Vec<Finding>);

impl Out {
    fn check(&mut self, rule: &'static str, ok: bool, detail: impl Into<String>) {
        self.0.push(Finding {
            rule,
            ok,
            detail: detail.into(),
        });
    }
}

fn ncname_id(v: &str) -> bool {
    let mut chars = v.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    first_ok
        && v.len() >= 17
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn instant(v: Option<&str>) -> Option<i64> {
    v.and_then(parse_instant)
}

/// Checks the signature that is a direct child of `signed`, if one is.
fn signature(out: &mut Out, signed: &Element, what: &'static str) -> bool {
    let Some(sig) = signed.child(DS, "Signature") else {
        return false;
    };
    let id = signed.attr("ID").unwrap_or_default();
    let info = sig.child(DS, "SignedInfo");
    let refs: Vec<&Element> = info
        .map(|i| i.children_named(DS, "Reference").collect())
        .unwrap_or_default();
    let uri_ok = refs.len() == 1
        && refs
            .first()
            .and_then(|r| r.attr("URI"))
            .is_some_and(|u| u.strip_prefix('#') == Some(id) && !id.is_empty());
    out.check(
        match what {
            "assertion" => "signature.assertion_reference",
            "response" => "signature.response_reference",
            _ => "signature.metadata_reference",
        },
        uri_ok,
        format!(
            "{} reference(s), the signed element's ID is {id:?}",
            refs.len()
        ),
    );
    let transforms: Vec<String> = refs
        .iter()
        .filter_map(|r| r.child(DS, "Transforms"))
        .flat_map(|t| t.children_named(DS, "Transform"))
        .map(|t| t.attr("Algorithm").unwrap_or_default().to_owned())
        .collect();
    let allowed = transforms.iter().all(|a| a == ENVELOPED || a == EXC_C14N);
    out.check(
        "signature.transforms",
        allowed && transforms.iter().any(|a| a == ENVELOPED),
        format!("{transforms:?}"),
    );
    let c14n = info
        .and_then(|i| i.child(DS, "CanonicalizationMethod"))
        .and_then(|c| c.attr("Algorithm"))
        .unwrap_or_default();
    out.check(
        "signature.canonicalization",
        c14n == EXC_C14N,
        c14n.to_owned(),
    );
    let mut algorithms: Vec<String> = Vec::new();
    if let Some(m) = info.and_then(|i| i.child(DS, "SignatureMethod")) {
        algorithms.push(m.attr("Algorithm").unwrap_or_default().to_owned());
    }
    for r in &refs {
        if let Some(d) = r.child(DS, "DigestMethod") {
            algorithms.push(d.attr("Algorithm").unwrap_or_default().to_owned());
        }
    }
    out.check(
        "signature.algorithms",
        !algorithms.is_empty()
            && algorithms
                .iter()
                .all(|a| !a.is_empty() && !WEAK_ALGORITHMS.contains(&a.as_str())),
        format!("{algorithms:?}"),
    );
    out.check(
        "signature.no_comments",
        !signed.contains_comment() && c14n != EXC_C14N_COMMENTS,
        "comments inside a signed element let verifiers and readers disagree",
    );
    true
}

/// Checks `response_xml` against `e`.
#[must_use]
#[allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "one check per rule, in message order"
)]
pub fn check_response(response_xml: &str, e: &Expectations) -> Vec<Finding> {
    let mut out = Out(Vec::new());
    let doc = match xml::parse(response_xml) {
        Ok(d) => d,
        Err(err) => {
            out.check("message.well_formed", false, err.to_string());
            return out.0;
        }
    };
    out.check("message.well_formed", true, "");
    out.check("message.no_doctype", !doc.doctype, "");
    let r = &doc.root;
    out.check("response.element", r.is(SAMLP, "Response"), r.name.clone());
    out.check(
        "response.version",
        r.attr("Version") == Some("2.0"),
        format!("{:?}", r.attr("Version")),
    );
    let rid = r.attr("ID").unwrap_or_default();
    out.check("response.id", ncname_id(rid), rid.to_owned());
    let at = instant(r.attr("IssueInstant"));
    out.check(
        "response.issue_instant",
        at.is_some_and(|t| (t.saturating_sub(e.now)).abs() <= e.skew),
        format!("{:?}", r.attr("IssueInstant")),
    );
    out.check(
        "response.destination",
        r.attr("Destination") == Some(e.acs.as_str()),
        format!("{:?}", r.attr("Destination")),
    );
    out.check(
        "response.in_response_to",
        r.attr("InResponseTo") == e.request_id.as_deref(),
        format!("{:?}", r.attr("InResponseTo")),
    );
    let issuer = r.child(SAML, "Issuer");
    out.check(
        "response.issuer",
        issuer.is_none_or(|i| {
            i.text().trim() == e.idp_entity && i.attr("Format").is_none_or(|f| f == ENTITY_FORMAT)
        }),
        issuer.map(Element::text).unwrap_or_default(),
    );
    let status = r
        .child(SAMLP, "Status")
        .and_then(|s| s.child(SAMLP, "StatusCode"))
        .and_then(|c| c.attr("Value"))
        .unwrap_or_default();
    out.check("response.status", status == SUCCESS, status.to_owned());

    let assertions: Vec<&Element> = r.children_named(SAML, "Assertion").collect();
    let encrypted = r.children_named(SAML, "EncryptedAssertion").count();
    out.check(
        "response.one_assertion",
        assertions.len().saturating_add(encrypted) == 1,
        format!("{} assertion(s), {encrypted} encrypted", assertions.len()),
    );
    let response_signed = signature(&mut out, r, "response");
    let Some(a) = assertions.first().copied() else {
        out.check(
            "signature.present",
            response_signed || encrypted == 1,
            "no plaintext assertion to inspect",
        );
        return out.0;
    };
    let assertion_signed = signature(&mut out, a, "assertion");
    out.check(
        "signature.present",
        response_signed || assertion_signed,
        format!("response signed: {response_signed}, assertion signed: {assertion_signed}"),
    );
    out.check(
        "assertion.version",
        a.attr("Version") == Some("2.0"),
        format!("{:?}", a.attr("Version")),
    );
    let aid = a.attr("ID").unwrap_or_default();
    out.check("assertion.id", ncname_id(aid) && aid != rid, aid.to_owned());
    let ai = a.child(SAML, "Issuer");
    out.check(
        "assertion.issuer",
        ai.is_some_and(|i| i.text().trim() == e.idp_entity),
        ai.map(Element::text).unwrap_or_default(),
    );

    let subject = a.child(SAML, "Subject");
    let name_id = subject.and_then(|s| s.child(SAML, "NameID"));
    out.check(
        "subject.name_id",
        name_id.is_some_and(|n| !n.text().trim().is_empty() && !n.has_comment_child()),
        name_id.map(Element::text).unwrap_or_default(),
    );
    let bearer: Vec<&Element> = subject
        .map(|s| {
            s.children_named(SAML, "SubjectConfirmation")
                .filter(|c| c.attr("Method") == Some(BEARER))
                .collect()
        })
        .unwrap_or_default();
    out.check(
        "subject.bearer_confirmation",
        !bearer.is_empty(),
        format!("{} bearer confirmation(s)", bearer.len()),
    );
    for c in &bearer {
        let d = c.child(SAML, "SubjectConfirmationData");
        let recipient = d.and_then(|d| d.attr("Recipient"));
        out.check(
            "subject.recipient",
            recipient == Some(e.acs.as_str()),
            format!("{recipient:?}"),
        );
        let until = instant(d.and_then(|d| d.attr("NotOnOrAfter")));
        out.check(
            "subject.not_on_or_after",
            until.is_some_and(|u| {
                u > e.now.saturating_sub(e.skew) && u <= e.now.saturating_add(e.max_validity)
            }),
            format!("{:?}", d.and_then(|d| d.attr("NotOnOrAfter"))),
        );
        out.check(
            "subject.no_not_before",
            d.is_some_and(|d| d.attr("NotBefore").is_none()),
            "the Web Browser SSO profile forbids NotBefore on bearer confirmation data",
        );
        out.check(
            "subject.in_response_to",
            d.and_then(|d| d.attr("InResponseTo")) == e.request_id.as_deref(),
            format!("{:?}", d.and_then(|d| d.attr("InResponseTo"))),
        );
    }

    let conditions = a.child(SAML, "Conditions");
    let from = instant(conditions.and_then(|c| c.attr("NotBefore")));
    let until = instant(conditions.and_then(|c| c.attr("NotOnOrAfter")));
    out.check(
        "conditions.window",
        match (from, until) {
            (Some(f), Some(u)) => {
                f <= e.now.saturating_add(e.skew)
                    && u > e.now.saturating_sub(e.skew)
                    && u.saturating_sub(f) <= e.max_validity
            }
            _ => false,
        },
        format!(
            "{:?} .. {:?}",
            conditions.and_then(|c| c.attr("NotBefore")),
            conditions.and_then(|c| c.attr("NotOnOrAfter"))
        ),
    );
    let audiences: Vec<String> = conditions
        .map(|c| {
            c.children_named(SAML, "AudienceRestriction")
                .flat_map(|r| r.children_named(SAML, "Audience"))
                .map(|x| x.text().trim().to_owned())
                .collect()
        })
        .unwrap_or_default();
    out.check(
        "conditions.audience",
        audiences.contains(&e.sp_entity),
        format!("{audiences:?}"),
    );
    let authn = a.child(SAML, "AuthnStatement");
    out.check(
        "authn.statement",
        authn.is_some_and(|s| {
            instant(s.attr("AuthnInstant")).is_some()
                && s.attr("SessionIndex").is_some_and(|i| !i.is_empty())
                && s.child(SAML, "AuthnContext")
                    .and_then(|c| c.child(SAML, "AuthnContextClassRef"))
                    .is_some_and(|c| !c.text().trim().is_empty())
        }),
        "AuthnInstant, SessionIndex and AuthnContextClassRef",
    );
    out.0
}

/// The attribute names an assertion carries (`Name`), with their value counts.
#[must_use]
pub fn attributes(response_xml: &str) -> Vec<(String, Option<String>, usize)> {
    let Ok(doc) = xml::parse(response_xml) else {
        return Vec::new();
    };
    doc.root
        .descendants()
        .into_iter()
        .filter(|e| e.is(SAML, "Attribute"))
        .map(|a| {
            (
                a.attr("Name").unwrap_or_default().to_owned(),
                a.attr("NameFormat").map(str::to_owned),
                a.children_named(SAML, "AttributeValue").count(),
            )
        })
        .collect()
}

/// Checks IdP metadata: an `IDPSSODescriptor` for SAML 2.0 with a signing key and SSO endpoints
/// on standard bindings, and an enveloped signature when the document is signed.
#[must_use]
pub fn check_metadata(metadata_xml: &str, idp_entity: &str) -> Vec<Finding> {
    let mut out = Out(Vec::new());
    let doc = match xml::parse(metadata_xml) {
        Ok(d) => d,
        Err(err) => {
            out.check("message.well_formed", false, err.to_string());
            return out.0;
        }
    };
    out.check("message.no_doctype", !doc.doctype, "");
    let r = &doc.root;
    out.check(
        "metadata.entity_id",
        r.is(MD, "EntityDescriptor") && r.attr("entityID") == Some(idp_entity),
        format!("{:?}", r.attr("entityID")),
    );
    let idp = r.child(MD, "IDPSSODescriptor");
    out.check(
        "metadata.idp_descriptor",
        idp.is_some_and(|d| {
            d.attr("protocolSupportEnumeration")
                .is_some_and(|p| p.split_whitespace().any(|x| x == SAMLP))
        }),
        "",
    );
    let signing = idp.is_some_and(|d| {
        d.children_named(MD, "KeyDescriptor")
            .any(|k| k.attr("use").is_none_or(|u| u == "signing"))
    });
    out.check("metadata.signing_key", signing, "");
    let sso: Vec<String> = idp
        .map(|d| {
            d.children_named(MD, "SingleSignOnService")
                .map(|s| s.attr("Binding").unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default();
    out.check(
        "metadata.sso_bindings",
        !sso.is_empty()
            && sso
                .iter()
                .all(|b| b.starts_with("urn:oasis:names:tc:SAML:2.0:bindings:")),
        format!("{sso:?}"),
    );
    if r.child(DS, "Signature").is_some() {
        signature(&mut out, r, "metadata");
    }
    out.0
}

/// Whether every finding holds.
#[must_use]
pub fn all_ok(findings: &[Finding]) -> bool {
    findings.iter().all(|f| f.ok)
}
