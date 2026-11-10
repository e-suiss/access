//! The suite against two stand-in IdPs: one that verifies like a careful implementation and one
//! with the classic flaws (it reads the root while the signature covers another element, and it
//! reads only the first text node). The careful one passes every case; the flawed one is caught.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use saml_idp_suite::profiles::{check_profile, profile};
use saml_idp_suite::request::{self, Class, Options, Outcome, Seen, Signer, Target, Template};
use saml_idp_suite::response::{Expectations, all_ok, check_metadata, check_response};
use saml_idp_suite::time::format_instant;
use saml_idp_suite::xml::{self, Element, Node};
use saml_idp_suite::{DS, SAML, SAMLP};

fn canonical(e: &Element, out: &mut String) {
    out.push('<');
    out.push_str(&e.name);
    let mut attrs = e.attrs.clone();
    attrs.sort();
    for (k, v) in attrs {
        out.push(' ');
        out.push_str(&k);
        out.push_str("=\"");
        out.push_str(&v);
        out.push('"');
    }
    out.push('>');
    for n in &e.children {
        match n {
            Node::Element(c) if c.is(DS, "Signature") => {}
            Node::Element(c) => canonical(c, out),
            Node::Text(t) => out.push_str(t),
            Node::Comment => {}
        }
    }
    out.push_str("</");
    out.push_str(&e.name);
    out.push('>');
}

fn digest(e: &Element) -> String {
    let mut s = String::new();
    canonical(e, &mut s);
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    format!("{:016x}", h.finish())
}

struct StandIn;

impl Signer for StandIn {
    fn sign(&mut self, t: &Template) -> Result<String, String> {
        let issuer = format!(
            r#"<saml:Issuer xmlns:saml="{SAML}">{}</saml:Issuer>"#,
            xml::escape(&t.issuer)
        );
        let open = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="{SAMLP}" ID="{}" Version="2.0" IssueInstant="2026-11-10T10:00:00Z" Destination="{}" AssertionConsumerServiceURL="{}">"#,
            t.id, t.destination, t.acs
        );
        let policy = r#"<samlp:NameIDPolicy AllowCreate="true"/>"#;
        let body = format!("{open}{issuer}{policy}</samlp:AuthnRequest>");
        let d = digest(&xml::parse(&body).unwrap().root);
        let sig = format!(
            r##"<ds:Signature xmlns:ds="{DS}"><ds:SignedInfo><ds:Reference URI="#{}"><ds:DigestValue>{d}</ds:DigestValue></ds:Reference></ds:SignedInfo></ds:Signature>"##,
            t.id
        );
        Ok(format!("{open}{issuer}{sig}{policy}</samlp:AuthnRequest>"))
    }
}

fn by_id<'a>(e: &'a Element, id: &str, found: &mut Vec<&'a Element>) {
    for d in e.descendants() {
        if d.attr("ID") == Some(id) {
            found.push(d);
        }
    }
}

fn reference(sig: &Element) -> Option<(String, String)> {
    let r = sig.child(DS, "SignedInfo")?.child(DS, "Reference")?;
    let uri = r.attr("URI")?.strip_prefix('#')?.to_owned();
    Some((uri, r.child(DS, "DigestValue")?.text()))
}

/// Verifies the root's own enveloped signature and reads only the root.
#[derive(Default)]
struct Careful {
    used: Vec<String>,
}

impl Target for Careful {
    fn submit(&mut self, x: &str) -> Outcome {
        if x.len() > 64 * 1024 {
            return Outcome::Refused("too large".into());
        }
        let Ok(doc) = xml::parse(x) else {
            return Outcome::Refused("malformed".into());
        };
        if doc.doctype {
            return Outcome::Refused("dtd".into());
        }
        let r = &doc.root;
        let Some(sig) = r.child(DS, "Signature") else {
            return Outcome::Refused("unsigned".into());
        };
        let Some((uri, value)) = reference(sig) else {
            return Outcome::Refused("no reference".into());
        };
        let mut found = Vec::new();
        by_id(r, &uri, &mut found);
        if found.len() != 1 || r.attr("ID") != Some(uri.as_str()) {
            return Outcome::Refused("reference is not the root".into());
        }
        if digest(r) != value {
            return Outcome::Refused("digest".into());
        }
        if self.used.contains(&uri) {
            return Outcome::Refused("replay".into());
        }
        self.used.push(uri.clone());
        Outcome::Accepted(Seen {
            id: uri,
            issuer: r.child(SAML, "Issuer").unwrap().text(),
            acs: r.attr("AssertionConsumerServiceURL").map(String::from),
        })
    }
}

/// Verifies whichever element the first signature references, then reads the root, and reads
/// only the Issuer's first text node.
struct Flawed;

impl Target for Flawed {
    fn submit(&mut self, x: &str) -> Outcome {
        let Ok(doc) = xml::parse(x) else {
            return Outcome::Refused("malformed".into());
        };
        let r = &doc.root;
        let Some(sig) = r.descendants().into_iter().find(|e| e.is(DS, "Signature")) else {
            return Outcome::Refused("unsigned".into());
        };
        let Some((uri, value)) = reference(sig) else {
            return Outcome::Refused("no reference".into());
        };
        let mut found = Vec::new();
        by_id(r, &uri, &mut found);
        if !found.iter().any(|e| digest(e) == value) {
            return Outcome::Refused("digest".into());
        }
        let issuer = r.child(SAML, "Issuer").unwrap();
        let first = issuer
            .children
            .iter()
            .find_map(|n| match n {
                Node::Text(t) => Some(t.clone()),
                _ => None,
            })
            .unwrap_or_default();
        Outcome::Accepted(Seen {
            id: r.attr("ID").unwrap().to_owned(),
            issuer: first,
            acs: r.attr("AssertionConsumerServiceURL").map(String::from),
        })
    }
}

fn opts() -> Options {
    Options {
        issuer: "https://sp.example.org/metadata".into(),
        acs: "https://sp.example.org/acs".into(),
        destination: "https://idp.example.net/sso".into(),
        signature_required: true,
        replay: true,
        size_limit: Some(64 * 1024),
    }
}

#[test]
fn a_careful_idp_passes_every_case() {
    let results = request::run(&mut Careful::default(), &mut StandIn, &opts()).unwrap();
    for r in &results {
        assert!(r.passed, "{} ({}): {}", r.name, r.class, r.detail);
    }
    for class in [
        Class::Baseline,
        Class::Wrapping,
        Class::Injection,
        Class::Tampering,
        Class::Unsigned,
        Class::Dtd,
        Class::Size,
        Class::Replay,
    ] {
        assert!(results.iter().any(|r| r.class == class), "{class}");
    }
    assert!(results.len() >= 16);
}

#[test]
fn a_flawed_idp_is_caught_by_wrapping_and_injection() {
    let results = request::run(&mut Flawed, &mut StandIn, &opts()).unwrap();
    let failed: Vec<&str> = results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| r.name)
        .collect();
    for name in [
        "xsw-extensions-wrap",
        "xsw-signature-object",
        "xsw-signature-moved",
        "comment-in-issuer",
        "cdata-in-issuer",
        "replay",
    ] {
        assert!(failed.contains(&name), "{name} not caught: {failed:?}");
    }
    assert!(!failed.contains(&"baseline"));
}

const IDP: &str = "https://idp.example.net/metadata";
const SP: &str = "https://sp.example.org/metadata";
const ACS: &str = "https://sp.example.org/acs";
const NOW: i64 = 1_794_312_000;

fn sig(id: &str, alg: &str) -> String {
    format!(
        r##"<ds:Signature xmlns:ds="{DS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="{alg}"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##
    )
}

fn response(alg: &str) -> String {
    let t = format_instant(NOW);
    let until = format_instant(NOW + 300);
    format!(
        r#"<samlp:Response xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}" ID="_r0123456789abcdef" Version="2.0" IssueInstant="{t}" Destination="{ACS}" InResponseTo="_q1"><saml:Issuer>{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a0123456789abcdef" Version="2.0" IssueInstant="{t}"><saml:Issuer>{IDP}</saml:Issuer>{}<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">u-1</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="{ACS}" NotOnOrAfter="{until}" InResponseTo="_q1"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{t}" NotOnOrAfter="{until}"><saml:AudienceRestriction><saml:Audience>{SP}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{t}" SessionIndex="s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="User.Email"><saml:AttributeValue>u@example.org</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"#,
        sig("_a0123456789abcdef", alg)
    )
}

fn expect() -> Expectations {
    Expectations {
        idp_entity: IDP.into(),
        sp_entity: SP.into(),
        acs: ACS.into(),
        request_id: Some("_q1".into()),
        now: NOW,
        skew: 180,
        max_validity: 600,
    }
}

#[test]
fn a_standard_response_passes_and_each_flaw_is_named() {
    let ecdsa = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    let good = check_response(&response(ecdsa), &expect());
    assert!(all_ok(&good), "{good:#?}");

    let failing = |xml: String, rule: &str| {
        let f = check_response(&xml, &expect());
        assert!(
            f.iter().any(|x| x.rule == rule && !x.ok),
            "{rule} not reported: {f:#?}"
        );
    };
    failing(
        response("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
        "signature.algorithms",
    );
    failing(
        response(ecdsa).replace(&format!(r#" Destination="{ACS}""#), ""),
        "response.destination",
    );
    failing(
        response(ecdsa).replace(">u-1<", ">u<!---->-1<"),
        "signature.no_comments",
    );
    failing(
        response(ecdsa).replace(
            r##"URI="#_a0123456789abcdef""##,
            r##"URI="#_r0123456789abcdef""##,
        ),
        "signature.assertion_reference",
    );
    failing(
        response(ecdsa).replace(SP, "https://other.example"),
        "conditions.audience",
    );
    failing(
        response(ecdsa).replace(
            "<saml:SubjectConfirmationData ",
            r#"<saml:SubjectConfirmationData NotBefore="2026-01-01T00:00:00Z" "#,
        ),
        "subject.no_not_before",
    );
    failing(
        format!("<!DOCTYPE r>{}", response(ecdsa)),
        "message.no_doctype",
    );
    let late = Expectations {
        now: NOW + 3600,
        ..expect()
    };
    assert!(
        check_response(&response(ecdsa), &late)
            .iter()
            .any(|f| f.rule == "conditions.window" && !f.ok)
    );
}

#[test]
fn profiles_add_requirements() {
    let x = response("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
    let slack = check_profile(profile("slack").unwrap(), &x);
    assert!(slack.iter().any(|f| f.rule == "profile.attribute" && f.ok));
    assert!(slack.iter().any(|f| f.rule == "profile.signing" && !f.ok));
    let workday = check_profile(profile("workday").unwrap(), &x);
    assert!(all_ok(&workday), "{workday:#?}");
    let aws = check_profile(profile("aws").unwrap(), &x);
    assert!(
        aws.iter()
            .filter(|f| f.rule == "profile.attribute")
            .all(|f| !f.ok)
    );
}

#[test]
fn metadata_needs_a_signing_key_and_standard_bindings() {
    let md = format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP}"><md:IDPSSODescriptor protocolSupportEnumeration="{SAMLP}"><md:KeyDescriptor use="signing"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.net/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
    );
    assert!(all_ok(&check_metadata(&md, IDP)));
    let bad = md.replace(r#" use="signing""#, r#" use="encryption""#);
    assert!(!all_ok(&check_metadata(&bad, IDP)));
}
