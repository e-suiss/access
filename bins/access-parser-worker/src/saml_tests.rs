//! The XSW regression corpus (8 classes and 3 newer ones) and the CVE regression corpus of
//! §10.6.1 against the worker's SAML operations (IDI-8, §14.6, SA-29). Every signed message is
//! written here in its canonical form and signed with a key made at run time; nothing signed is
//! committed.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use access_edge_core::saml::{Context, Facts, Kind, Redirect, Signed};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair};

use crate::dsig::{ECDSA_SHA256, RSA_SHA256};
use crate::saml::{redirect, request};

const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENV: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn sha256(data: &[u8]) -> Vec<u8> {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

/// A service provider's key and its self-signed certificate.
struct Sp {
    key: EcdsaKeyPair,
    cert: Vec<u8>,
}

fn sp() -> Sp {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec![String::from("sp.test")])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    let key = EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &kp.serialize_der(),
    )
    .unwrap();
    Sp {
        key,
        cert: cert.der().to_vec(),
    }
}

impl Sp {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.key
            .sign(&SystemRandom::new(), data)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    /// The canonical `SignedInfo` (with `xmlns:ds`) over `digest` of `#id`, and its signature.
    fn signed_info(&self, id: &str, digest: &[u8], extra_transform: &str) -> (String, String) {
        let si = format!(
            r##"<ds:SignedInfo xmlns:ds="{DS_NS}"><ds:CanonicalizationMethod Algorithm="{C14N}"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="{ECDSA_SHA256}"></ds:SignatureMethod><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="{ENV}"></ds:Transform><ds:Transform Algorithm="{C14N}"></ds:Transform>{extra_transform}</ds:Transforms><ds:DigestMethod Algorithm="{SHA256_URI}"></ds:DigestMethod><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
            b64(digest)
        );
        let value = b64(&self.sign(si.as_bytes()));
        (si, value)
    }

    /// The `ds:Signature` element over the canonical `body` (the message without signature).
    fn signature(&self, id: &str, body: &str) -> String {
        let (si, value) = self.signed_info(id, &sha256(body.as_bytes()), "");
        let si = si.replacen(&format!(r#" xmlns:ds="{DS_NS}""#), "", 1);
        format!(
            r#"<ds:Signature xmlns:ds="{DS_NS}">{si}<ds:SignatureValue>{value}</ds:SignatureValue></ds:Signature>"#
        )
    }
}

const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

fn head(id: &str) -> String {
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{SAMLP_NS}" AssertionConsumerServiceURL="https://sp.test/acs" Destination="https://idp.test/sso" ForceAuthn="true" ID="{id}" IssueInstant="2026-11-10T10:00:00Z" Version="2.0">"#
    )
}

const ISSUER: &str = r#"<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.test</saml:Issuer>"#;
const POLICY: &str = r#"<samlp:NameIDPolicy AllowCreate="false" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"></samlp:NameIDPolicy><samlp:Scoping ProxyCount="0"><samlp:RequesterID>urn:requester</samlp:RequesterID></samlp:Scoping>"#;
const TAIL: &str = "</samlp:AuthnRequest>";

/// A canonical, signed `AuthnRequest` with identifier `id`.
fn signed(sp: &Sp, id: &str) -> String {
    let body = format!("{}{ISSUER}{POLICY}{TAIL}", head(id));
    let sig = sp.signature(id, &body);
    format!("{}{ISSUER}{sig}{POLICY}{TAIL}", head(id))
}

fn ctx(sp: &Sp) -> Context {
    Context {
        inflate: false,
        certs: vec![sp.cert.clone()],
        require_signature: true,
    }
}

fn run(c: &Context, xml: &str) -> Result<Facts, &'static str> {
    let (_, out) = request(&c.encode(xml.as_bytes()).unwrap())?;
    Ok(Facts::decode(&out).unwrap())
}

// IDI-8, §10.6.1
#[test]
fn a_signed_request_verifies_and_its_facts_come_from_the_signed_element() {
    let sp = sp();
    let f = run(&ctx(&sp), &signed(&sp, "_r1")).unwrap();
    assert_eq!(f.kind, Kind::Authn);
    assert_eq!(f.id, "_r1");
    assert_eq!(f.issuer, "https://sp.test");
    assert_eq!(f.acs_url.as_deref(), Some("https://sp.test/acs"));
    assert!(f.force_authn && !f.is_passive);
    assert_eq!(f.allow_create, Some(false));
    assert_eq!(f.requester_ids, ["urn:requester"]);
    assert_eq!(f.proxy_count, Some(0));
    assert_eq!(f.signed, Signed::Verified(String::from(ECDSA_SHA256)));
}

// §10.6.1
#[test]
fn a_tampered_request_or_a_foreign_key_is_refused() {
    let sp = sp();
    let tampered = signed(&sp, "_r1").replace("https://sp.test/acs", "https://evil.test/acs");
    assert_eq!(run(&ctx(&sp), &tampered), Err("signature-digest"));
    let other = self::sp();
    assert_eq!(
        run(&ctx(&other), &signed(&sp, "_r1")),
        Err("signature-invalid")
    );
    let unsigned = format!("{}{ISSUER}{POLICY}{TAIL}", head("_r1"));
    assert_eq!(run(&ctx(&sp), &unsigned), Err("signature-missing"));
    let lenient = Context {
        require_signature: false,
        ..ctx(&sp)
    };
    assert_eq!(run(&lenient, &unsigned).unwrap().signed, Signed::Absent);
}

/// Wraps `inner` as an `Extensions` child of a new request whose identifier is `outer`.
fn wrapped(outer: &str, inner: &str, signature: &str) -> String {
    format!(
        "{}{ISSUER}{signature}<samlp:Extensions>{inner}</samlp:Extensions>{POLICY}{TAIL}",
        head(outer).replace("https://sp.test/acs", "https://evil.test/acs")
    )
}

fn strip_signature(xml: &str) -> (String, String) {
    let start = xml.find("<ds:Signature").unwrap();
    let end = xml.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    (
        format!("{}{}", &xml[..start], &xml[end..]),
        String::from(&xml[start..end]),
    )
}

// IDI-8
#[test]
fn idi_8_xsw_corpus_is_refused() {
    let sp = sp();
    let c = ctx(&sp);
    let original = signed(&sp, "_r1");
    let (bare, sig) = strip_signature(&original);
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "xsw1: signed original wrapped under a new unsigned root",
            wrapped("_evil", &original, ""),
            "signature-not-enveloped",
        ),
        (
            "xsw2: the new root takes the original's identifier",
            wrapped("_r1", &original, ""),
            "xml-duplicate-id",
        ),
        (
            "xsw3: the signature moves to the new root, still naming the original",
            wrapped("_evil", &bare, &sig),
            "signature-reference",
        ),
        (
            "xsw4: the new root wraps the original with its signature as a sibling",
            wrapped("_evil", &format!("{bare}{sig}"), ""),
            "signature-not-enveloped",
        ),
        (
            "xsw5: the original rides in the SOAP header, an evil request in the body",
            format!(
                r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header>{original}</soap:Header><soap:Body>{}{ISSUER}{POLICY}{TAIL}</soap:Body></soap:Envelope>"#,
                head("_evil")
            ),
            "signature-not-enveloped",
        ),
        (
            "xsw6: a second copy of the signature",
            original.replacen(&sig, &format!("{sig}{sig}"), 1),
            "signature-multiple",
        ),
        (
            "xsw7: the reference names the whole document",
            original.replacen(r##"URI="#_r1""##, r#"URI="""#, 1),
            "signature-reference",
        ),
        (
            "xsw8: the reference is an XPointer",
            original.replacen(r##"URI="#_r1""##, r##"URI="#xpointer(/)""##, 1),
            "signature-reference",
        ),
        (
            "new 1: an extra transform selects a different node set",
            {
                let body = format!("{}{ISSUER}{POLICY}{TAIL}", head("_r1"));
                let (si, value) = sp.signed_info(
                    "_r1",
                    &sha256(body.as_bytes()),
                    r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::samlp:Scoping)</ds:XPath></ds:Transform>"#,
                );
                let si = si.replacen(&format!(r#" xmlns:ds="{DS_NS}""#), "", 1);
                format!(
                    r#"{}{ISSUER}<ds:Signature xmlns:ds="{DS_NS}">{si}<ds:SignatureValue>{value}</ds:SignatureValue></ds:Signature>{POLICY}{TAIL}"#,
                    head("_r1")
                )
            },
            "signature-transform",
        ),
        (
            "new 2: a second reference in SignedInfo",
            {
                let start = original.find("<ds:Reference").unwrap();
                let end = original.find("</ds:Reference>").unwrap() + "</ds:Reference>".len();
                let r = &original[start..end];
                original.replacen(r, &format!("{r}{r}"), 1)
            },
            "signature-reference-count",
        ),
        (
            "new 3: the ds prefix is rebound to a look-alike namespace",
            original.replacen(DS_NS, "http://www.w3.org/2000/09/xmldsig#x", 1),
            "signature-missing",
        ),
    ];
    for (name, xml, code) in cases {
        assert_eq!(run(&c, &xml).map(|f| f.id), Err(code), "{name}");
    }
}

// TI-9, OP-155 m.3 (e), SHA-1
#[test]
fn sha1_is_refused() {
    let sp = sp();
    let original = signed(&sp, "_r1");
    let rsa_sha1 = original.replacen(
        ECDSA_SHA256,
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        1,
    );
    assert_eq!(run(&ctx(&sp), &rsa_sha1), Err("signature-alg"));
    let sha1 = original.replacen(SHA256_URI, "http://www.w3.org/2000/09/xmldsig#sha1", 1);
    assert_eq!(run(&ctx(&sp), &sha1), Err("signature-digest-alg"));
    let r = Redirect {
        certs: vec![sp.cert.clone()],
        sig_alg: String::from("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
        signed: b"SAMLRequest=x".to_vec(),
        signature: sp.sign(b"SAMLRequest=x"),
    };
    assert_eq!(
        redirect(&r.encode().unwrap()).map(|_| ()),
        Err("signature-alg")
    );
}

// §3.4.4.1
#[test]
fn a_redirect_signature_verifies_over_the_received_octets() {
    let sp = sp();
    let signed = b"SAMLRequest=fZJb&RelayState=r&SigAlg=http%3A%2F%2Fwww.w3.org".to_vec();
    let r = Redirect {
        certs: vec![sp.cert.clone()],
        sig_alg: String::from(ECDSA_SHA256),
        signed: signed.clone(),
        signature: sp.sign(&signed),
    };
    assert!(redirect(&r.encode().unwrap()).is_ok());
    let changed = Redirect {
        signed: b"SAMLRequest=fZJb&RelayState=s&SigAlg=http%3A%2F%2Fwww.w3.org".to_vec(),
        ..r.clone()
    };
    assert_eq!(
        redirect(&changed.encode().unwrap()).map(|_| ()),
        Err("signature-invalid")
    );
    let rsa = Redirect {
        sig_alg: String::from(RSA_SHA256),
        ..r
    };
    assert_eq!(
        redirect(&rsa.encode().unwrap()).map(|_| ()),
        Err("signature-invalid")
    );
}

fn deflate(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(data, 9)
}

// §10.6.1
#[test]
fn cve_corpus_is_refused() {
    let sp = sp();
    let c = ctx(&sp);
    let original = signed(&sp, "_r1");
    let (bare, sig) = strip_signature(&original);

    // CVE-2025-25291, CVE-2025-25292
    let doctype = format!(
        r#"<!DOCTYPE samlp:AuthnRequest [<!ATTLIST samlp:AuthnRequest ID CDATA "_x">]>{original}"#
    );
    assert_eq!(run(&c, &doctype).map(|_| ()), Err("xml-doctype"));

    // CVE-2025-25293, CVE-2023-28119
    let bomb = format!(
        "{}{ISSUER}<samlp:Extensions>{}</samlp:Extensions>{TAIL}",
        head("_b"),
        " ".repeat(900_000)
    );
    let inflating = Context {
        inflate: true,
        ..c.clone()
    };
    let r = request(&inflating.encode(&deflate(bomb.as_bytes())).unwrap()).map(|_| ());
    assert!(matches!(r, Err("xml-ratio" | "xml-too-large")), "{r:?}");

    // CVE-2024-45409
    let two_digests = original.replacen(
        "</ds:DigestValue>",
        "</ds:DigestValue><ds:DigestValue>AAAA</ds:DigestValue>",
        1,
    );
    assert_eq!(
        run(&c, &two_digests).map(|_| ()),
        Err("signature-malformed")
    );

    // CVE-2025-29774, CVE-2025-29775
    let si_start = original.find("<ds:SignedInfo>").unwrap();
    let si_end = original.find("</ds:SignedInfo>").unwrap() + "</ds:SignedInfo>".len();
    let si = &original[si_start..si_end];
    let two_si = original.replacen(si, &format!("{si}{si}"), 1);
    assert_eq!(run(&c, &two_si).map(|_| ()), Err("signature-malformed"));
    let dv_start = original.find("<ds:DigestValue>").unwrap() + "<ds:DigestValue>".len();
    let commented = format!(
        "{}AAAA<!---->{}",
        &original[..dv_start],
        &original[dv_start..]
    );
    assert_eq!(run(&c, &commented).map(|_| ()), Err("signature-digest"));

    // CVE-2017-11427, CVE-2017-11428
    let logout = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{SAMLP_NS}" ID="_l1" IssueInstant="2026-11-10T10:00:00Z" Version="2.0">{ISSUER}<saml:NameID xmlns:saml="{SAML_NS}">a@x.test<!---->.evil.test</saml:NameID><samlp:SessionIndex>_s1</samlp:SessionIndex></samlp:LogoutRequest>"#
    );
    let lenient = Context {
        require_signature: false,
        certs: vec![],
        inflate: false,
    };
    let f = run(&lenient, &logout).unwrap();
    assert_eq!(f.name_id.as_deref(), Some("a@x.test.evil.test"));
    assert_eq!(f.session_indexes, ["_s1"]);

    // CVE-2022-39299
    // IDI-7
    assert_eq!(run(&c, &bare).map(|_| ()), Err("signature-missing"));

    // CVE-2018-0489
    let entity = original.replacen("https://sp.test</saml:Issuer>", "&sp;</saml:Issuer>", 1);
    assert_eq!(run(&c, &entity).map(|_| ()), Err("xml-entity"));

    // CVE-2025-23369
    let rebound = original.replacen(
        r"<ds:SignedInfo>",
        r#"<ds:SignedInfo xmlns:ds="urn:evil">"#,
        1,
    );
    assert_eq!(run(&c, &rebound).map(|_| ()), Err("signature-malformed"));

    // CVE-2025-54419
    let part = format!(
        r#"{}{ISSUER}{}<samlp:Extensions ID="_part"></samlp:Extensions>{POLICY}{TAIL}"#,
        head("_r9"),
        sig.replacen(r##"URI="#_r1""##, r##"URI="#_part""##, 1)
    );
    assert_eq!(run(&c, &part).map(|_| ()), Err("signature-reference"));

    // CVE-2025-66578
    let twin = original.replacen(
        "<samlp:NameIDPolicy",
        r#"<samlp:Extensions Id="_r1"></samlp:Extensions><samlp:NameIDPolicy"#,
        1,
    );
    assert_eq!(run(&c, &twin).map(|_| ()), Err("xml-duplicate-id"));
    drop(bare);
}

// §10.6.1
#[test]
fn an_ecp_request_is_read_from_the_soap_body() {
    let sp = sp();
    let env = format!(
        r#"<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"><S:Body>{}</S:Body></S:Envelope>"#,
        signed(&sp, "_e1")
    );
    let f = run(&ctx(&sp), &env).unwrap();
    assert!(f.soap);
    assert_eq!(f.id, "_e1");
}

/// P4: a canonical assertion `id` of upstream `https://idp.test` about `name_id`, with
/// `extra` inserted before its closing tag; signed by `idp` when `sign`.
fn assertion(idp: &Sp, id: &str, name_id: &str, sign: bool) -> String {
    let head = format!(
        r#"<saml:Assertion xmlns:saml="{SAML_NS}" ID="{id}" IssueInstant="2026-11-10T10:00:00Z" Version="2.0">"#
    );
    let issuer = "<saml:Issuer>https://idp.test</saml:Issuer>";
    let rest = format!(
        concat!(
            r#"<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{n}</saml:NameID>"#,
            r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="_req1" NotOnOrAfter="2026-11-10T10:05:00Z" Recipient="https://sp.test/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject>"#,
            r#"<saml:Conditions NotBefore="2026-11-10T09:59:00Z" NotOnOrAfter="2026-11-10T10:05:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.test</saml:Audience></saml:AudienceRestriction></saml:Conditions>"#,
            r#"<saml:AuthnStatement AuthnInstant="2026-11-10T10:00:00Z" SessionIndex="s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"#,
            r#"<saml:AttributeStatement><saml:Attribute Name="mail"><saml:AttributeValue>ada@corp.test</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>"#,
            "</saml:Assertion>"
        ),
        n = name_id
    );
    let body = format!("{head}{issuer}{rest}");
    if !sign {
        return body;
    }
    let sig = idp.signature(id, &body);
    format!("{head}{issuer}{sig}{rest}")
}

fn response(inner: &str, status: &str) -> String {
    format!(
        r#"<samlp:Response xmlns:samlp="{SAMLP_NS}" ID="r1" InResponseTo="_req1" IssueInstant="2026-11-10T10:00:00Z" Version="2.0"><saml:Issuer xmlns:saml="{SAML_NS}">https://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:{status}"></samlp:StatusCode></samlp:Status>{inner}</samlp:Response>"#
    )
}

fn run_assertion(
    c: &Context,
    xml: &str,
) -> Result<access_edge_core::saml::AssertionFacts, &'static str> {
    let (_, out) = crate::saml::assertion(&c.encode(xml.as_bytes()).unwrap())?;
    Ok(access_edge_core::saml::AssertionFacts::decode(&out).unwrap())
}

// OP-155 m.3 (h), IDI-8, Ek B 4784
#[test]
fn an_upstream_assertion_verifies_and_its_facts_come_from_the_signed_assertion() {
    let idp = sp();
    let c = ctx(&idp);
    let f = run_assertion(
        &c,
        &response(&assertion(&idp, "a1", "emp-1", true), "Success"),
    )
    .unwrap();
    assert_eq!(f.id, "a1");
    assert_eq!(f.issuer, "https://idp.test");
    assert_eq!(f.name_id, "emp-1");
    assert_eq!(f.audiences, ["https://sp.test"]);
    assert_eq!(f.in_response_to.as_deref(), Some("_req1"));
    assert_eq!(f.recipient.as_deref(), Some("https://sp.test/acs"));
    assert_eq!(f.session_index.as_deref(), Some("s1"));
    assert!(
        f.authn_context
            .unwrap()
            .ends_with("PasswordProtectedTransport")
    );
    assert_eq!(
        f.attributes,
        [(String::from("mail"), vec![String::from("ada@corp.test")])]
    );
    assert!(f.in_response);
    assert_eq!(f.signed, ECDSA_SHA256);
    let bare = run_assertion(&c, &assertion(&idp, "a2", "emp-2", true)).unwrap();
    assert!(!bare.in_response);
}

// OP-155 m.3 (h), IDI-8
#[test]
fn an_unsigned_tampered_wrapped_encrypted_or_failed_assertion_is_refused() {
    let idp = sp();
    let c = ctx(&idp);
    assert_eq!(
        run_assertion(
            &c,
            &response(&assertion(&idp, "a1", "emp-1", false), "Success")
        ),
        Err("signature-missing")
    );
    let signed = assertion(&idp, "a1", "emp-1", true);
    let tampered = signed.replace(">emp-1<", ">emp-9<");
    assert!(run_assertion(&c, &response(&tampered, "Success")).is_err());
    let other = sp();
    assert!(run_assertion(&ctx(&other), &response(&signed, "Success")).is_err());
    let two = format!("{signed}{}", assertion(&idp, "a2", "evil", false));
    assert_eq!(
        run_assertion(&c, &response(&two, "Success")),
        Err("saml-message")
    );
    assert_eq!(
        run_assertion(&c, &response(&signed, "Requester")),
        Err("saml-status")
    );
    let enc =
        format!(r#"<saml:EncryptedAssertion xmlns:saml="{SAML_NS}"></saml:EncryptedAssertion>"#);
    assert_eq!(
        run_assertion(&c, &response(&enc, "Success")),
        Err("saml-encrypted")
    );
    let none = Context {
        certs: Vec::new(),
        ..ctx(&idp)
    };
    assert_eq!(
        run_assertion(&none, &response(&signed, "Success")),
        Err("signature-no-key")
    );
}

/// The worker as the neutral SAML `IdP` suite sees it: a request is accepted when the worker
/// returns its facts.
struct SuiteTarget(Context);

impl saml_idp_suite::request::Target for SuiteTarget {
    fn submit(&mut self, xml: &str) -> saml_idp_suite::request::Outcome {
        use saml_idp_suite::request::{Outcome, Seen};
        match run(&self.0, xml) {
            Ok(f) => Outcome::Accepted(Seen {
                id: f.id,
                issuer: f.issuer,
                acs: f.acs_url,
            }),
            Err(code) => Outcome::Refused(String::from(code)),
        }
    }
}

struct SuiteSigner(Sp);

impl saml_idp_suite::request::Signer for SuiteSigner {
    fn sign(&mut self, t: &saml_idp_suite::request::Template) -> Result<String, String> {
        let head = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="{SAMLP_NS}" AssertionConsumerServiceURL="{}" Destination="{}" ID="{}" IssueInstant="2026-11-10T10:00:00Z" Version="2.0">"#,
            t.acs, t.destination, t.id
        );
        let issuer = format!(
            r#"<saml:Issuer xmlns:saml="{SAML_NS}">{}</saml:Issuer>"#,
            t.issuer
        );
        let body = format!("{head}{issuer}{POLICY}{TAIL}");
        let sig = self.0.signature(&t.id, &body);
        Ok(format!("{head}{issuer}{sig}{POLICY}{TAIL}"))
    }
}

// IDI-8, §10.6.1, Ek B 5004
#[test]
fn the_saml_idp_suite_request_corpus_is_refused_or_answered_for_the_signed_values() {
    let sp = sp();
    let mut target = SuiteTarget(ctx(&sp));
    let mut signer = SuiteSigner(sp);
    let results = saml_idp_suite::request::run(
        &mut target,
        &mut signer,
        &saml_idp_suite::request::Options {
            issuer: String::from("https://sp.test"),
            acs: String::from("https://sp.test/acs"),
            destination: String::from("https://idp.test/sso"),
            signature_required: true,
            replay: false,
            size_limit: Some(crate::parse::MAX_XML),
        },
    )
    .unwrap();
    assert!(results.len() >= 15, "{results:?}");
    for r in &results {
        assert!(r.passed, "{} ({}): {}", r.name, r.class, r.detail);
    }
}

const SP_FIXTURES: &[(&str, &str)] = &[
    (
        "adfs",
        include_str!("../../../conformance/interop/fixtures/saml/adfs.xml"),
    ),
    (
        "atlassian",
        include_str!("../../../conformance/interop/fixtures/saml/atlassian.xml"),
    ),
    (
        "aws-identity-center",
        include_str!("../../../conformance/interop/fixtures/saml/aws-identity-center.xml"),
    ),
    (
        "google-workspace",
        include_str!("../../../conformance/interop/fixtures/saml/google-workspace.xml"),
    ),
    (
        "salesforce",
        include_str!("../../../conformance/interop/fixtures/saml/salesforce.xml"),
    ),
    (
        "servicenow",
        include_str!("../../../conformance/interop/fixtures/saml/servicenow.xml"),
    ),
    (
        "slack",
        include_str!("../../../conformance/interop/fixtures/saml/slack.xml"),
    ),
    (
        "workday",
        include_str!("../../../conformance/interop/fixtures/saml/workday.xml"),
    ),
    (
        "zoom",
        include_str!("../../../conformance/interop/fixtures/saml/zoom.xml"),
    ),
];

// IDP-40, OP-155 m.3 (q), Ek B 4934, 5024
#[test]
fn service_provider_requests_read_the_same_as_an_independent_reader() {
    use saml_idp_suite::{SAML, SAMLP};
    let lenient = Context {
        inflate: false,
        certs: vec![],
        require_signature: false,
    };
    for (name, xml) in SP_FIXTURES {
        let f = run(&lenient, xml).unwrap_or_else(|e| panic!("{name}: {e}"));
        let doc = saml_idp_suite::xml::parse(xml).unwrap();
        let r = &doc.root;
        assert!(r.is(SAMLP, "AuthnRequest"), "{name}");
        assert_eq!(f.kind, Kind::Authn, "{name}");
        assert_eq!(Some(f.id.as_str()), r.attr("ID"), "{name}");
        assert_eq!(f.issuer, r.child(SAML, "Issuer").unwrap().text(), "{name}");
        assert_eq!(
            f.acs_url.as_deref(),
            r.attr("AssertionConsumerServiceURL"),
            "{name}"
        );
        assert_eq!(
            f.protocol_binding.as_deref(),
            r.attr("ProtocolBinding"),
            "{name}"
        );
        assert_eq!(
            f.force_authn,
            r.attr("ForceAuthn") == Some("true"),
            "{name}"
        );
        assert_eq!(f.is_passive, r.attr("IsPassive") == Some("true"), "{name}");
        let policy = r.child(SAMLP, "NameIDPolicy");
        assert_eq!(
            f.nameid_format.as_deref(),
            policy.and_then(|p| p.attr("Format")),
            "{name}"
        );
        assert_eq!(f.signed, Signed::Absent, "{name}");
    }
}
