//! The SAML requests an identity provider reads (SAML Core §3.4.1, §3.7.1, §10.6.1): an
//! `AuthnRequest` or a `LogoutRequest`, alone or in the SOAP body of an ECP exchange. The
//! message is read into one tree, its enveloped signature is verified against the pinned
//! certificates, and its facts are read from that same element (IDI-8).

use access_edge_core::ipc::Summary;
use access_edge_core::saml::{
    AssertionFacts, Context, Facts, Kind, MAX_ATTRIBUTES, MAX_LIST, MAX_TEXT, Redirect, Signed,
};

use crate::dom::{self, Doc};
use crate::dsig;

/// The SAML 2.0 protocol namespace.
pub(crate) const SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// The SAML 2.0 assertion namespace.
pub(crate) const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// The SOAP 1.1 envelope namespace (ECP, SAML Bindings §3.2).
pub(crate) const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";

fn bounded(s: &str) -> Result<String, &'static str> {
    if s.len() > MAX_TEXT || s.chars().any(char::is_control) {
        Err("saml-field")
    } else {
        Ok(String::from(s))
    }
}

fn boolean(v: Option<&str>) -> Result<Option<bool>, &'static str> {
    match v {
        None => Ok(None),
        Some("true" | "1") => Ok(Some(true)),
        Some("false" | "0") => Ok(Some(false)),
        Some(_) => Err("saml-field"),
    }
}

fn uint(v: Option<&str>) -> Result<Option<u64>, &'static str> {
    v.map(|s| {
        if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err("saml-field");
        }
        s.parse::<u64>().map_err(|_| "saml-field")
    })
    .transpose()
}

fn opt(doc: &Doc, at: usize, local: &str) -> Result<Option<String>, &'static str> {
    doc.get(at)?.attr(local).map(bounded).transpose()
}

/// The message element: the root, or the one child of a SOAP envelope's body.
fn message(doc: &Doc) -> Result<(usize, bool), &'static str> {
    let root = doc.get(0)?;
    if !root.is(SOAP, "Envelope") {
        return Ok((0, false));
    }
    let body = doc.one(0, SOAP, "Body")?.ok_or("saml-soap")?;
    match doc.kids(body)?.as_slice() {
        [one] => Ok((*one, true)),
        _ => Err("saml-soap"),
    }
}

fn facts(doc: &Doc, at: usize, soap: bool, signed: Signed) -> Result<Facts, &'static str> {
    let e = doc.get(at)?;
    let kind = if e.is(SAMLP, "AuthnRequest") {
        Kind::Authn
    } else if e.is(SAMLP, "LogoutRequest") && !soap {
        Kind::Logout
    } else {
        return Err("saml-message");
    };
    if e.attr("Version") != Some("2.0") {
        return Err("saml-version");
    }
    let id = opt(doc, at, "ID")?.ok_or("saml-field")?;
    let issue_instant = opt(doc, at, "IssueInstant")?.ok_or("saml-field")?;
    let issuer_el = doc.one(at, SAML, "Issuer")?.ok_or("saml-issuer")?;
    let issuer = bounded(doc.text(issuer_el)?.trim())?;
    if issuer.is_empty() {
        return Err("saml-issuer");
    }
    let mut f = Facts {
        kind,
        id,
        issue_instant,
        destination: opt(doc, at, "Destination")?,
        issuer,
        acs_url: None,
        acs_index: None,
        protocol_binding: None,
        force_authn: false,
        is_passive: false,
        nameid_format: None,
        allow_create: None,
        sp_name_qualifier: None,
        requester_ids: Vec::new(),
        proxy_count: None,
        signed,
        name_id: None,
        session_indexes: Vec::new(),
        soap,
    };
    match kind {
        Kind::Authn => authn(doc, at, &mut f)?,
        Kind::Logout => logout(doc, at, &mut f)?,
    }
    Ok(f)
}

fn authn(doc: &Doc, at: usize, f: &mut Facts) -> Result<(), &'static str> {
    f.acs_url = opt(doc, at, "AssertionConsumerServiceURL")?;
    f.acs_index = uint(doc.get(at)?.attr("AssertionConsumerServiceIndex"))?;
    if f.acs_url.is_some() && f.acs_index.is_some() {
        return Err("saml-acs-both");
    }
    f.protocol_binding = opt(doc, at, "ProtocolBinding")?;
    f.force_authn = boolean(doc.get(at)?.attr("ForceAuthn"))?.unwrap_or(false);
    f.is_passive = boolean(doc.get(at)?.attr("IsPassive"))?.unwrap_or(false);
    if let Some(p) = doc.one(at, SAMLP, "NameIDPolicy")? {
        f.nameid_format = opt(doc, p, "Format")?;
        f.allow_create = boolean(doc.get(p)?.attr("AllowCreate"))?;
        f.sp_name_qualifier = opt(doc, p, "SPNameQualifier")?;
    }
    if let Some(s) = doc.one(at, SAMLP, "Scoping")? {
        f.proxy_count = uint(doc.get(s)?.attr("ProxyCount"))?;
        let ids = doc.named(s, SAMLP, "RequesterID")?;
        if ids.len() > MAX_LIST {
            return Err("saml-field");
        }
        for r in ids {
            f.requester_ids.push(bounded(doc.text(r)?.trim())?);
        }
    }
    Ok(())
}

fn logout(doc: &Doc, at: usize, f: &mut Facts) -> Result<(), &'static str> {
    if doc.one(at, SAML, "EncryptedID")?.is_some() || doc.one(at, SAML, "BaseID")?.is_some() {
        return Err("saml-name-id");
    }
    let n = doc.one(at, SAML, "NameID")?.ok_or("saml-name-id")?;
    f.name_id = Some(bounded(doc.text(n)?.trim())?);
    let indexes = doc.named(at, SAMLP, "SessionIndex")?;
    if indexes.len() > MAX_LIST {
        return Err("saml-field");
    }
    for i in indexes {
        f.session_indexes.push(bounded(doc.text(i)?.trim())?);
    }
    Ok(())
}

/// `saml.request`: reads the message of `input` (a [`Context`], then the message), verifies its
/// enveloped signature when the context names certificates, and returns its facts.
///
/// # Errors
/// A stable refusal code.
pub(crate) fn request(input: &[u8]) -> Result<(Summary, Vec<u8>), &'static str> {
    let (ctx, raw) = Context::decode(input).map_err(|_| "frame-malformed")?;
    let inflated;
    let xml = if ctx.inflate {
        inflated = crate::parse::inflate(raw)?.1;
        inflated.as_slice()
    } else {
        raw
    };
    let summary = crate::parse::xml(xml)?;
    let doc = dom::read(xml)?;
    let (at, soap) = message(&doc)?;
    let signed = if ctx.certs.is_empty() {
        if ctx.require_signature {
            return Err("signature-no-key");
        }
        Signed::Absent
    } else {
        match dsig::enveloped(&doc, at, &ctx.certs)? {
            Some(alg) => Signed::Verified(alg),
            None if ctx.require_signature => return Err("signature-missing"),
            None => Signed::Absent,
        }
    };
    let f = facts(&doc, at, soap, signed)?;
    let out = f.encode().map_err(|_| "saml-field")?;
    Ok((summary, out))
}

/// `saml.redirect`: verifies a detached HTTP-Redirect signature with a pinned certificate.
///
/// # Errors
/// A stable refusal code.
pub(crate) fn redirect(input: &[u8]) -> Result<(Summary, Vec<u8>), &'static str> {
    let r = Redirect::decode(input).map_err(|_| "frame-malformed")?;
    dsig::verify_with(&r.certs, &r.sig_alg, &r.signed, &r.signature)?;
    let out = access_edge_core::saml::encode_verified(&r.sig_alg).map_err(|_| "saml-field")?;
    Ok((Summary::default(), out))
}

/// The SAML 2.0 success status (SAML Core §3.2.2.2).
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// The bearer subject confirmation method (SAML Profiles §3.3).
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

fn text_of(doc: &Doc, at: usize) -> Result<String, &'static str> {
    bounded(doc.text(at)?.trim())
}

/// The one assertion of an upstream's message: the root, or the one child of a `samlp:Response`
/// with a success status. An encrypted assertion, a second assertion anywhere in the document
/// or a non-success status is refused (OP-155 m.3 (h), IDI-8).
fn the_assertion(doc: &Doc) -> Result<(usize, bool), &'static str> {
    let all = doc
        .subtree(0)?
        .into_iter()
        .filter(|&i| {
            doc.get(i)
                .is_ok_and(|e| e.is(SAML, "Assertion") || e.is(SAML, "EncryptedAssertion"))
        })
        .collect::<Vec<_>>();
    if all
        .iter()
        .any(|&i| doc.get(i).is_ok_and(|e| e.is(SAML, "EncryptedAssertion")))
    {
        return Err("saml-encrypted");
    }
    let root = doc.get(0)?;
    if root.is(SAML, "Assertion") {
        return if all.len() == 1 {
            Ok((0, false))
        } else {
            Err("saml-message")
        };
    }
    if !root.is(SAMLP, "Response") || root.attr("Version") != Some("2.0") {
        return Err("saml-message");
    }
    let status = doc.one(0, SAMLP, "Status")?.ok_or("saml-status")?;
    let code = doc.one(status, SAMLP, "StatusCode")?.ok_or("saml-status")?;
    if doc.get(code)?.attr("Value") != Some(SUCCESS) {
        return Err("saml-status");
    }
    match (doc.named(0, SAML, "Assertion")?.as_slice(), all.len()) {
        ([one], 1) => Ok((*one, true)),
        _ => Err("saml-message"),
    }
}

fn assertion_facts(
    doc: &Doc,
    at: usize,
    in_response: bool,
    signed: String,
) -> Result<AssertionFacts, &'static str> {
    if doc.get(at)?.attr("Version") != Some("2.0") {
        return Err("saml-version");
    }
    let issuer = text_of(doc, doc.one(at, SAML, "Issuer")?.ok_or("saml-issuer")?)?;
    if issuer.is_empty() {
        return Err("saml-issuer");
    }
    let subject = doc.one(at, SAML, "Subject")?.ok_or("saml-name-id")?;
    if doc.one(subject, SAML, "EncryptedID")?.is_some()
        || doc.one(subject, SAML, "BaseID")?.is_some()
    {
        return Err("saml-name-id");
    }
    let n = doc.one(subject, SAML, "NameID")?.ok_or("saml-name-id")?;
    let name_id = text_of(doc, n)?;
    if name_id.is_empty() {
        return Err("saml-name-id");
    }
    let mut f = AssertionFacts {
        id: opt(doc, at, "ID")?.ok_or("saml-field")?,
        issuer,
        issue_instant: opt(doc, at, "IssueInstant")?.ok_or("saml-field")?,
        name_id,
        name_id_format: opt(doc, n, "Format")?,
        audiences: Vec::new(),
        not_before: None,
        not_on_or_after: None,
        recipient: None,
        confirmation_not_on_or_after: None,
        in_response_to: None,
        authn_instant: None,
        session_index: None,
        authn_context: None,
        attributes: Vec::new(),
        signed,
        in_response,
    };
    let bearer: Vec<usize> = doc
        .named(subject, SAML, "SubjectConfirmation")?
        .into_iter()
        .filter(|&c| doc.get(c).is_ok_and(|e| e.attr("Method") == Some(BEARER)))
        .collect();
    match bearer.as_slice() {
        [c] => {
            if let Some(d) = doc.one(*c, SAML, "SubjectConfirmationData")? {
                f.recipient = opt(doc, d, "Recipient")?;
                f.confirmation_not_on_or_after = opt(doc, d, "NotOnOrAfter")?;
                f.in_response_to = opt(doc, d, "InResponseTo")?;
            }
        }
        _ => return Err("saml-confirmation"),
    }
    if let Some(c) = doc.one(at, SAML, "Conditions")? {
        f.not_before = opt(doc, c, "NotBefore")?;
        f.not_on_or_after = opt(doc, c, "NotOnOrAfter")?;
        for r in doc.named(c, SAML, "AudienceRestriction")? {
            for a in doc.named(r, SAML, "Audience")? {
                if f.audiences.len() >= MAX_LIST {
                    return Err("saml-field");
                }
                f.audiences.push(text_of(doc, a)?);
            }
        }
    }
    if let Some(s) = doc.one(at, SAML, "AuthnStatement")? {
        f.authn_instant = opt(doc, s, "AuthnInstant")?;
        f.session_index = opt(doc, s, "SessionIndex")?;
        if let Some(ctx) = doc.one(s, SAML, "AuthnContext")?
            && let Some(r) = doc.one(ctx, SAML, "AuthnContextClassRef")?
        {
            f.authn_context = Some(text_of(doc, r)?);
        }
    }
    for st in doc.named(at, SAML, "AttributeStatement")? {
        if doc.one(st, SAML, "EncryptedAttribute")?.is_some() {
            return Err("saml-encrypted");
        }
        for a in doc.named(st, SAML, "Attribute")? {
            if f.attributes.len() >= MAX_ATTRIBUTES {
                return Err("saml-field");
            }
            let name = opt(doc, a, "Name")?.ok_or("saml-field")?;
            let mut values = Vec::new();
            for v in doc.named(a, SAML, "AttributeValue")? {
                if values.len() >= MAX_LIST {
                    return Err("saml-field");
                }
                values.push(text_of(doc, v)?);
            }
            f.attributes.push((name, values));
        }
    }
    Ok(f)
}

/// `saml.assertion` (P4): reads an upstream IdP's `samlp:Response` or bare `saml:Assertion`
/// (a [`Context`], then the message, never deflated), verifies the assertion's own enveloped
/// signature with one of the IdP's pinned certificates and returns the assertion's facts, read
/// from that element (OP-155 m.3 (h), IDI-8). A Response signature alone never suffices.
///
/// # Errors
/// A stable refusal code.
pub(crate) fn assertion(input: &[u8]) -> Result<(Summary, Vec<u8>), &'static str> {
    let (ctx, xml) = Context::decode(input).map_err(|_| "frame-malformed")?;
    if ctx.inflate || ctx.certs.is_empty() {
        return Err("signature-no-key");
    }
    let summary = crate::parse::xml(xml)?;
    let doc = dom::read(xml)?;
    let (at, in_response) = the_assertion(&doc)?;
    let alg = dsig::enveloped(&doc, at, &ctx.certs)?.ok_or("signature-missing")?;
    let f = assertion_facts(&doc, at, in_response, alg)?;
    let out = f.encode().map_err(|_| "saml-field")?;
    Ok((summary, out))
}
