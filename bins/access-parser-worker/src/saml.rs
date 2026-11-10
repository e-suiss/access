//! The SAML requests an identity provider reads (SAML Core §3.4.1, §3.7.1, §10.6.1): an
//! `AuthnRequest` or a `LogoutRequest`, alone or in the SOAP body of an ECP exchange. The
//! message is read into one tree, its enveloped signature is verified against the pinned
//! certificates, and its facts are read from that same element (IDI-8).

use access_edge_core::ipc::Summary;
use access_edge_core::saml::{Context, Facts, Kind, MAX_LIST, MAX_TEXT, Redirect, Signed};

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
