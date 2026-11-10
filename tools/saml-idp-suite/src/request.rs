//! The `AuthnRequest` corpus: signature wrapping (XSW), comment and CDATA injection, tampering,
//! DTD and size attacks and replay, each built from a request the integrator signed for that case
//! alone. The rule every case checks: the IdP acts only on what the service provider signed.

use std::collections::hash_map::RandomState;
use std::fmt::{self, Write as _};
use std::hash::{BuildHasher, Hasher};

use crate::xml::{self, Element};
use crate::{DS, SAML, SAMLP};

/// The values the integrator signs into one `AuthnRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    /// The request `ID`.
    pub id: String,
    /// The service provider entity ID (`saml:Issuer`).
    pub issuer: String,
    /// `AssertionConsumerServiceURL`.
    pub acs: String,
    /// `Destination`, the IdP's SSO endpoint.
    pub destination: String,
}

/// Signs an `AuthnRequest` for a template: an enveloped XML signature, exclusive
/// canonicalization, the `ds:Signature` a direct child of the root after `saml:Issuer`.
pub trait Signer {
    /// The signed request XML.
    ///
    /// # Errors
    /// A message when the integrator cannot sign.
    fn sign(&mut self, t: &Template) -> Result<String, String>;
}

/// What the IdP acted on when it accepted a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    /// The request ID it answers (`InResponseTo`).
    pub id: String,
    /// The service provider it answers.
    pub issuer: String,
    /// The ACS URL it answers at, when it used one from the request.
    pub acs: Option<String>,
}

/// How the IdP handled one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Refused, with the IdP's reason.
    Refused(String),
    /// Accepted and acted on.
    Accepted(Seen),
}

/// The IdP under test, given a request XML document (the integrator picks the binding).
pub trait Target {
    /// Submits one request.
    fn submit(&mut self, xml: &str) -> Outcome;
}

/// The service provider the corpus speaks for and what the IdP is expected to enforce.
#[derive(Clone, Debug)]
pub struct Options {
    /// The registered service provider entity ID.
    pub issuer: String,
    /// Its registered ACS URL.
    pub acs: String,
    /// The IdP's SSO endpoint.
    pub destination: String,
    /// Whether the IdP requires signed requests from this service provider.
    pub signature_required: bool,
    /// The IdP refuses a second request with a used ID.
    pub replay: bool,
    /// The largest message the IdP accepts; a case exceeds it by one byte.
    pub size_limit: Option<usize>,
}

/// The attack family of a case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// The unmodified signed request.
    Baseline,
    /// XML signature wrapping.
    Wrapping,
    /// Comment or CDATA inside signed text.
    Injection,
    /// A signed value changed after signing.
    Tampering,
    /// No signature where one is required.
    Unsigned,
    /// A document type declaration.
    Dtd,
    /// A message over the size limit.
    Size,
    /// A used request ID.
    Replay,
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Baseline => "baseline",
            Self::Wrapping => "xsw",
            Self::Injection => "injection",
            Self::Tampering => "tampering",
            Self::Unsigned => "unsigned",
            Self::Dtd => "dtd",
            Self::Size => "size",
            Self::Replay => "replay",
        })
    }
}

/// What a case requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// Accepted with exactly the signed values.
    Accept,
    /// Refused.
    Refuse,
    /// Refused, or accepted with exactly the signed values.
    RefuseOrSigned,
}

/// One result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseResult {
    /// The case name.
    pub name: &'static str,
    /// Its family.
    pub class: Class,
    /// Whether the IdP did what the case requires.
    pub passed: bool,
    /// What happened.
    pub detail: String,
}

/// Why the corpus could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpusError(pub String);

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "corpus: {}", self.0)
    }
}

impl std::error::Error for CorpusError {}

/// The attacker's values.
pub const ATTACKER_ISSUER: &str = "https://attacker.invalid/metadata";
/// The attacker's ACS URL.
pub const ATTACKER_ACS: &str = "https://attacker.invalid/acs";

/// A fresh request ID (`_` and 32 hex digits); not secret, only unique.
#[must_use]
pub fn fresh_id() -> String {
    let mut out = String::from("_");
    for _ in 0..2 {
        let mut h = RandomState::new().build_hasher();
        h.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        let _ = write!(out, "{:016x}", h.finish());
    }
    out
}

struct Parts {
    xml: String,
    root: Element,
    issuer: Element,
    signature: Element,
}

fn parts(xml: String) -> Result<Parts, CorpusError> {
    let doc = xml::parse(&xml).map_err(|e| CorpusError(format!("signed request: {e}")))?;
    let root = doc.root;
    if !root.is(SAMLP, "AuthnRequest") {
        return Err(CorpusError(String::from(
            "the signed request is not an AuthnRequest",
        )));
    }
    let issuer = root
        .child(SAML, "Issuer")
        .cloned()
        .ok_or_else(|| CorpusError(String::from("the signed request has no Issuer")))?;
    let signature = root.child(DS, "Signature").cloned().ok_or_else(|| {
        CorpusError(String::from(
            "the signed request has no enveloped Signature",
        ))
    })?;
    Ok(Parts {
        xml,
        root,
        issuer,
        signature,
    })
}

fn slice(s: &str, from: usize, to: usize) -> Result<&str, CorpusError> {
    s.get(from..to)
        .ok_or_else(|| CorpusError(String::from("span outside the document")))
}

fn start_tag_end(s: &str, e: &Element) -> Result<usize, CorpusError> {
    let tail = slice(s, e.start, e.end)?;
    let k = tail
        .find('>')
        .ok_or_else(|| CorpusError(String::from("no start tag end")))?;
    e.start
        .checked_add(k)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| CorpusError(String::from("offset overflow")))
}

/// Replaces the value of `name="…"` in a start tag.
fn set_attr(tag: &str, name: &str, value: &str) -> String {
    let needle = format!(" {name}=\"");
    let Some(at) = tag.find(&needle) else {
        return tag.to_owned();
    };
    let from = at.saturating_add(needle.len());
    let rest = tag.get(from..).unwrap_or_default();
    let to = rest.find('"').map_or(tag.len(), |k| from.saturating_add(k));
    format!(
        "{}{}{}",
        tag.get(..from).unwrap_or_default(),
        xml::escape(value),
        tag.get(to..).unwrap_or_default()
    )
}

impl Parts {
    fn s(&self, from: usize, to: usize) -> Result<&str, CorpusError> {
        slice(&self.xml, from, to)
    }

    fn root_tag(&self) -> Result<&str, CorpusError> {
        self.s(self.root.start, start_tag_end(&self.xml, &self.root)?)
    }

    fn close(&self) -> String {
        format!("</{}>", self.root.name)
    }

    fn prolog(&self) -> Result<&str, CorpusError> {
        self.s(0, self.root.start)
    }

    fn epilog(&self) -> Result<&str, CorpusError> {
        self.s(self.root.end, self.xml.len())
    }

    fn whole_root(&self) -> Result<&str, CorpusError> {
        self.s(self.root.start, self.root.end)
    }

    fn root_without_signature(&self) -> Result<String, CorpusError> {
        Ok(format!(
            "{}{}",
            self.s(self.root.start, self.signature.start)?,
            self.s(self.signature.end, self.root.end)?
        ))
    }

    fn signature_text(&self) -> Result<&str, CorpusError> {
        self.s(self.signature.start, self.signature.end)
    }

    fn issuer_with(&self, value: &str) -> Result<String, CorpusError> {
        let tag_end = start_tag_end(&self.xml, &self.issuer)?;
        Ok(format!(
            "{}{}</{}>",
            self.s(self.issuer.start, tag_end)?,
            xml::escape(value),
            self.issuer.name
        ))
    }

    /// The root's children after `Issuer` and `Signature`.
    fn rest(&self) -> Result<String, CorpusError> {
        let inner_start = start_tag_end(&self.xml, &self.root)?;
        let inner_end = self
            .root
            .end
            .checked_sub(self.close().len())
            .ok_or_else(|| CorpusError(String::from("offset underflow")))?;
        let after = self.issuer.end.max(self.signature.end);
        let mut out = String::new();
        if self.signature.end < self.issuer.start {
            out.push_str(self.s(inner_start, self.signature.start)?);
        }
        out.push_str(self.s(after.min(inner_end), inner_end)?);
        Ok(out)
    }

    fn evil_tag(&self, id: &str) -> Result<String, CorpusError> {
        let t = set_attr(self.root_tag()?, "ID", id);
        Ok(set_attr(&t, "AssertionConsumerServiceURL", ATTACKER_ACS))
    }

    fn ext(&self, inner: &str) -> String {
        let p = self
            .root
            .prefix()
            .map_or(String::new(), |p| format!("{p}:"));
        format!("<{p}Extensions>{inner}</{p}Extensions>")
    }

    fn document(&self, root: &str) -> Result<String, CorpusError> {
        Ok(format!("{}{root}{}", self.prolog()?, self.epilog()?))
    }
}

fn split_text(v: &str) -> (String, String) {
    let at = v
        .find('.')
        .or_else(|| v.char_indices().nth(v.chars().count() / 2).map(|(i, _)| i))
        .unwrap_or(0);
    (
        v.get(..at).unwrap_or_default().to_owned(),
        v.get(at..).unwrap_or_default().to_owned(),
    )
}

struct Built {
    name: &'static str,
    class: Class,
    xml: String,
    expect: Expect,
}

#[allow(clippy::too_many_lines, reason = "one block per case, in report order")]
fn build(p: &Parts, t: &Template, opts: &Options) -> Result<Vec<Built>, CorpusError> {
    let evil = fresh_id();
    let mut out = Vec::new();
    let mut add = |name, class, xml, expect| {
        out.push(Built {
            name,
            class,
            xml,
            expect,
        });
    };
    let evil_issuer = p.issuer_with(ATTACKER_ISSUER)?;
    let rest = p.rest()?;
    let close = p.close();

    add(
        "xsw-extensions-wrap",
        Class::Wrapping,
        p.document(&format!(
            "{}{evil_issuer}{}{rest}{close}",
            p.evil_tag(&evil)?,
            p.ext(p.whole_root()?)
        ))?,
        Expect::RefuseOrSigned,
    );
    add(
        "xsw-signature-object",
        Class::Wrapping,
        p.document(&format!(
            "{}{evil_issuer}{}{rest}{close}",
            p.evil_tag(&evil)?,
            p.signature_text()?.replacen(
                &format!("</{}>", p.signature.name),
                &format!(
                    "<{}Object>{}</{}Object></{}>",
                    p.signature
                        .prefix()
                        .map_or(String::new(), |x| format!("{x}:")),
                    p.root_without_signature()?,
                    p.signature
                        .prefix()
                        .map_or(String::new(), |x| format!("{x}:")),
                    p.signature.name
                ),
                1
            )
        ))?,
        Expect::RefuseOrSigned,
    );
    add(
        "xsw-duplicate-id",
        Class::Wrapping,
        p.document(&format!(
            "{}{evil_issuer}{}{rest}{close}",
            p.evil_tag(&t.id)?,
            p.ext(p.whole_root()?)
        ))?,
        Expect::RefuseOrSigned,
    );
    add(
        "xsw-signature-moved",
        Class::Wrapping,
        p.document(&format!(
            "{}{evil_issuer}{}{}{rest}{close}",
            p.evil_tag(&evil)?,
            p.signature_text()?,
            p.ext(&p.root_without_signature()?)
        ))?,
        Expect::RefuseOrSigned,
    );
    add(
        "xsw-inner-extensions",
        Class::Wrapping,
        p.document(&format!(
            "{}{}{}{close}",
            p.s(p.root.start, p.signature.end.max(p.issuer.end))?,
            p.ext(&format!("{}{evil_issuer}{close}", p.evil_tag(&evil)?)),
            p.s(
                p.signature.end.max(p.issuer.end),
                p.root.end.saturating_sub(close.len())
            )?,
        ))?,
        Expect::RefuseOrSigned,
    );

    let (head, tail) = split_text(&t.issuer);
    let tag_end = start_tag_end(&p.xml, &p.issuer)?;
    let issuer_tag = p.s(p.issuer.start, tag_end)?;
    for (name, injected) in [
        (
            "comment-in-issuer",
            format!(
                "{issuer_tag}{}<!---->{}</{}>",
                xml::escape(&head),
                xml::escape(&tail),
                p.issuer.name
            ),
        ),
        (
            "cdata-in-issuer",
            format!(
                "{issuer_tag}{}<![CDATA[{tail}]]></{}>",
                xml::escape(&head),
                p.issuer.name
            ),
        ),
    ] {
        add(
            name,
            Class::Injection,
            format!(
                "{}{injected}{}",
                p.s(0, p.issuer.start)?,
                p.s(p.issuer.end, p.xml.len())?
            ),
            Expect::RefuseOrSigned,
        );
    }

    let root_tag = p.root_tag()?;
    add(
        "tamper-acs",
        Class::Tampering,
        p.xml.replacen(
            root_tag,
            &set_attr(root_tag, "AssertionConsumerServiceURL", ATTACKER_ACS),
            1,
        ),
        Expect::Refuse,
    );
    add(
        "tamper-issuer",
        Class::Tampering,
        format!(
            "{}{evil_issuer}{}",
            p.s(0, p.issuer.start)?,
            p.s(p.issuer.end, p.xml.len())?
        ),
        Expect::Refuse,
    );
    if opts.signature_required {
        add(
            "unsigned",
            Class::Unsigned,
            p.document(&p.root_without_signature()?)?,
            Expect::Refuse,
        );
    }
    let bare_prolog = p.prolog()?;
    let root = p.whole_root()?;
    add(
        "doctype",
        Class::Dtd,
        format!("{bare_prolog}<!DOCTYPE {}>{root}", p.root.name),
        Expect::Refuse,
    );
    add(
        "external-entity",
        Class::Dtd,
        format!(
            "{bare_prolog}<!DOCTYPE {} [<!ENTITY e SYSTEM \"file:///etc/hostname\">]>{}",
            p.root.name,
            root.replacen(&xml::escape(&t.issuer), "&e;", 1)
        ),
        Expect::Refuse,
    );
    let mut laughs = String::from("<!ENTITY l0 \"lol\">");
    for k in 1_u32..10 {
        let prev = k.saturating_sub(1);
        let _ = write!(
            laughs,
            "<!ENTITY l{k} \"{}\">",
            format!("&l{prev};").repeat(10)
        );
    }
    add(
        "entity-expansion",
        Class::Dtd,
        format!(
            "{bare_prolog}<!DOCTYPE {} [{laughs}]>{}",
            p.root.name,
            root.replacen(&xml::escape(&t.issuer), "&l9;", 1)
        ),
        Expect::Refuse,
    );
    if let Some(limit) = opts.size_limit {
        let pad = limit.saturating_sub(p.xml.len()).saturating_add(1);
        add(
            "oversized",
            Class::Size,
            format!("{bare_prolog}<!--{}-->{root}", " ".repeat(pad)),
            Expect::Refuse,
        );
    }
    Ok(out)
}

fn judge(expect: Expect, signed: &Template, outcome: &Outcome) -> (bool, String) {
    let exact = |s: &Seen| {
        s.id == signed.id
            && s.issuer == signed.issuer
            && s.acs.as_deref().is_none_or(|a| a == signed.acs)
    };
    match (expect, outcome) {
        (Expect::Accept, Outcome::Accepted(s)) if exact(s) => (true, String::from("accepted")),
        (Expect::RefuseOrSigned, Outcome::Accepted(s)) if exact(s) => {
            (true, String::from("accepted for the signed values only"))
        }
        (Expect::Accept | Expect::RefuseOrSigned, Outcome::Accepted(s)) => (
            false,
            format!(
                "acted on id={} issuer={} acs={:?}; signed id={} issuer={} acs={}",
                s.id, s.issuer, s.acs, signed.id, signed.issuer, signed.acs
            ),
        ),
        (Expect::Accept, Outcome::Refused(r)) => (false, format!("refused: {r}")),
        (Expect::Refuse | Expect::RefuseOrSigned, Outcome::Refused(r)) => {
            (true, format!("refused: {r}"))
        }
        (Expect::Refuse, Outcome::Accepted(s)) => (
            false,
            format!("accepted id={} issuer={} acs={:?}", s.id, s.issuer, s.acs),
        ),
    }
}

/// Runs the corpus: a baseline that must be accepted, every attack built from its own freshly
/// signed request, then a replay of the baseline.
///
/// # Errors
/// [`CorpusError`] when the signer fails or its output is not a signed `AuthnRequest`.
pub fn run<T: Target, S: Signer>(
    target: &mut T,
    signer: &mut S,
    opts: &Options,
) -> Result<Vec<CaseResult>, CorpusError> {
    let template = || Template {
        id: fresh_id(),
        issuer: opts.issuer.clone(),
        acs: opts.acs.clone(),
        destination: opts.destination.clone(),
    };
    let mut results = Vec::new();
    let base = template();
    let base_xml = signer.sign(&base).map_err(CorpusError)?;
    parts(base_xml.clone())?;
    let (passed, detail) = judge(Expect::Accept, &base, &target.submit(&base_xml));
    results.push(CaseResult {
        name: "baseline",
        class: Class::Baseline,
        passed,
        detail,
    });
    let count = build(&parts(base_xml.clone())?, &base, opts)?.len();
    for k in 0..count {
        let t = template();
        let p = parts(signer.sign(&t).map_err(CorpusError)?)?;
        let Some(case) = build(&p, &t, opts)?.into_iter().nth(k) else {
            continue;
        };
        let (passed, detail) = judge(case.expect, &t, &target.submit(&case.xml));
        results.push(CaseResult {
            name: case.name,
            class: case.class,
            passed,
            detail,
        });
    }
    if opts.replay {
        let (passed, detail) = judge(Expect::Refuse, &base, &target.submit(&base_xml));
        results.push(CaseResult {
            name: "replay",
            class: Class::Replay,
            passed,
            detail,
        });
    }
    Ok(results)
}

/// The corpus around one already signed request, for IdPs driven outside Rust; every attack
/// reuses its ID, so an IdP with replay protection should see each in a fresh state.
///
/// # Errors
/// [`CorpusError`] when `signed` is not a signed `AuthnRequest`.
pub fn corpus_of(
    signed: &str,
    opts: &Options,
) -> Result<Vec<(&'static str, Class, String)>, CorpusError> {
    let p = parts(signed.to_owned())?;
    let t = Template {
        id: p.root.attr("ID").unwrap_or_default().to_owned(),
        issuer: p.issuer.text(),
        acs: p
            .root
            .attr("AssertionConsumerServiceURL")
            .unwrap_or_default()
            .to_owned(),
        destination: p.root.attr("Destination").unwrap_or_default().to_owned(),
    };
    Ok(build(&p, &t, opts)?
        .into_iter()
        .map(|b| (b.name, b.class, b.xml))
        .collect())
}
