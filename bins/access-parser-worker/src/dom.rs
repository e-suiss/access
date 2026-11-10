//! One XML tree per message (IDI-8, §10.6.1): the document is read once, under the parser limits,
//! into an arena whose element indexes are the identities the signature check and the fact
//! extraction share. Namespaces are resolved while reading; an unbound prefix, a duplicate
//! attribute or a duplicate identifier refuses the whole document.

use std::collections::{BTreeMap, BTreeSet};

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use crate::parse::{MAX_DEPTH, MAX_ELEMENTS, MAX_XML};

/// The XML namespace, bound to `xml` everywhere.
pub(crate) const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Most namespace declarations in one document (§14.6 `max_declarations`).
pub(crate) const MAX_DECLARATIONS: usize = 32;

/// The attribute local names that identify an element for a same-document reference: SAML 2.0
/// `ID`, XML Signature `Id`, SAML 1.1 `AssertionID`/`ResponseID`/`RequestID`, and `xml:id`.
const ID_NAMES: [&str; 6] = ["ID", "Id", "id", "AssertionID", "ResponseID", "RequestID"];

/// One attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Attr {
    /// Prefix as written; empty for none.
    pub prefix: String,
    /// Local name.
    pub local: String,
    /// Namespace URI; empty for an unprefixed attribute.
    pub ns: String,
    /// Normalized value.
    pub value: String,
}

/// One element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Element {
    /// Prefix as written; empty for none.
    pub prefix: String,
    /// Local name.
    pub local: String,
    /// Namespace URI; empty when none is in scope.
    pub ns: String,
    /// Namespace declarations made on this element: prefix (empty for the default) to URI.
    pub decls: Vec<(String, String)>,
    /// Attributes other than namespace declarations.
    pub attrs: Vec<Attr>,
    /// Children, in document order.
    pub children: Vec<Child>,
    /// The parent element.
    pub parent: Option<usize>,
}

/// A child of an element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Child {
    /// An element, by index.
    Element(usize),
    /// Character data, unescaped and with line ends normalized.
    Text(String),
}

/// A document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Doc {
    /// Elements; the root is index 0.
    pub elements: Vec<Element>,
    /// Identifier value to its one element.
    pub ids: BTreeMap<String, usize>,
}

impl Element {
    /// The value of the unprefixed attribute `local`.
    pub(crate) fn attr(&self, local: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.ns.is_empty() && a.local == local)
            .map(|a| a.value.as_str())
    }

    /// Whether the element is `local` in namespace `ns`.
    pub(crate) fn is(&self, ns: &str, local: &str) -> bool {
        self.ns == ns && self.local == local
    }
}

impl Doc {
    /// The element at `i`.
    pub(crate) fn get(&self, i: usize) -> Result<&Element, &'static str> {
        self.elements.get(i).ok_or("xml-malformed")
    }

    /// The element children of `i`.
    pub(crate) fn kids(&self, i: usize) -> Result<Vec<usize>, &'static str> {
        Ok(self
            .get(i)?
            .children
            .iter()
            .filter_map(|c| match c {
                Child::Element(e) => Some(*e),
                Child::Text(_) => None,
            })
            .collect())
    }

    /// The element children of `i` named `ns`:`local`.
    pub(crate) fn named(
        &self,
        i: usize,
        ns: &str,
        local: &str,
    ) -> Result<Vec<usize>, &'static str> {
        let mut out = Vec::new();
        for k in self.kids(i)? {
            if self.get(k)?.is(ns, local) {
                out.push(k);
            }
        }
        Ok(out)
    }

    /// The one child of `i` named `ns`:`local`, if any; two are refused.
    pub(crate) fn one(
        &self,
        i: usize,
        ns: &str,
        local: &str,
    ) -> Result<Option<usize>, &'static str> {
        let all = self.named(i, ns, local)?;
        match all.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(*one)),
            _ => Err("saml-duplicate-element"),
        }
    }

    /// The text of `i`: its character data children; an element child is refused.
    pub(crate) fn text(&self, i: usize) -> Result<String, &'static str> {
        let mut s = String::new();
        for c in &self.get(i)?.children {
            match c {
                Child::Text(t) => s.push_str(t),
                Child::Element(_) => return Err("saml-mixed-content"),
            }
        }
        Ok(s)
    }

    /// Every element at or under `i`, in document order.
    pub(crate) fn subtree(&self, i: usize) -> Result<Vec<usize>, &'static str> {
        let mut out = Vec::new();
        let mut todo = vec![i];
        while let Some(e) = todo.pop() {
            out.push(e);
            let kids = self.kids(e)?;
            todo.extend(kids.into_iter().rev());
        }
        Ok(out)
    }
}

struct Scope {
    decls: Vec<(String, String)>,
}

fn lookup<'a>(scopes: &'a [Scope], prefix: &str) -> Option<&'a str> {
    if prefix == "xml" {
        return Some(XML_NS);
    }
    scopes.iter().rev().find_map(|s| {
        s.decls
            .iter()
            .rev()
            .find(|(p, _)| p == prefix)
            .map(|(_, u)| u.as_str())
    })
}

fn split_name(name: &str) -> Result<(&str, &str), &'static str> {
    match name.split_once(':') {
        None => Ok(("", name)),
        Some((p, l)) if !p.is_empty() && !l.is_empty() && !l.contains(':') => Ok((p, l)),
        Some(_) => Err("xml-namespace"),
    }
}

fn utf8(b: &[u8]) -> Result<&str, &'static str> {
    core::str::from_utf8(b).map_err(|_| "xml-encoding")
}

const PREDEFINED: [(&str, char); 5] = [
    ("lt", '<'),
    ("gt", '>'),
    ("amp", '&'),
    ("apos", '\''),
    ("quot", '"'),
];

struct Builder {
    doc: Doc,
    scopes: Vec<Scope>,
    open: Vec<usize>,
    closed: bool,
    declarations: usize,
}

impl Builder {
    fn start(&mut self, e: &BytesStart<'_>) -> Result<usize, &'static str> {
        if self.closed {
            return Err("xml-multiple-roots");
        }
        if self.doc.elements.len() >= usize::try_from(MAX_ELEMENTS).map_err(|_| "xml-elements")? {
            return Err("xml-elements");
        }
        if self.open.len() >= usize::try_from(MAX_DEPTH).map_err(|_| "xml-depth")? {
            return Err("xml-depth");
        }
        let mut decls = Vec::new();
        let mut raw = Vec::new();
        let mut seen = BTreeSet::new();
        for a in e.attributes() {
            let a = a.map_err(|_| "xml-malformed")?;
            let name: &str = a.key.as_ref();
            if !seen.insert(String::from(name)) {
                return Err("xml-malformed");
            }
            let value = a
                .normalized_value(quick_xml::XmlVersion::Explicit1_0)
                .map_err(|_| "xml-entity")?
                .into_owned();
            if name == "xmlns" {
                decls.push((String::new(), value));
            } else if let Some(p) = name.strip_prefix("xmlns:") {
                if p.is_empty() || p == "xmlns" || p == "xml" || value.is_empty() {
                    return Err("xml-namespace");
                }
                decls.push((String::from(p), value));
            } else {
                raw.push((String::from(name), value));
            }
        }
        self.declarations = self.declarations.saturating_add(decls.len());
        if self.declarations > MAX_DECLARATIONS {
            return Err("xml-declarations");
        }
        self.scopes.push(Scope {
            decls: decls.clone(),
        });
        let qname = e.name();
        let (prefix, local) = split_name(qname.as_ref())?;
        let ns = if prefix.is_empty() {
            lookup(&self.scopes, "").unwrap_or("")
        } else {
            lookup(&self.scopes, prefix).ok_or("xml-namespace")?
        };
        let mut attrs = Vec::new();
        let mut qualified = BTreeSet::new();
        for (name, value) in raw {
            let (p, l) = split_name(&name)?;
            let ans = if p.is_empty() {
                String::new()
            } else {
                String::from(lookup(&self.scopes, p).ok_or("xml-namespace")?)
            };
            if !qualified.insert((ans.clone(), String::from(l))) {
                return Err("xml-malformed");
            }
            attrs.push(Attr {
                prefix: String::from(p),
                local: String::from(l),
                ns: ans,
                value,
            });
        }
        let index = self.doc.elements.len();
        for a in &attrs {
            let id = (a.ns.is_empty() && ID_NAMES.contains(&a.local.as_str()))
                || (a.ns == XML_NS && a.local == "id");
            // IDI-8
            if id && self.doc.ids.insert(a.value.clone(), index).is_some() {
                return Err("xml-duplicate-id");
            }
        }
        let parent = self.open.last().copied();
        if let Some(p) = parent {
            self.doc
                .elements
                .get_mut(p)
                .ok_or("xml-malformed")?
                .children
                .push(Child::Element(index));
        }
        self.doc.elements.push(Element {
            prefix: String::from(prefix),
            local: String::from(local),
            ns: String::from(ns),
            decls,
            attrs,
            children: Vec::new(),
            parent,
        });
        Ok(index)
    }

    fn end(&mut self) -> Result<(), &'static str> {
        self.open.pop().ok_or("xml-malformed")?;
        self.scopes.pop().ok_or("xml-malformed")?;
        if self.open.is_empty() {
            self.closed = true;
        }
        Ok(())
    }

    fn text(&mut self, t: &str) -> Result<(), &'static str> {
        let Some(&p) = self.open.last() else {
            if t.bytes().all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n')) {
                return Ok(());
            }
            return Err("xml-content-outside-root");
        };
        let el = self.doc.elements.get_mut(p).ok_or("xml-malformed")?;
        if let Some(Child::Text(prev)) = el.children.last_mut() {
            prev.push_str(t);
        } else if !t.is_empty() {
            el.children.push(Child::Text(String::from(t)));
        }
        Ok(())
    }
}

/// Reads `input` into one tree under the parser limits: UTF-8 XML 1.0, no `DOCTYPE`, no
/// processing instruction, only the five predefined entities and character references, bound
/// namespace prefixes, unique attributes, unique identifiers.
///
/// # Errors
/// A stable refusal code.
pub(crate) fn read(input: &[u8]) -> Result<Doc, &'static str> {
    if input.len() > MAX_XML {
        return Err("xml-too-large");
    }
    let text = utf8(input)?;
    let mut reader = Reader::from_str(text);
    let config = reader.config_mut();
    config.check_end_names = true;
    config.check_comments = true;
    config.allow_dangling_amp = false;
    config.allow_unmatched_ends = false;
    config.expand_empty_elements = false;
    let mut b = Builder {
        doc: Doc {
            elements: Vec::new(),
            ids: BTreeMap::new(),
        },
        scopes: Vec::new(),
        open: Vec::new(),
        closed: false,
        declarations: 0,
    };
    loop {
        match reader.read_event().map_err(|_| "xml-malformed")? {
            Event::DocType(_) => return Err("xml-doctype"),
            Event::PI(_) => return Err("xml-processing-instruction"),
            Event::Decl(d) => {
                if !b.doc.elements.is_empty() {
                    return Err("xml-malformed");
                }
                if d.version().map_err(|_| "xml-malformed")? != "1.0" {
                    return Err("xml-version");
                }
                match d.encoding() {
                    None => {}
                    Some(Ok(e)) if e.eq_ignore_ascii_case("utf-8") => {}
                    Some(_) => return Err("xml-encoding"),
                }
            }
            Event::Start(e) => {
                let i = b.start(&e)?;
                b.open.push(i);
            }
            Event::Empty(e) => {
                let i = b.start(&e)?;
                b.open.push(i);
                b.end()?;
            }
            Event::End(_) => b.end()?,
            Event::Text(t) => b.text(&t.xml10_content())?,
            Event::CData(c) => {
                if b.open.is_empty() {
                    return Err("xml-content-outside-root");
                }
                b.text(&c.xml10_content())?;
            }
            Event::GeneralRef(r) => {
                if b.open.is_empty() {
                    return Err("xml-content-outside-root");
                }
                let c = if r.is_char_ref() {
                    match r.resolve_char_ref() {
                        Ok(Some(c)) if c != '\u{0}' => c,
                        _ => return Err("xml-entity"),
                    }
                } else {
                    let name: &str = &r;
                    PREDEFINED
                        .iter()
                        .find(|(n, _)| *n == name)
                        .map(|(_, c)| *c)
                        .ok_or("xml-entity")?
                };
                let mut buf = [0_u8; 4];
                b.text(c.encode_utf8(&mut buf))?;
            }
            Event::Comment(_) => {}
            Event::Eof => break,
        }
    }
    if !b.closed || !b.open.is_empty() {
        return Err("xml-unclosed");
    }
    Ok(b.doc)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    // IDI-8
    #[test]
    fn idi_8_a_duplicate_identifier_refuses_the_document() {
        assert_eq!(
            read(br#"<r ID="a"><x ID="a"/></r>"#),
            Err("xml-duplicate-id")
        );
        assert_eq!(
            read(br#"<r ID="a"><x AssertionID="a"/></r>"#),
            Err("xml-duplicate-id")
        );
        assert_eq!(
            read(br#"<r xml:id="a"><x Id="a"/></r>"#),
            Err("xml-duplicate-id")
        );
        assert!(read(br#"<r ID="a"><x ID="b"/></r>"#).is_ok());
    }

    // §10.6.1
    #[test]
    fn namespaces_resolve_and_unbound_prefixes_refuse() {
        let d = read(br#"<p:r xmlns:p="urn:p" xmlns="urn:d"><c p:a="1" b="2">t&amp;x</c></p:r>"#)
            .unwrap();
        assert_eq!(d.elements[0].ns, "urn:p");
        assert_eq!(d.elements[1].ns, "urn:d");
        assert_eq!(d.elements[1].attrs[0].ns, "urn:p");
        assert_eq!(d.elements[1].attrs[1].ns, "");
        assert_eq!(d.text(1).unwrap(), "t&x");
        assert_eq!(read(b"<q:r/>"), Err("xml-namespace"));
        assert_eq!(read(br#"<r xmlns:p=""/>"#), Err("xml-namespace"));
        assert_eq!(
            read(br#"<r xmlns:p="urn:p" xmlns:q="urn:p" p:a="1" q:a="2"/>"#),
            Err("xml-malformed")
        );
        assert_eq!(read(br#"<r a="1" a="2"/>"#), Err("xml-malformed"));
    }

    // §14.6, OP-155 m.3 (c)
    #[test]
    fn namespace_declarations_are_bounded() {
        let decls = |n: usize| {
            let mut doc = String::from("<r");
            for i in 0..n {
                let _ =
                    std::fmt::Write::write_fmt(&mut doc, format_args!(" xmlns:p{i}=\"urn:{i}\""));
            }
            doc.push_str("/>");
            doc
        };
        assert!(read(decls(32).as_bytes()).is_ok());
        assert_eq!(read(decls(33).as_bytes()), Err("xml-declarations"));
    }

    // RUSTSEC-2024-0437, OP-155 m.3 (c)
    #[test]
    fn rustsec_2024_0437_deep_nesting_is_refused_without_recursion() {
        let mut d = "<a>".repeat(100_000);
        d.push_str(&"</a>".repeat(100_000));
        assert_eq!(read(d.as_bytes()), Err("xml-depth"));
        let mut ok = "<a>".repeat(64);
        ok.push_str(&"</a>".repeat(64));
        assert!(read(ok.as_bytes()).is_ok());
    }

    // §10.6.1
    #[test]
    fn text_is_normalized_and_comments_dropped() {
        let d = read(b"<r>a\r\nb<!--c-->c&#x41;<![CDATA[<x>]]></r>").unwrap();
        assert_eq!(d.text(0).unwrap(), "a\nbcA<x>");
        assert_eq!(read(b"<!DOCTYPE r><r/>"), Err("xml-doctype"));
        assert_eq!(read(b"<r>&ext;</r>"), Err("xml-entity"));
    }
}
