//! The parser limits (OP-155 m.3 (c), OP-125, CR-10), applied before and while untrusted XML and
//! DER are read. Every refusal is a stable code; nothing here panics or allocates beyond the
//! limits.

use access_edge_core::ipc::Summary;
use quick_xml::Reader;
use quick_xml::events::Event;

/// Largest XML document, after inflation.
pub(crate) const MAX_XML: usize = 1024 * 1024;

/// Deepest XML element nesting.
pub(crate) const MAX_DEPTH: u64 = 64;

/// Most XML elements in one document.
pub(crate) const MAX_ELEMENTS: u64 = 50_000;

/// Largest inflated size as a multiple of the deflated size.
pub(crate) const MAX_RATIO: usize = 100;

/// Largest DER input (CR-10 m.3).
pub(crate) const MAX_DER: usize = access_parse::der::MAX_INPUT;

/// Deepest DER nesting.
pub(crate) const MAX_DER_DEPTH: u64 = 32;

/// The entities XML predefines; no other entity is resolved.
const PREDEFINED: [&str; 5] = ["lt", "gt", "amp", "apos", "quot"];

struct Walk {
    depth: u64,
    elements: u64,
    max_depth: u64,
    root: Option<String>,
    closed: bool,
}

impl Walk {
    fn open(&mut self, name: &str) -> Result<(), &'static str> {
        if self.closed {
            return Err("xml-multiple-roots");
        }
        self.elements = self.elements.checked_add(1).ok_or("xml-elements")?;
        if self.elements > MAX_ELEMENTS {
            return Err("xml-elements");
        }
        let depth = self.depth.checked_add(1).ok_or("xml-depth")?;
        if depth > MAX_DEPTH {
            return Err("xml-depth");
        }
        if self.root.is_none() {
            let local = name.rsplit(':').next().unwrap_or(name);
            self.root = Some(String::from(local));
        }
        self.max_depth = self.max_depth.max(depth);
        Ok(())
    }

    fn inside(&self) -> Result<(), &'static str> {
        if self.depth == 0 {
            Err("xml-content-outside-root")
        } else {
            Ok(())
        }
    }
}

fn attributes(e: &quick_xml::events::BytesStart<'_>) -> Result<(), &'static str> {
    for a in e.attributes() {
        let a = a.map_err(|_| "xml-malformed")?;
        a.normalized_value(quick_xml::XmlVersion::Explicit1_0)
            .map_err(|_| "xml-entity")?;
    }
    Ok(())
}

fn reference(r: &quick_xml::events::BytesRef<'_>) -> Result<(), &'static str> {
    if r.is_char_ref() {
        return match r.resolve_char_ref() {
            Ok(Some(c)) if c != '\u{0}' => Ok(()),
            _ => Err("xml-entity"),
        };
    }
    let name: &str = r;
    if PREDEFINED.contains(&name) {
        Ok(())
    } else {
        Err("xml-entity")
    }
}

fn declaration(d: &quick_xml::events::BytesDecl<'_>) -> Result<(), &'static str> {
    if d.version().map_err(|_| "xml-malformed")? != "1.0" {
        return Err("xml-version");
    }
    match d.encoding() {
        None => Ok(()),
        Some(Ok(e)) if e.eq_ignore_ascii_case("utf-8") => Ok(()),
        Some(_) => Err("xml-encoding"),
    }
}

/// Checks an XML document: UTF-8, no `DOCTYPE`, only the five predefined entities and character
/// references, no processing instruction, one root, at most [`MAX_DEPTH`] deep and
/// [`MAX_ELEMENTS`] elements, at most [`MAX_XML`] bytes.
///
/// # Errors
/// A stable refusal code.
pub(crate) fn xml(input: &[u8]) -> Result<Summary, &'static str> {
    if input.len() > MAX_XML {
        return Err("xml-too-large");
    }
    let text = core::str::from_utf8(input).map_err(|_| "xml-encoding")?;
    let mut reader = Reader::from_str(text);
    let config = reader.config_mut();
    config.check_end_names = true;
    config.check_comments = true;
    config.allow_dangling_amp = false;
    config.allow_unmatched_ends = false;
    config.expand_empty_elements = false;
    let mut w = Walk {
        depth: 0,
        elements: 0,
        max_depth: 0,
        root: None,
        closed: false,
    };
    loop {
        match reader.read_event().map_err(|_| "xml-malformed")? {
            Event::DocType(_) => return Err("xml-doctype"),
            Event::PI(_) => return Err("xml-processing-instruction"),
            Event::Decl(d) => declaration(&d)?,
            Event::Start(e) => {
                w.open(e.name().as_ref())?;
                attributes(&e)?;
                w.depth = w.depth.checked_add(1).ok_or("xml-depth")?;
            }
            Event::Empty(e) => {
                w.open(e.name().as_ref())?;
                attributes(&e)?;
                if w.depth == 0 {
                    w.closed = true;
                }
            }
            Event::End(_) => {
                w.depth = w.depth.checked_sub(1).ok_or("xml-malformed")?;
                if w.depth == 0 {
                    w.closed = true;
                }
            }
            Event::Text(t) => {
                if w.depth == 0 && !t.bytes().all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n')) {
                    return Err("xml-content-outside-root");
                }
            }
            Event::CData(_) => w.inside()?,
            Event::GeneralRef(r) => {
                w.inside()?;
                reference(&r)?;
            }
            Event::Comment(_) => {}
            Event::Eof => break,
        }
    }
    if w.depth != 0 || !w.closed {
        return Err("xml-unclosed");
    }
    Ok(Summary {
        elements: w.elements,
        depth: w.max_depth,
        root: w.root.unwrap_or_default(),
    })
}

/// Inflates a raw DEFLATE stream (SAML HTTP-Redirect binding) within [`MAX_XML`] and a
/// compression ratio of at most [`MAX_RATIO`], then checks it as [`xml`].
///
/// # Errors
/// A stable refusal code.
pub(crate) fn inflate(input: &[u8]) -> Result<(Summary, Vec<u8>), &'static str> {
    let by_ratio = input.len().saturating_mul(MAX_RATIO);
    let limit = by_ratio.min(MAX_XML);
    let out =
        miniz_oxide::inflate::decompress_to_vec_with_limit(input, limit).map_err(|e| {
            match e.status {
                miniz_oxide::inflate::TINFLStatus::HasMoreOutput if by_ratio <= MAX_XML => {
                    "xml-ratio"
                }
                miniz_oxide::inflate::TINFLStatus::HasMoreOutput => "xml-too-large",
                _ => "deflate-malformed",
            }
        })?;
    let summary = xml(&out)?;
    Ok((summary, out))
}

fn walk(
    mut r: access_parse::der::Reader<'_>,
    depth: u64,
    elements: &mut u64,
    deepest: &mut u64,
) -> Result<(), &'static str> {
    if depth > MAX_DER_DEPTH {
        return Err("der-depth");
    }
    *deepest = (*deepest).max(depth);
    while !r.is_empty() {
        let t = r.next_tlv().map_err(|_| "der-malformed")?;
        *elements = elements.checked_add(1).ok_or("der-malformed")?;
        if t.tag & 0x20 != 0 {
            let inner = access_parse::der::Reader::new(t.value).map_err(|_| "der-malformed")?;
            walk(inner, depth.saturating_add(1), elements, deepest)?;
        }
    }
    Ok(())
}

/// Checks a DER element tree: at most [`MAX_DER`] bytes (refused before reading), definite
/// shortest lengths, single-byte tags, at most [`MAX_DER_DEPTH`] deep, nothing after the last
/// element.
///
/// # Errors
/// A stable refusal code.
pub(crate) fn der(input: &[u8]) -> Result<Summary, &'static str> {
    if input.len() > MAX_DER {
        return Err("der-too-large");
    }
    if input.is_empty() {
        return Err("der-malformed");
    }
    let r = access_parse::der::Reader::new(input).map_err(|_| "der-too-large")?;
    let (mut elements, mut deepest) = (0, 0);
    walk(r, 1, &mut elements, &mut deepest)?;
    Ok(Summary {
        elements,
        depth: deepest,
        root: String::new(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-125, OP-155 m.3 (c)
    #[test]
    fn a_doctype_is_refused_before_any_entity_is_read() {
        let doc = br#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>"#;
        assert_eq!(xml(doc), Err("xml-doctype"));
        assert_eq!(xml(b"<!DOCTYPE r><r/>"), Err("xml-doctype"));
    }

    // OP-155 m.3 (c)
    #[test]
    fn only_the_five_predefined_entities_resolve() {
        assert!(xml(b"<r a='&lt;&gt;&amp;&apos;&quot;'>&lt;&#x41;&#66;</r>").is_ok());
        assert_eq!(xml(b"<r>&nbsp;</r>"), Err("xml-entity"));
        assert_eq!(xml(b"<r a='&x;'/>"), Err("xml-entity"));
        assert_eq!(xml(b"<r>&#0;</r>"), Err("xml-entity"));
    }

    // OP-155 m.3 (c)
    #[test]
    fn depth_and_element_count_are_bounded() {
        let deep = |n: usize| {
            let mut d = "<a>".repeat(n);
            d.push_str(&"</a>".repeat(n));
            d
        };
        assert_eq!(xml(deep(64).as_bytes()).unwrap().depth, 64);
        assert_eq!(xml(deep(65).as_bytes()), Err("xml-depth"));
        let wide = |n: usize| format!("<r>{}</r>", "<e/>".repeat(n));
        assert_eq!(xml(wide(49_999).as_bytes()).unwrap().elements, 50_000);
        assert_eq!(xml(wide(50_000).as_bytes()), Err("xml-elements"));
    }

    // OP-155 m.3 (c)
    #[test]
    fn documents_are_well_formed_utf8_with_one_root() {
        let s = xml(br#"<?xml version="1.0" encoding="UTF-8"?><s:R xmlns:s="urn:x"><s:A/></s:R>"#)
            .unwrap();
        assert_eq!(s.root, "R");
        assert_eq!(xml(b"<a/><b/>"), Err("xml-multiple-roots"));
        assert_eq!(xml(b"<a>"), Err("xml-unclosed"));
        assert_eq!(xml(b"<a></b>"), Err("xml-malformed"));
        assert_eq!(xml(b"x<a/>"), Err("xml-content-outside-root"));
        assert_eq!(xml(b"<?pi x?><a/>"), Err("xml-processing-instruction"));
        assert_eq!(
            xml(br#"<?xml version="1.0" encoding="UTF-16"?><a/>"#),
            Err("xml-encoding")
        );
        assert_eq!(xml(&[0x3c, 0x61, 0xff, 0x2f, 0x3e]), Err("xml-encoding"));
        assert_eq!(xml(b""), Err("xml-unclosed"));
        let mut big = b"<a>".to_vec();
        big.resize(MAX_XML + 1, b' ');
        assert_eq!(xml(&big), Err("xml-too-large"));
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec(data, 9)
    }

    // OP-155 m.3 (c)
    #[test]
    fn inflation_is_bounded_by_size_and_ratio() {
        let doc = format!("<r>{}</r>", "<e a='1'/>".repeat(50));
        let (s, out) = inflate(&deflate(doc.as_bytes())).unwrap();
        assert_eq!(s.elements, 51);
        assert_eq!(out, doc.as_bytes());
        let bomb = format!("<r>{}</r>", " ".repeat(500_000));
        assert_eq!(inflate(&deflate(bomb.as_bytes())), Err("xml-ratio"));
        assert_eq!(inflate(b"\xff\xff\xff"), Err("deflate-malformed"));
    }

    // CR-10 m.3, OP-125
    #[test]
    fn der_is_bounded_before_it_is_read() {
        let ok = [0x30, 0x06, 0x02, 0x01, 0x05, 0x30, 0x01, 0x05];
        assert!(matches!(der(&[0x30, 0x03, 0x02, 0x01, 0x05]), Ok(s) if s.elements == 2));
        assert_eq!(der(&ok), Err("der-malformed"));
        let mut big = vec![0x04, 0x82, 0x20, 0x00];
        big.resize(MAX_DER + 1, 0);
        assert_eq!(der(&big), Err("der-too-large"));
        assert_eq!(der(&[0x30, 0x80, 0x00, 0x00]), Err("der-malformed"));
        let mut nested = Vec::new();
        for _ in 0..40 {
            let mut outer = vec![0x30, u8::try_from(nested.len()).unwrap_or(0)];
            outer.extend_from_slice(&nested);
            nested = outer;
            if nested.len() > 120 {
                break;
            }
        }
        assert_eq!(der(&nested), Err("der-depth"));
    }
}
