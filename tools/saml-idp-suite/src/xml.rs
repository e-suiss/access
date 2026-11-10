//! A small, bounded, non-validating XML reader: enough to inspect SAML messages and to find the
//! byte spans the request corpus rewrites. It never resolves an entity other than the five
//! predefined ones and character references; a DOCTYPE is recorded, never processed.

use std::fmt;

/// Input larger than this is refused.
pub const MAX_INPUT: usize = 4 * 1024 * 1024;
/// Element nesting deeper than this is refused.
pub const MAX_DEPTH: usize = 64;
/// More nodes than this are refused.
pub const MAX_NODES: usize = 200_000;

/// Why a document was not read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlError(pub String);

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "xml: {}", self.0)
    }
}

impl std::error::Error for XmlError {}

fn err<T>(m: &str) -> Result<T, XmlError> {
    Err(XmlError(m.to_owned()))
}

/// A child of an element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    /// An element.
    Element(Element),
    /// Character data (text or CDATA), entities decoded.
    Text(String),
    /// A comment.
    Comment,
}

/// An element with its namespace resolved and its byte span in the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Element {
    /// The qualified name as written (`samlp:Response`).
    pub name: String,
    /// The namespace URI the prefix resolves to, if any.
    pub ns: Option<String>,
    /// Attributes as written, values decoded, `xmlns` declarations included.
    pub attrs: Vec<(String, String)>,
    /// Children in document order.
    pub children: Vec<Node>,
    /// Offset of `<` of the start tag.
    pub start: usize,
    /// Offset just after the end tag (or `/>`).
    pub end: usize,
}

/// A read document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    /// The root element.
    pub root: Element,
    /// Whether a DOCTYPE declaration appeared.
    pub doctype: bool,
    /// Comments anywhere in the document.
    pub comments: usize,
}

impl Element {
    /// The local part of the name.
    #[must_use]
    pub fn local(&self) -> &str {
        self.name
            .rsplit_once(':')
            .map_or(self.name.as_str(), |(_, l)| l)
    }

    /// Whether the element has local name `local` in namespace `ns`.
    #[must_use]
    pub fn is(&self, ns: &str, local: &str) -> bool {
        self.local() == local && self.ns.as_deref() == Some(ns)
    }

    /// The prefix of the name, if any.
    #[must_use]
    pub fn prefix(&self) -> Option<&str> {
        self.name.split_once(':').map(|(p, _)| p)
    }

    /// The value of attribute `name` (unprefixed attributes only match unprefixed names).
    #[must_use]
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Child elements.
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    /// The first child element `ns`:`local`.
    #[must_use]
    pub fn child(&self, ns: &str, local: &str) -> Option<&Element> {
        self.elements().find(|e| e.is(ns, local))
    }

    /// Every child element `ns`:`local`.
    pub fn children_named<'a>(
        &'a self,
        ns: &'a str,
        local: &'a str,
    ) -> impl Iterator<Item = &'a Element> + 'a {
        self.elements().filter(move |e| e.is(ns, local))
    }

    /// The element's own text, every text child joined (comments do not split it).
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        for n in &self.children {
            if let Node::Text(t) = n {
                out.push_str(t);
            }
        }
        out
    }

    /// Whether a comment sits among the element's own children.
    #[must_use]
    pub fn has_comment_child(&self) -> bool {
        self.children.iter().any(|n| matches!(n, Node::Comment))
    }

    /// Every descendant element, depth first, the element itself first.
    #[must_use]
    pub fn descendants(&self) -> Vec<&Element> {
        let mut out = vec![self];
        let mut i = 0;
        while let Some(e) = out.get(i).copied() {
            out.extend(e.elements());
            i = i.saturating_add(1);
        }
        out
    }

    /// Whether a comment appears anywhere inside the element.
    #[must_use]
    pub fn contains_comment(&self) -> bool {
        self.descendants().iter().any(|e| e.has_comment_child())
    }
}

struct Reader<'a> {
    s: &'a str,
    b: &'a [u8],
    i: usize,
    nodes: usize,
    comments: usize,
}

/// Reads `input`.
///
/// # Errors
/// [`XmlError`] for malformed XML or a limit.
pub fn parse(input: &str) -> Result<Document, XmlError> {
    if input.len() > MAX_INPUT {
        return err("input too large");
    }
    let mut r = Reader {
        s: input,
        b: input.as_bytes(),
        i: 0,
        nodes: 0,
        comments: 0,
    };
    let mut doctype = false;
    let mut root = None;
    loop {
        r.skip_ws();
        if r.i >= r.b.len() {
            break;
        }
        if r.starts("<?") {
            r.skip_past("?>")?;
        } else if r.starts("<!--") {
            r.skip_past("-->")?;
            r.comments = r.comments.saturating_add(1);
        } else if r.starts("<!DOCTYPE") {
            if root.is_some() || doctype {
                return err("misplaced DOCTYPE");
            }
            doctype = true;
            r.skip_doctype()?;
        } else if r.starts("<") {
            if root.is_some() {
                return err("more than one root element");
            }
            let scope = vec![(
                String::from("xml"),
                String::from("http://www.w3.org/XML/1998/namespace"),
            )];
            root = Some(r.element(&scope, 0)?);
        } else {
            return err("content outside the root element");
        }
    }
    let Some(root) = root else {
        return err("no root element");
    };
    Ok(Document {
        root,
        doctype,
        comments: r.comments,
    })
}

impl Reader<'_> {
    fn starts(&self, p: &str) -> bool {
        self.b
            .get(self.i..)
            .is_some_and(|t| t.starts_with(p.as_bytes()))
    }

    fn skip_ws(&mut self) {
        while self
            .b
            .get(self.i)
            .is_some_and(|c| matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.i = self.i.saturating_add(1);
        }
    }

    fn find(&self, p: &str) -> Option<usize> {
        self.s
            .get(self.i..)?
            .find(p)
            .and_then(|k| self.i.checked_add(k))
    }

    fn skip_past(&mut self, p: &str) -> Result<(), XmlError> {
        let Some(at) = self.find(p) else {
            return err("unterminated construct");
        };
        self.i = at.saturating_add(p.len());
        Ok(())
    }

    fn skip_doctype(&mut self) -> Result<(), XmlError> {
        let mut depth = 0_usize;
        while let Some(&c) = self.b.get(self.i) {
            self.i = self.i.saturating_add(1);
            match c {
                b'[' => depth = depth.saturating_add(1),
                b']' => depth = depth.saturating_sub(1),
                b'>' if depth == 0 => return Ok(()),
                _ => {}
            }
        }
        err("unterminated DOCTYPE")
    }

    fn name(&mut self) -> Result<String, XmlError> {
        let start = self.i;
        while self.b.get(self.i).is_some_and(|&c| {
            c.is_ascii_alphanumeric() || matches!(c, b':' | b'_' | b'-' | b'.') || c >= 0x80
        }) {
            self.i = self.i.saturating_add(1);
        }
        match self.s.get(start..self.i) {
            Some(n) if !n.is_empty() => Ok(n.to_owned()),
            _ => err("expected a name"),
        }
    }

    fn count(&mut self) -> Result<(), XmlError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_NODES {
            return err("too many nodes");
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines, reason = "one branch per markup construct")]
    fn element(&mut self, outer: &[(String, String)], depth: usize) -> Result<Element, XmlError> {
        if depth >= MAX_DEPTH {
            return err("too deep");
        }
        self.count()?;
        let start = self.i;
        self.i = self.i.saturating_add(1);
        let name = self.name()?;
        let mut attrs = Vec::new();
        let empty = loop {
            self.skip_ws();
            if self.starts("/>") {
                self.i = self.i.saturating_add(2);
                break true;
            }
            if self.starts(">") {
                self.i = self.i.saturating_add(1);
                break false;
            }
            let k = self.name()?;
            self.skip_ws();
            if !self.starts("=") {
                return err("expected =");
            }
            self.i = self.i.saturating_add(1);
            self.skip_ws();
            let Some(&q) = self.b.get(self.i) else {
                return err("unterminated attribute");
            };
            if q != b'"' && q != b'\'' {
                return err("unquoted attribute");
            }
            self.i = self.i.saturating_add(1);
            let Some(end) = self.find(if q == b'"' { "\"" } else { "'" }) else {
                return err("unterminated attribute");
            };
            let raw = self.s.get(self.i..end).unwrap_or_default();
            if raw.contains('<') {
                return err("< in attribute value");
            }
            if attrs.iter().any(|(a, _): &(String, String)| *a == k) {
                return err("duplicate attribute");
            }
            attrs.push((k, decode(raw)?));
            self.i = end.saturating_add(1);
        };
        let mut scope = outer.to_vec();
        for (k, v) in &attrs {
            if k == "xmlns" {
                scope.push((String::new(), v.clone()));
            } else if let Some(p) = k.strip_prefix("xmlns:") {
                scope.push((p.to_owned(), v.clone()));
            }
        }
        let prefix = name.split_once(':').map_or("", |(p, _)| p);
        let ns = scope
            .iter()
            .rev()
            .find(|(p, _)| p == prefix)
            .map(|(_, u)| u.clone())
            .filter(|u| !u.is_empty());
        if ns.is_none() && !prefix.is_empty() {
            return err("unbound prefix");
        }
        let mut children = Vec::new();
        if !empty {
            loop {
                if self.i >= self.b.len() {
                    return err("unterminated element");
                }
                if self.starts("</") {
                    self.i = self.i.saturating_add(2);
                    let close = self.name()?;
                    if close != name {
                        return err("mismatched end tag");
                    }
                    self.skip_ws();
                    if !self.starts(">") {
                        return err("expected >");
                    }
                    self.i = self.i.saturating_add(1);
                    break;
                } else if self.starts("<!--") {
                    self.skip_past("-->")?;
                    self.comments = self.comments.saturating_add(1);
                    self.count()?;
                    children.push(Node::Comment);
                } else if self.starts("<![CDATA[") {
                    let from = self.i.saturating_add(9);
                    self.skip_past("]]>")?;
                    let to = self.i.saturating_sub(3);
                    self.count()?;
                    children.push(Node::Text(
                        self.s.get(from..to).unwrap_or_default().to_owned(),
                    ));
                } else if self.starts("<?") {
                    self.skip_past("?>")?;
                } else if self.starts("<!") {
                    return err("declaration inside an element");
                } else if self.starts("<") {
                    children.push(Node::Element(
                        self.element(&scope, depth.saturating_add(1))?,
                    ));
                } else {
                    let from = self.i;
                    let to = self.find("<").unwrap_or(self.b.len());
                    self.i = to;
                    self.count()?;
                    children.push(Node::Text(decode(
                        self.s.get(from..to).unwrap_or_default(),
                    )?));
                }
            }
        }
        Ok(Element {
            name,
            ns,
            attrs,
            children,
            start,
            end: self.i,
        })
    }
}

/// Decodes the five predefined entities and character references; any other entity is refused.
///
/// # Errors
/// [`XmlError`] for an unknown or malformed reference.
pub fn decode(raw: &str) -> Result<String, XmlError> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(rest.get(..at).unwrap_or_default());
        let tail = rest.get(at..).unwrap_or_default();
        let Some(semi) = tail.find(';') else {
            return err("unterminated reference");
        };
        let ent = tail.get(1..semi).unwrap_or_default();
        let c = match ent {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(h) = ent.strip_prefix("#x") {
                    u32::from_str_radix(h, 16).ok()
                } else if let Some(d) = ent.strip_prefix('#') {
                    d.parse().ok()
                } else {
                    return err("entity reference");
                };
                match code.and_then(char::from_u32) {
                    Some(c) => c,
                    None => return err("bad character reference"),
                }
            }
        };
        out.push(c);
        rest = tail.get(semi.saturating_add(1)..).unwrap_or_default();
    }
    out.push_str(rest);
    Ok(out)
}

/// Escapes text for element content or an attribute value.
#[must_use]
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_namespaces_text_and_spans() {
        let x = r#"<?xml version="1.0"?><a:R xmlns:a="urn:a" ID="x"><a:I>he<!-- c -->llo &amp; bye</a:I><b xmlns="urn:b"/></a:R>"#;
        let d = parse(x).unwrap();
        assert!(d.root.is("urn:a", "R"));
        assert_eq!(d.root.attr("ID"), Some("x"));
        let i = d.root.child("urn:a", "I").unwrap();
        assert_eq!(i.text(), "hello & bye");
        assert!(i.has_comment_child());
        assert_eq!(d.comments, 1);
        assert!(d.root.child("urn:b", "b").is_some());
        assert_eq!(&x[i.start..i.end], "<a:I>he<!-- c -->llo &amp; bye</a:I>");
    }

    #[test]
    fn records_a_doctype_and_refuses_entities() {
        let d = parse("<!DOCTYPE r><r/>").unwrap();
        assert!(d.doctype);
        assert!(parse("<!DOCTYPE r [<!ENTITY x \"y\">]><r>&x;</r>").is_err());
        assert!(parse("<r><a></r>").is_err());
        assert!(parse("<p:r/>").is_err());
        assert!(parse("<r/><r/>").is_err());
    }

    #[test]
    fn refuses_deep_nesting() {
        let x = format!(
            "{}{}",
            "<a>".repeat(MAX_DEPTH + 1),
            "</a>".repeat(MAX_DEPTH + 1)
        );
        assert!(parse(&x).is_err());
    }
}
