//! The XML Access writes (§10.6.1): a small element tree whose only serialization is its Exclusive
//! XML Canonicalization (W3C xml-exc-c14n, without comments). A document is written in canonical
//! form, so the octets digested for a signature are the octets sent, and the verifier's
//! canonicalization of any signed element reproduces them. Nothing here parses XML.

use std::collections::BTreeMap;

/// One element: a prefixed name in a namespace, unprefixed attributes, children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct El {
    /// Namespace prefix; every element Access writes has one.
    pub prefix: &'static str,
    /// Namespace URI of the prefix.
    pub ns: &'static str,
    /// Local name.
    pub local: &'static str,
    /// Unprefixed attributes.
    pub attrs: Vec<(&'static str, String)>,
    /// Children in order.
    pub children: Vec<Node>,
}

/// A child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    /// An element.
    El(El),
    /// Character data.
    Text(String),
}

impl El {
    /// `prefix:local` in `ns`, empty.
    #[must_use]
    pub const fn new(prefix: &'static str, ns: &'static str, local: &'static str) -> Self {
        Self {
            prefix,
            ns,
            local,
            attrs: Vec::new(),
            children: Vec::new(),
        }
    }

    /// With the attribute `name` = `value`.
    #[must_use]
    pub fn attr(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.attrs.push((name, value.into()));
        self
    }

    /// With the attribute when `value` is present.
    #[must_use]
    pub fn attr_opt(self, name: &'static str, value: Option<impl Into<String>>) -> Self {
        match value {
            Some(v) => self.attr(name, v),
            None => self,
        }
    }

    /// With the child element `child`.
    #[must_use]
    pub fn child(mut self, child: Self) -> Self {
        self.children.push(Node::El(child));
        self
    }

    /// With every element of `children`.
    #[must_use]
    pub fn children(mut self, children: impl IntoIterator<Item = Self>) -> Self {
        self.children.extend(children.into_iter().map(Node::El));
        self
    }

    /// With character data.
    #[must_use]
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.children.push(Node::Text(text.into()));
        self
    }

    /// Inserts `child` as the child at `at` (or last).
    pub fn insert(&mut self, at: usize, child: Self) {
        let at = at.min(self.children.len());
        self.children.insert(at, Node::El(child));
    }

    /// The attribute `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The canonical form of this element as an apex.
    #[must_use]
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        write(self, &BTreeMap::new(), &mut out);
        out
    }
}

fn text(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// Escapes `s` as an attribute value of the canonical form.
pub fn attr_value(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// Escapes `s` for HTML text or a double-quoted HTML attribute value.
#[must_use]
pub fn html(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn write(e: &El, rendered: &BTreeMap<&'static str, &'static str>, out: &mut String) {
    out.push('<');
    out.push_str(e.prefix);
    out.push(':');
    out.push_str(e.local);
    let mut mine = rendered.clone();
    if rendered.get(e.prefix) != Some(&e.ns) {
        out.push_str(" xmlns:");
        out.push_str(e.prefix);
        out.push_str("=\"");
        attr_value(out, e.ns);
        out.push('"');
        mine.insert(e.prefix, e.ns);
    }
    let mut attrs: Vec<_> = e.attrs.iter().collect();
    attrs.sort_by(|a, b| a.0.cmp(b.0));
    for (n, v) in attrs {
        out.push(' ');
        out.push_str(n);
        out.push_str("=\"");
        attr_value(out, v);
        out.push('"');
    }
    out.push('>');
    for c in &e.children {
        match c {
            Node::El(k) => write(k, &mine, out),
            Node::Text(t) => text(out, t),
        }
    }
    out.push_str("</");
    out.push_str(e.prefix);
    out.push(':');
    out.push_str(e.local);
    out.push('>');
}

#[cfg(test)]
mod tests {
    use super::*;

    // §10.6.1
    #[test]
    fn a_tree_serializes_as_its_exclusive_canonical_form() {
        let e = El::new("a", "urn:a", "r")
            .attr("z", "1")
            .attr("b", "<&\"\n")
            .child(El::new("a", "urn:a", "x").text("t<&>"))
            .child(El::new("b", "urn:b", "y"));
        assert_eq!(
            e.canonical(),
            r#"<a:r xmlns:a="urn:a" b="&lt;&amp;&quot;&#xA;" z="1"><a:x>t&lt;&amp;&gt;</a:x><b:y xmlns:b="urn:b"></b:y></a:r>"#
        );
        assert_eq!(html("<a href=\"x\">'"), "&lt;a href=&quot;x&quot;&gt;&#39;");
    }
}
