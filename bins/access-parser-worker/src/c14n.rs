//! Exclusive XML Canonicalization 1.0 without comments (W3C REC xml-exc-c14n-20020718), over the
//! one tree the message was read into: the subtree of an apex element, optionally without one
//! descendant (the enveloped signature), with an `InclusiveNamespaces PrefixList`. Recursion is
//! bounded by the parser's depth limit.

use std::collections::BTreeMap;

use crate::dom::{Child, Doc, Element, XML_NS};

/// `InclusiveNamespaces PrefixList` token for the default namespace.
pub(crate) const DEFAULT_TOKEN: &str = "#default";

fn in_scope(doc: &Doc, mut at: Option<usize>) -> Result<BTreeMap<String, String>, &'static str> {
    let mut chain = Vec::new();
    while let Some(i) = at {
        let e = doc.get(i)?;
        chain.push(e);
        at = e.parent;
    }
    let mut map = BTreeMap::new();
    for e in chain.into_iter().rev() {
        for (p, u) in &e.decls {
            map.insert(p.clone(), u.clone());
        }
    }
    Ok(map)
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

fn attr_value(out: &mut String, s: &str) {
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

struct C14n<'a> {
    doc: &'a Doc,
    without: Option<usize>,
    inclusive: &'a [String],
    out: String,
}

impl C14n<'_> {
    fn qname(e: &Element) -> String {
        if e.prefix.is_empty() {
            e.local.clone()
        } else {
            format!("{}:{}", e.prefix, e.local)
        }
    }

    fn element(
        &mut self,
        i: usize,
        scope: &BTreeMap<String, String>,
        rendered: &BTreeMap<String, String>,
    ) -> Result<(), &'static str> {
        let e = self.doc.get(i)?;
        let mut scope = scope.clone();
        for (p, u) in &e.decls {
            scope.insert(p.clone(), u.clone());
        }
        let mut used: Vec<String> = vec![e.prefix.clone()];
        for a in &e.attrs {
            if !a.prefix.is_empty() {
                used.push(a.prefix.clone());
            }
        }
        for token in self.inclusive {
            let p = if token == DEFAULT_TOKEN {
                String::new()
            } else {
                token.clone()
            };
            if p.is_empty() || scope.contains_key(&p) {
                used.push(p);
            }
        }
        used.sort();
        used.dedup();
        let mut mine = rendered.clone();
        let mut decls = Vec::new();
        for p in used {
            if p == "xml" {
                continue;
            }
            let v = scope.get(&p).cloned().unwrap_or_default();
            let before = rendered.get(&p);
            let render = if p.is_empty() {
                match before {
                    Some(b) => *b != v,
                    None => !v.is_empty(),
                }
            } else {
                if v.is_empty() {
                    return Err("xml-namespace");
                }
                before != Some(&v)
            };
            if render {
                mine.insert(p.clone(), v.clone());
                decls.push((p, v));
            }
        }
        self.out.push('<');
        self.out.push_str(&Self::qname(e));
        for (p, v) in &decls {
            if p.is_empty() {
                self.out.push_str(" xmlns=\"");
            } else {
                self.out.push_str(" xmlns:");
                self.out.push_str(p);
                self.out.push_str("=\"");
            }
            attr_value(&mut self.out, v);
            self.out.push('"');
        }
        let mut attrs: Vec<_> = e.attrs.iter().collect();
        attrs.sort_by(|a, b| (&a.ns, &a.local).cmp(&(&b.ns, &b.local)));
        for a in attrs {
            self.out.push(' ');
            if !a.prefix.is_empty() {
                self.out.push_str(&a.prefix);
                self.out.push(':');
            }
            self.out.push_str(&a.local);
            self.out.push_str("=\"");
            attr_value(&mut self.out, &a.value);
            self.out.push('"');
        }
        self.out.push('>');
        for c in &e.children {
            match c {
                Child::Text(t) => text(&mut self.out, t),
                Child::Element(k) if Some(*k) == self.without => {}
                Child::Element(k) => self.element(*k, &scope, &mine)?,
            }
        }
        self.out.push_str("</");
        self.out.push_str(&Self::qname(e));
        self.out.push('>');
        Ok(())
    }
}

/// The exclusive canonical form of the subtree at `apex`, without the subtree at `without`,
/// rendering the namespaces of `inclusive` as inclusive canonicalization would.
///
/// # Errors
/// A stable refusal code.
pub(crate) fn canonical(
    doc: &Doc,
    apex: usize,
    without: Option<usize>,
    inclusive: &[String],
) -> Result<String, &'static str> {
    let parent = doc.get(apex)?.parent;
    let mut scope = in_scope(doc, parent)?;
    scope.insert(String::from("xml"), String::from(XML_NS));
    let mut c = C14n {
        doc,
        without,
        inclusive,
        out: String::new(),
    };
    c.element(apex, &scope, &BTreeMap::new())?;
    Ok(c.out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use crate::dom::read;

    fn c(xml: &str, apex: usize) -> String {
        canonical(&read(xml.as_bytes()).unwrap(), apex, None, &[]).unwrap()
    }

    // §10.6.1
    #[test]
    fn exclusive_canonical_form_of_a_subtree() {
        let doc = r#"<a:r xmlns:a="urn:a" xmlns:b="urn:b" xmlns="urn:d"><a:x z="1" b:y="2" a="3"/><c>t</c></a:r>"#;
        assert_eq!(
            c(doc, 1),
            r#"<a:x xmlns:a="urn:a" xmlns:b="urn:b" a="3" z="1" b:y="2"></a:x>"#
        );
        assert_eq!(c(doc, 2), r#"<c xmlns="urn:d">t</c>"#);
        assert_eq!(
            c(doc, 0),
            r#"<a:r xmlns:a="urn:a"><a:x xmlns:b="urn:b" a="3" z="1" b:y="2"></a:x><c xmlns="urn:d">t</c></a:r>"#
        );
    }

    // §3
    #[test]
    fn text_and_attributes_are_escaped() {
        let doc = "<r a=\"&lt;&amp;&quot;&#9;&#10;&#13;\">&lt;&amp;&gt;&#13;</r>";
        assert_eq!(
            c(doc, 0),
            "<r a=\"&lt;&amp;&quot;&#x9;&#xA;&#xD;\">&lt;&amp;&gt;&#xD;</r>"
        );
    }

    #[test]
    fn an_undeclared_default_namespace_is_rendered_empty() {
        let doc = r#"<r xmlns="urn:d"><x xmlns=""><y/></x></r>"#;
        assert_eq!(c(doc, 0), r#"<r xmlns="urn:d"><x xmlns=""><y></y></x></r>"#);
        assert_eq!(c(doc, 1), r"<x><y></y></x>");
    }

    #[test]
    fn inclusive_prefixes_are_rendered_on_the_apex() {
        let doc = read(br#"<r xmlns:xs="urn:xs" xmlns:p="urn:p"><p:x>v</p:x></r>"#).unwrap();
        assert_eq!(
            canonical(&doc, 1, None, &[String::from("xs")]).unwrap(),
            r#"<p:x xmlns:p="urn:p" xmlns:xs="urn:xs">v</p:x>"#
        );
    }

    // CVE-2017-11427, CVE-2017-11428
    #[test]
    fn comments_are_not_part_of_the_canonical_form() {
        assert_eq!(c("<r>a@x.test<!---->.evil</r>", 0), "<r>a@x.test.evil</r>");
    }
}
