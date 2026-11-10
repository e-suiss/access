//! A small ordered tree written as block YAML 1.2: every string double-quoted with JSON escapes,
//! so no value is ever read as another type, and keys keep the order they were given in.

use std::fmt::Write as _;

/// One YAML node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Y {
    /// A mapping, in order.
    Map(Vec<(String, Y)>),
    /// A sequence.
    List(Vec<Y>),
    /// A string.
    Str(String),
    /// An integer.
    Int(u64),
    /// A boolean.
    Bool(bool),
}

/// A mapping of `pairs`.
#[must_use]
pub fn map<const N: usize>(pairs: [(&str, Y); N]) -> Y {
    Y::Map(
        pairs
            .into_iter()
            .map(|(k, v)| (String::from(k), v))
            .collect(),
    )
}

/// A string.
#[must_use]
pub fn s(v: impl Into<String>) -> Y {
    Y::Str(v.into())
}

fn quote(v: &str) -> String {
    serde_json::Value::String(String::from(v)).to_string()
}

fn key(k: &str) -> String {
    if !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        String::from(k)
    } else {
        quote(k)
    }
}

fn scalar(v: &Y) -> String {
    match v {
        Y::Map(_) => String::from("{}"),
        Y::List(_) => String::from("[]"),
        Y::Str(s) => quote(s),
        Y::Int(n) => n.to_string(),
        Y::Bool(b) => b.to_string(),
    }
}

fn nested(v: &Y) -> bool {
    match v {
        Y::Map(m) => !m.is_empty(),
        Y::List(a) => !a.is_empty(),
        _ => false,
    }
}

fn write(out: &mut String, v: &Y, indent: usize) {
    let pad = " ".repeat(indent);
    match v {
        Y::Map(m) if !m.is_empty() => {
            for (k, v) in m {
                if nested(v) {
                    let _ = writeln!(out, "{pad}{}:", key(k));
                    let inner = if matches!(v, Y::List(_)) {
                        indent
                    } else {
                        indent.saturating_add(2)
                    };
                    write(out, v, inner);
                } else {
                    let _ = writeln!(out, "{pad}{}: {}", key(k), scalar(v));
                }
            }
        }
        Y::List(a) if !a.is_empty() => {
            for item in a {
                if nested(item) {
                    let mut inner = String::new();
                    write(&mut inner, item, indent.saturating_add(2));
                    let body = inner.get(indent.saturating_add(2)..).unwrap_or_default();
                    let _ = write!(out, "{pad}- {body}");
                } else {
                    let _ = writeln!(out, "{pad}- {}", scalar(item));
                }
            }
        }
        other => {
            let _ = writeln!(out, "{pad}{}", scalar(other));
        }
    }
}

/// `v` as a YAML document.
#[must_use]
pub fn to_yaml(v: &Y) -> String {
    let mut out = String::new();
    write(&mut out, v, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // IDP-30 (2)
    #[test]
    fn strings_stay_strings_and_nesting_follows_the_value() {
        let v = map([
            ("a", map([("b", s("true")), ("@type", s("x\"y"))])),
            (
                "list",
                Y::List(vec![
                    map([("k", Y::Int(1)), ("m", Y::List(vec![s("s")]))]),
                    s("plain"),
                    Y::List(vec![]),
                ]),
            ),
            ("empty", map([])),
            ("on", Y::Bool(false)),
        ]);
        assert_eq!(
            to_yaml(&v),
            "a:\n  b: \"true\"\n  \"@type\": \"x\\\"y\"\nlist:\n- k: 1\n  m:\n  - \"s\"\n- \"plain\"\n- []\nempty: {}\non: false\n"
        );
    }
}
