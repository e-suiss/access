//! JSON text for answers: the Kernel parses, this writes.

use alloc::string::String;
use core::fmt::Write as _;

use access_kernel::json::Json;

/// Appends `s` as a JSON string.
pub(crate) fn text(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Appends `v`.
pub(crate) fn value(out: &mut String, v: &Json) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Json::Str(s) => text(out, s),
        Json::Array(items) => {
            out.push('[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                value(out, item);
            }
            out.push(']');
        }
        Json::Object(members) => {
            out.push('{');
            for (n, (k, item)) in members.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                text(out, k);
                out.push(':');
                value(out, item);
            }
            out.push('}');
        }
    }
}

/// `v` as text.
pub(crate) fn render(v: &Json) -> String {
    let mut out = String::new();
    value(&mut out, v);
    out
}
