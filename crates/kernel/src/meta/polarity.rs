//! Structural polarity of a `policy_set` (OP-157 m.3 (b), SI-18, INV-36): a change narrows only
//! when the new content keeps every old statement byte for byte and adds forbid statements.

use alloc::vec::Vec;

use suiss_crypto::dcbor::Value;

/// The statements of a restriction source: the text between top-level `;`, each with its `;`,
/// trimmed of ASCII whitespace. A `;` inside a string literal or a `//` comment does not end a
/// statement; text after the last `;` is a statement of its own.
#[must_use]
pub fn statements(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'"' => i = skip_string(bytes, i),
            b'/' if bytes.get(i.saturating_add(1)) == Some(&b'/') => i = skip_comment(bytes, i),
            b';' => {
                i = i.saturating_add(1);
                push(source, start, i, &mut out);
                start = i;
            }
            _ => i = i.saturating_add(1),
        }
    }
    push(source, start, bytes.len(), &mut out);
    out
}

fn push<'a>(source: &'a str, start: usize, end: usize, out: &mut Vec<&'a str>) {
    if let Some(s) = source.get(start..end) {
        let s = s.trim_matches(|c: char| c.is_ascii_whitespace());
        if !s.is_empty() {
            out.push(s);
        }
    }
}

fn skip_string(bytes: &[u8], open: usize) -> usize {
    let mut i = open.saturating_add(1);
    while let Some(&b) = bytes.get(i) {
        match b {
            b'\\' => i = i.saturating_add(2),
            b'"' => return i.saturating_add(1),
            _ => i = i.saturating_add(1),
        }
    }
    bytes.len()
}

fn skip_comment(bytes: &[u8], open: usize) -> usize {
    let mut i = open;
    while let Some(&b) = bytes.get(i) {
        if b == b'\n' {
            return i.saturating_add(1);
        }
        i = i.saturating_add(1);
    }
    bytes.len()
}

fn skip_space(bytes: &[u8], mut i: usize) -> usize {
    while let Some(&b) = bytes.get(i) {
        if b.is_ascii_whitespace() {
            i = i.saturating_add(1);
        } else if b == b'/' && bytes.get(i.saturating_add(1)) == Some(&b'/') {
            i = skip_comment(bytes, i);
        } else {
            break;
        }
    }
    i
}

const fn ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Whether a statement's effect, after its annotations, is `forbid`.
#[must_use]
pub fn is_forbid(statement: &str) -> bool {
    let bytes = statement.as_bytes();
    let mut i = skip_space(bytes, 0);
    while bytes.get(i) == Some(&b'@') {
        i = i.saturating_add(1);
        while bytes.get(i).is_some_and(|b| ident_byte(*b)) {
            i = i.saturating_add(1);
        }
        i = skip_space(bytes, i);
        if bytes.get(i) == Some(&b'(') {
            i = i.saturating_add(1);
            loop {
                match bytes.get(i) {
                    None => return false,
                    Some(b')') => {
                        i = i.saturating_add(1);
                        break;
                    }
                    Some(b'"') => i = skip_string(bytes, i),
                    Some(_) => i = i.saturating_add(1),
                }
            }
        }
        i = skip_space(bytes, i);
    }
    bytes.get(i..i.saturating_add(6)) == Some(b"forbid".as_slice())
        && !bytes
            .get(i.saturating_add(6))
            .is_some_and(|b| ident_byte(*b))
}

fn text<'a>(content: &'a Value, member: &str) -> Option<&'a str> {
    match content.get(member) {
        Some(Value::Text(t)) => Some(t),
        _ => None,
    }
}

/// Whether `new` restricts at least as much as `old` by structure alone (OP-157 m.3 (b)): same
/// schema and target, every old requirement set unchanged, every old statement present byte for
/// byte as often as before (its `@require` and `@breakglass_exempt` annotations with it), and
/// every added statement a `forbid`. Anything else widens.
#[must_use]
pub fn policy_narrows(old: &Value, new: &Value) -> bool {
    if old.get("schema") != new.get("schema") || old.get("target") != new.get("target") {
        return false;
    }
    let kept = match (old.get("requirements"), new.get("requirements")) {
        (None, _) => true,
        (Some(Value::Map(o)), Some(Value::Map(n))) => o
            .iter()
            .all(|(k, v)| n.iter().any(|(nk, nv)| nk == k && nv == v)),
        _ => false,
    };
    let (Some(old), Some(new)) = (text(old, "source"), text(new, "source")) else {
        return false;
    };
    let mut added = statements(new);
    for s in statements(old) {
        match added.iter().position(|n| *n == s) {
            Some(i) => {
                added.remove(i);
            }
            None => return false,
        }
    }
    kept && added.iter().all(|s| is_forbid(s))
}

#[cfg(test)]
mod tests;
