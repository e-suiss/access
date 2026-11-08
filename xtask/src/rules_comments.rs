//! OP-99: comments in Rust code are `// SAFETY:` notes (with their continuation lines), doc
//! comments and bare spec-ID lines such as `// INV-2, OP-150 m.3 (h)`.

use std::collections::BTreeSet;
use std::path::Path;

use crate::Violation;
use crate::rules::files::{read, rel, walk};
use crate::rules::lex::{Lexed, lex};

const RULE: &str = "comment-ids";

/// Files whose narrative comments are still being reduced, one path per line (OP-99).
const PENDING: &str = "xtask/comment-pending.txt";

/// Words a bare spec-ID line may carry between its IDs.
const WORDS: &[&str] = &[
    "item", "rule", "test", "step", "to", "and", "Ek", "B", "RFC", "madde", "m", "k", "case",
    "row", "rows", "vector", "vectors",
];

const BANNED: &[&str] = &["TODO", "FIXME", "NOTE", "XXX", "HACK"];

fn all_ascii(t: &str, f: impl Fn(char) -> bool) -> bool {
    !t.is_empty() && t.chars().all(f)
}

fn token_ok(t: &str, paren: bool) -> bool {
    if t.is_empty() {
        return true;
    }
    if BANNED.contains(&t) {
        return false;
    }
    let digit = t.chars().any(|c| c.is_ascii_digit());
    if digit && t.contains(['–', '…']) {
        return t
            .split(['–', '…'])
            .filter(|p| !p.is_empty())
            .all(|p| token_ok(p, paren));
    }
    if digit {
        let mut chars = t.chars();
        let first = chars.next().unwrap_or(' ');
        let rest: String = chars.collect();
        if first.is_ascii_lowercase() && rest.starts_with('.') {
            return all_ascii(rest.get(1..).unwrap_or_default(), |c| {
                c.is_ascii_digit() || c.is_ascii_lowercase()
            });
        }
        if first.is_ascii_digit() {
            return all_ascii(t, |c| c.is_ascii_digit() || c.is_ascii_lowercase());
        }
        if first == '§' || first.is_ascii_uppercase() {
            return t
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "§.-_/+".contains(c));
        }
        return false;
    }
    if WORDS.contains(&t) {
        return true;
    }
    if paren && all_ascii(t, |c| c.is_ascii_lowercase()) && t.len() <= 4 {
        return true;
    }
    let mut parts = t.split('-');
    let head = parts.next().unwrap_or_default();
    head.len() >= 2
        && head.len() <= 6
        && head.starts_with(|c: char| c.is_ascii_uppercase())
        && all_ascii(head, |c| c.is_ascii_uppercase() || c.is_ascii_digit())
        && parts.all(|p| all_ascii(p, |c| c.is_ascii_uppercase() || c.is_ascii_digit()))
}

/// True when `body` (the comment text after `//`) lists spec IDs and nothing else.
pub(crate) fn bare_ids(body: &str) -> bool {
    let mut any_id = false;
    let mut any = false;
    for raw in body.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        if raw.is_empty() {
            continue;
        }
        any = true;
        let paren = raw.starts_with('(') || raw.ends_with(')');
        let t = raw.trim_matches(|c| c == '(' || c == ')');
        if !token_ok(t, paren) {
            return false;
        }
        any_id |= t.chars().any(|c| c.is_ascii_digit())
            && t.starts_with(|c: char| c == '§' || c.is_ascii_uppercase());
    }
    any && any_id
}

/// The line numbers of `src`'s comments that break OP-99.
pub(crate) fn narrative_lines(src: &str) -> Vec<usize> {
    let Lexed { code, comments, .. } = lex(src);
    let code_lines: Vec<&str> = code.lines().collect();
    let own_line = |line: usize| {
        code_lines
            .get(line.saturating_sub(1))
            .is_none_or(|l| l.trim().is_empty())
    };
    let mut out = Vec::new();
    let mut safety: Option<usize> = None;
    for c in comments {
        let text = c.text.as_str();
        if text.starts_with("///") || text.starts_with("//!") {
            safety = None;
            continue;
        }
        if text.starts_with("/*") {
            safety = None;
            if !(text.starts_with("/**") || text.starts_with("/*!")) {
                out.push(c.line);
            }
            continue;
        }
        let body = text.get(2..).unwrap_or_default().trim();
        if body.starts_with("SAFETY:") {
            safety = Some(c.line);
            continue;
        }
        if safety.is_some_and(|s| s.saturating_add(1) == c.line) && own_line(c.line) {
            safety = Some(c.line);
            continue;
        }
        safety = None;
        if !bare_ids(body) {
            out.push(c.line);
        }
    }
    out
}

fn pending(root: &Path) -> Result<BTreeSet<String>, String> {
    let path = root.join(PENDING);
    if !path.is_file() {
        return Ok(BTreeSet::new());
    }
    Ok(read(&path)?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let skip = pending(root)?;
    let mut out = Vec::new();
    for path in walk(root)? {
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let rel_path = rel(root, &path);
        if skip.contains(&rel_path) {
            continue;
        }
        for line in narrative_lines(&read(&path)?) {
            out.push(Violation {
                rule: RULE,
                path: format!("{rel_path}:{line}").into(),
                message: "comment is neither a SAFETY note, a doc comment nor a bare spec-ID line \
                          (OP-99)"
                    .to_owned(),
            });
        }
    }
    for p in &skip {
        if !root.join(p).is_file() {
            out.push(Violation {
                rule: RULE,
                path: PENDING.into(),
                message: format!("{p} is not a file; remove it from the list (OP-99)"),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-99
    #[test]
    fn bare_spec_id_lines_pass_and_narrative_does_not() {
        for ok in [
            "INV-2",
            "OP-150 m.3 (h), TN-110",
            "§9.9.4 k.2, L2-JOS-1 to L2-JOS-4",
            "CR-10, OP-106 m.1–m.3, G60, SAI-41",
            "L0-SIG-30…L0-SIG-42, CR-56; OP-122 m.7",
            "TN-110, OP-151 m.19 (a), (d), Ek B 3088",
            "RFC 9052 §2",
            "V4 (CR-51.2)",
        ] {
            assert!(bare_ids(ok), "{ok}");
        }
        for bad in [
            "",
            "the stored head moved",
            "OP-41: CEF escaping keeps a value from forging a field",
            "TODO OP-3",
            "PD",
            "count = 1",
        ] {
            assert!(!bare_ids(bad), "{bad}");
        }
    }

    // OP-99
    #[test]
    fn safety_notes_continue_and_strings_are_not_comments() {
        let src = "fn f() {\n    // SAFETY: the pointer is valid\n    // for the whole call\n    let s = \"// not a comment\";\n    // OP-64\n    let t = 1; // trailing words\n    // a narrative line\n}\n";
        assert_eq!(narrative_lines(src), vec![6, 7]);
        let docs = "//! Module text.\n/// Item text.\nfn g() {}\n";
        assert_eq!(narrative_lines(docs), Vec::<usize>::new());
    }
}
