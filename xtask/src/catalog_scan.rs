//! Finds rule IDs cited by Rust tests (SAI-1, SA-59 rule coverage).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::catalog::ids::{ids_in, name_cites, snake};

/// Rust source split into comments and code with comments and literals blanked out.
struct Lexed {
    /// (line, text) for every comment.
    comments: Vec<(usize, String)>,
    /// The source with comments, strings and char literals replaced by spaces.
    code: String,
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear lexer loop; splitting it scatters the state"
)]
fn lex(src: &str) -> Lexed {
    let chars: Vec<char> = src.chars().collect();
    let mut code = String::with_capacity(src.len());
    let mut comments = Vec::new();
    let mut line: usize = 1;
    let mut i = 0;
    let at = |k: usize| chars.get(k).copied().unwrap_or('\0');
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    while i < chars.len() {
        let c = at(i);
        let next = at(i.saturating_add(1));
        if c == '/' && next == '/' {
            let start = i;
            while i < chars.len() && at(i) != '\n' {
                code.push(' ');
                i = i.saturating_add(1);
            }
            comments.push((
                line,
                chars.get(start..i).unwrap_or_default().iter().collect(),
            ));
            continue;
        }
        if c == '/' && next == '*' {
            let (start, start_line) = (i, line);
            let mut depth: u32 = 0;
            while i < chars.len() {
                if at(i) == '/' && at(i.saturating_add(1)) == '*' {
                    depth = depth.saturating_add(1);
                    code.push_str("  ");
                    i = i.saturating_add(2);
                } else if at(i) == '*' && at(i.saturating_add(1)) == '/' {
                    depth = depth.saturating_sub(1);
                    code.push_str("  ");
                    i = i.saturating_add(2);
                    if depth == 0 {
                        break;
                    }
                } else {
                    if at(i) == '\n' {
                        line = line.saturating_add(1);
                    }
                    code.push(blank(at(i)));
                    i = i.saturating_add(1);
                }
            }
            comments.push((
                start_line,
                chars.get(start..i).unwrap_or_default().iter().collect(),
            ));
            continue;
        }
        let prev_ident =
            i > 0 && (at(i.saturating_sub(1)).is_alphanumeric() || at(i.saturating_sub(1)) == '_');
        let raw_start = if !prev_ident && c == 'r' {
            Some(i.saturating_add(1))
        } else if !prev_ident && c == 'b' && next == 'r' {
            Some(i.saturating_add(2))
        } else {
            None
        };
        if let Some(mut j) = raw_start {
            let mut hashes = 0usize;
            while at(j) == '#' {
                hashes = hashes.saturating_add(1);
                j = j.saturating_add(1);
            }
            if at(j) == '"' {
                for k in i..=j {
                    code.push(blank(at(k)));
                }
                i = j.saturating_add(1);
                loop {
                    if i >= chars.len() {
                        break;
                    }
                    if at(i) == '"' && (1..=hashes).all(|h| at(i.saturating_add(h)) == '#') {
                        for _ in 0..=hashes {
                            code.push(' ');
                        }
                        i = i.saturating_add(hashes).saturating_add(1);
                        break;
                    }
                    if at(i) == '\n' {
                        line = line.saturating_add(1);
                    }
                    code.push(blank(at(i)));
                    i = i.saturating_add(1);
                }
                continue;
            }
        }
        if c == '"' {
            code.push(' ');
            i = i.saturating_add(1);
            while i < chars.len() && at(i) != '"' {
                if at(i) == '\\' {
                    code.push(' ');
                    i = i.saturating_add(1);
                }
                if at(i) == '\n' {
                    line = line.saturating_add(1);
                }
                code.push(blank(at(i)));
                i = i.saturating_add(1);
            }
            code.push(' ');
            i = i.saturating_add(1);
            continue;
        }
        if c == '\'' {
            let end = if next == '\\' {
                (i.saturating_add(2)..chars.len().min(i.saturating_add(12)))
                    .find(|k| at(*k) == '\'')
            } else if at(i.saturating_add(2)) == '\'' {
                Some(i.saturating_add(2))
            } else {
                None
            };
            if let Some(end) = end {
                for _ in i..=end {
                    code.push(' ');
                }
                i = end.saturating_add(1);
                continue;
            }
        }
        if c == '\n' {
            line = line.saturating_add(1);
        }
        code.push(c);
        i = i.saturating_add(1);
    }
    Lexed { comments, code }
}

/// A function in test code: name, declaration line and body line range.
#[derive(Debug)]
struct Func {
    name: String,
    decl: usize,
    body: (usize, usize),
}

fn line_of(code: &str, byte: usize) -> usize {
    code.get(..byte)
        .map_or(1, |s| s.matches('\n').count().saturating_add(1))
}

/// Byte offset of the `}` matching the `{` at `open`.
fn matching_brace(code: &str, open: usize) -> usize {
    let mut depth: i64 = 0;
    for (k, b) in code.bytes().enumerate().skip(open) {
        match b {
            b'{' => depth = depth.saturating_add(1),
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return k;
                }
            }
            _ => {}
        }
    }
    code.len()
}

fn ident_after(code: &str, from: usize) -> Option<(String, usize)> {
    let rest = code.get(from..)?;
    let trimmed = rest.trim_start();
    let skip = rest.len().saturating_sub(trimmed.len());
    let name: String = trimmed
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then(|| {
        (
            name.clone(),
            from.saturating_add(skip).saturating_add(name.len()),
        )
    })
}

/// Line ranges of `#[cfg(test)] mod x { ... }` bodies.
fn test_module_ranges(code: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = code.get(from..).and_then(|s| s.find("#[cfg(test)]")) {
        let at = from.saturating_add(pos);
        from = at.saturating_add(1);
        let after = code.get(at..).unwrap_or_default();
        let Some(mod_pos) = after.find("mod ") else {
            continue;
        };
        let Some(brace) = after.find('{') else {
            continue;
        };
        let semi = after.find(';').unwrap_or(usize::MAX);
        if mod_pos < brace && brace < semi {
            let open = at.saturating_add(brace);
            out.push((line_of(code, at), line_of(code, matching_brace(code, open))));
        }
    }
    out
}

fn functions(code: &str) -> Vec<Func> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = code.get(from..).and_then(|s| s.find("fn ")) {
        let at = from.saturating_add(pos);
        from = at.saturating_add(3);
        let boundary = at == 0
            || code
                .as_bytes()
                .get(at.saturating_sub(1))
                .is_some_and(|b| !(b.is_ascii_alphanumeric() || *b == b'_'));
        if !boundary {
            continue;
        }
        let Some((name, end)) = ident_after(code, at.saturating_add(3)) else {
            continue;
        };
        let tail = code.get(end..).unwrap_or_default();
        let (Some(brace), semi) = (tail.find('{'), tail.find(';').unwrap_or(usize::MAX)) else {
            continue;
        };
        if semi < brace {
            continue;
        }
        let open = end.saturating_add(brace);
        let close = matching_brace(code, open);
        out.push(Func {
            name,
            decl: line_of(code, at),
            body: (line_of(code, open), line_of(code, close)),
        });
    }
    out
}

/// Where a comment on `line` attaches: the function it precedes or sits in.
fn owner<'a>(line: usize, funcs: &'a [Func], code_lines: &[&str]) -> Option<&'a Func> {
    let next = funcs
        .iter()
        .filter(|f| f.decl >= line)
        .min_by_key(|f| f.decl);
    if let Some(f) = next {
        let gap_is_attributes = (line.saturating_add(1)..f.decl).all(|l| {
            let t = code_lines.get(l.saturating_sub(1)).map_or("", |s| s.trim());
            t.is_empty() || t.starts_with("#[")
        });
        if gap_is_attributes {
            return Some(f);
        }
    }
    funcs
        .iter()
        .filter(|f| f.body.0 <= line && line <= f.body.1)
        .max_by_key(|f| f.body.0)
}

/// Citations of known IDs in one Rust file: ID → locations.
pub(crate) fn scan_source(
    path: &str,
    src: &str,
    known: &BTreeSet<String>,
    whole_file_is_test: bool,
) -> BTreeMap<String, BTreeSet<String>> {
    let lexed = lex(src);
    let ranges = if whole_file_is_test {
        vec![(1, usize::MAX)]
    } else {
        test_module_ranges(&lexed.code)
    };
    let in_test = |line: usize| ranges.iter().any(|(a, b)| *a <= line && line <= *b);
    let funcs: Vec<Func> = functions(&lexed.code)
        .into_iter()
        .filter(|f| in_test(f.decl))
        .collect();
    let code_lines: Vec<&str> = lexed.code.lines().collect();
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let location =
        |f: Option<&Func>| f.map_or_else(|| path.to_owned(), |f| format!("{path}::{}", f.name));
    for (line, text) in &lexed.comments {
        if !in_test(*line) {
            continue;
        }
        let module_doc = text.starts_with("//!") || text.starts_with("/*!");
        let at = if module_doc {
            path.to_owned()
        } else {
            location(owner(*line, &funcs, &code_lines))
        };
        for token in ids_in(text) {
            if known.contains(&token.text) {
                out.entry(token.text).or_default().insert(at.clone());
            }
        }
    }
    let snakes: Vec<(String, &String)> = known.iter().map(|id| (snake(id), id)).collect();
    for f in &funcs {
        for (s, id) in &snakes {
            if name_cites(&f.name, s) {
                out.entry((*id).clone())
                    .or_default()
                    .insert(location(Some(f)));
            }
        }
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let name = entry.file_name();
        if name == "target" || name == "node_modules" || name.to_string_lossy().starts_with('.') {
            continue;
        }
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Citations of known IDs across all Rust files under `roots`.
pub(crate) fn scan(
    root: &Path,
    roots: &[String],
    known: &BTreeSet<String>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut files = Vec::new();
    for r in roots {
        walk(&root.join(r), &mut files);
    }
    files.sort();
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for file in files {
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        let rel = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let whole = rel.split('/').any(|c| c == "tests") || rel.ends_with("/tests.rs");
        for (id, locs) in scan_source(&rel, &src, known, whole) {
            out.entry(id).or_default().extend(locs);
        }
    }
    out
}

/// Whether a catalog test link (`path` or `path::function`) resolves.
pub(crate) fn link_exists(root: &Path, link: &str) -> bool {
    let (path, func) = link
        .split_once("::")
        .map_or((link, None), |(p, f)| (p, Some(f)));
    let Ok(src) = std::fs::read_to_string(root.join(path)) else {
        return false;
    };
    func.is_none_or(|f| functions(&lex(&src).code).iter().any(|x| x.name == f))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| (*s).to_owned()).collect()
    }

    const SRC: &str = r##"
//! Module docs mention INV-1 outside test code.
fn helper() { let _ = "INV-2 in a string"; let c = '{'; }

#[cfg(test)]
mod tests {
    // SA-26: a secret has no formatting.
    static_assertions::assert_not_impl_any!(u8: Drop);

    // SA-21 / R-3: a panicking handler yields 500.
    #[test]
    fn panic_becomes_500() {
        let s = r#"TI-9 in a raw string { "#;
    }

    #[test]
    fn ti_9_unknown_key_is_rejected() {
        // TH-1: also inside the body.
    }
}
"##;

    #[test]
    fn comments_in_test_modules_link_to_their_function() {
        let found = scan_source(
            "a.rs",
            SRC,
            &known(&["SA-21", "R-3", "TH-1", "SA-26"]),
            false,
        );
        assert_eq!(
            found.get("SA-21").unwrap().iter().next().unwrap(),
            "a.rs::panic_becomes_500"
        );
        assert_eq!(
            found.get("TH-1").unwrap().iter().next().unwrap(),
            "a.rs::ti_9_unknown_key_is_rejected"
        );
        assert_eq!(found.get("SA-26").unwrap().iter().next().unwrap(), "a.rs");
    }

    #[test]
    fn strings_and_non_test_code_are_not_citations() {
        let found = scan_source("a.rs", SRC, &known(&["INV-1", "INV-2"]), false);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn test_function_names_cite_ids() {
        let found = scan_source("a.rs", SRC, &known(&["TI-9"]), false);
        assert_eq!(
            found.get("TI-9").unwrap().iter().collect::<Vec<_>>(),
            ["a.rs::ti_9_unknown_key_is_rejected"]
        );
    }

    #[test]
    fn integration_test_files_are_test_code_throughout() {
        let src = "//! CR-35 canary.\n#[test]\nfn password_never_logged() {}\n";
        let found = scan_source("t/tests/x.rs", src, &known(&["CR-35"]), true);
        assert!(found.contains_key("CR-35"));
    }
}
