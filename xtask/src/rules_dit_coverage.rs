//! `dit-coverage` (CR-39, OP-159 m.3 (s)): every constant-time comparison in the crypto crates runs under a DIT guard.
//!
//! In `crates/crypto/src` and `crates/suiss-crypto/src`, every function whose body calls a
//! constant-time primitive (`.ct_eq(`, `hmac::verify(`, `constant_time::`) holds a
//! `DitGuard::new()` in the same body. `Secret::ct_eq_bytes` sets the guard itself, so its
//! callers are covered. Test modules are not checked.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{read, rel, walk};

const RULE: &str = "dit-coverage";

const ROOTS: [&str; 2] = ["crates/crypto/src", "crates/suiss-crypto/src"];

/// Calls of a constant-time primitive whose timing DIT protects on ARM64.
const PRIMITIVES: [&str; 3] = [".ct_eq(", "hmac::verify(", "constant_time::"];

const GUARD: &str = "DitGuard::new()";

/// The functions of `src` outside `#[cfg(test)]` modules: name, first line, body.
pub(crate) fn functions(src: &str) -> Vec<(String, usize, String)> {
    let code = without_tests(src);
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(found) = code.get(from..).and_then(|rest| rest.find("fn ")) {
        let at = from.saturating_add(found);
        from = at.saturating_add(3);
        let starts_word = at == 0
            || code
                .get(..at)
                .and_then(|b| b.chars().next_back())
                .is_some_and(|c| !c.is_alphanumeric() && c != '_');
        if !starts_word {
            continue;
        }
        let name: String = code
            .get(at.saturating_add(3)..)
            .unwrap_or_default()
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let Some(open) = code.get(at..).and_then(|rest| {
            let semi = rest.find(';');
            let brace = rest.find('{')?;
            (semi.is_none_or(|s| brace < s)).then_some(brace)
        }) else {
            continue;
        };
        let open = at.saturating_add(open);
        let mut depth = 0usize;
        let mut end = None;
        for (i, b) in bytes.iter().enumerate().skip(open) {
            match b {
                b'{' => depth = depth.saturating_add(1),
                b'}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { continue };
        let line = code
            .get(..at)
            .unwrap_or_default()
            .matches('\n')
            .count()
            .saturating_add(1);
        out.push((
            name,
            line,
            code.get(open..=end).unwrap_or_default().to_owned(),
        ));
    }
    out
}

/// `src` with `#[cfg(test)]` modules blanked out, line numbers kept.
fn without_tests(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut skipping = false;
    let mut depth = 0usize;
    let mut armed = false;
    for line in src.lines() {
        let t = line.trim_start();
        if !skipping && t.starts_with("#[cfg(test)]") {
            armed = true;
        }
        if armed && t.starts_with("mod ") {
            skipping = true;
            armed = false;
        }
        if skipping {
            for c in line.chars() {
                match c {
                    '{' => depth = depth.saturating_add(1),
                    '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
            if depth == 0 && line.contains('}') {
                skipping = false;
            }
            out.push('\n');
            continue;
        }
        if !t.starts_with("//") {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// The unguarded functions of `src`: name and line.
pub(crate) fn unguarded(src: &str) -> Vec<(String, usize)> {
    functions(src)
        .into_iter()
        .filter(|(_, _, body)| PRIMITIVES.iter().any(|p| body.contains(p)) && !body.contains(GUARD))
        .map(|(name, line, _)| (name, line))
        .collect()
}

/// Runs `dit-coverage`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for dir in ROOTS {
        for path in walk(&root.join(dir))? {
            let p = rel(root, &path);
            if path.extension().is_none_or(|e| e != "rs")
                || p.ends_with("tests.rs")
                || p.ends_with("testing.rs")
                || p.contains("/tests/")
            {
                continue;
            }
            for (name, line) in unguarded(&read(&path)?) {
                out.push(Violation {
                    rule: RULE,
                    path: PathBuf::from(&p),
                    message: format!(
                        "line {line}: `fn {name}` compares in constant time without `DitGuard::new()` (CR-39 m.6)"
                    ),
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR-39 m.6, OP-159 m.3 (s)
    #[test]
    fn a_constant_time_comparison_outside_a_dit_guard_is_found() {
        let src = "\
fn guarded(a: &[u8], b: &[u8]) -> bool {
    let _dit = DitGuard::new();
    bool::from(a.ct_eq(b))
}

pub fn bare(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

fn mac(k: &Key) -> bool {
    hmac::verify(k, b\"x\", b\"y\").is_ok()
}

fn secret_only(s: &Secret<[u8; 32]>, c: &[u8]) -> bool {
    s.ct_eq_bytes(c)
}

trait T { fn decl(&self); }

#[cfg(test)]
mod tests {
    fn in_test(a: &[u8]) -> bool { bool::from(a.ct_eq(a)) }
}
";
        assert_eq!(
            unguarded(src),
            vec![(String::from("bare"), 6), (String::from("mac"), 10)]
        );
    }
}
