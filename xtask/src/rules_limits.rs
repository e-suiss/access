//! Resource and time rules: bounded regex compilation (SA-32, §14.6), no
//! pre-allocation from a size read off the wire in parsers (U48, §14.6) and no
//! semantic timers in pure code (TI-10, T15, §6.7).

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{Lexed, find_token, in_regions, lex, line_at, test_regions};
use crate::supply_chain::metadata::{DepKind, Metadata};

fn at(rule: &'static str, path: &str, line: usize, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(format!("{path}:{line}")),
        message,
    }
}

fn rust_sources(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    Ok(walk(root)?
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .map(|p| (rel(root, &p), p))
        .filter(|(r, _)| !r.starts_with("xtask/") && !is_test_file(r))
        .collect())
}

/// Matches `path` against `pattern`; `*` is one segment, a trailing `/` matches below.
fn under(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.trim_end_matches('/').split('/').collect();
    let segs: Vec<&str> = path.split('/').collect();
    let dir = pattern.ends_with('/');
    if segs.len() < pat.len() || (!dir && segs.len() != pat.len()) {
        return false;
    }
    pat.iter().zip(&segs).all(|(p, s)| *p == "*" || p == s)
}

/// The text between the `(` (or `[`) at byte `open` and its matching closer.
fn group(code: &str, open: usize) -> Option<&str> {
    let bytes = code.as_bytes();
    let (o, c) = match bytes.get(open)? {
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        _ => return None,
    };
    let mut depth = 0_usize;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        if b == o {
            depth = depth.saturating_add(1);
        } else if b == c {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return code.get(open.saturating_add(1)..i);
            }
        }
    }
    None
}

/// Splits at top-level commas or semicolons.
fn split_top(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0_i32;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' | '{' | '<' => depth = depth.saturating_add(1),
            ')' | ']' | '}' | '>' => depth = depth.saturating_sub(1),
            _ if c == sep && depth == 0 => {
                out.push(s.get(start..i).unwrap_or_default());
                start = i.saturating_add(1);
            }
            _ => {}
        }
    }
    out.push(s.get(start..).unwrap_or_default());
    out
}

const REGEX: &str = "regex-limits";

/// SA-32: the longest pattern compiled.
pub(crate) const MAX_PATTERN: usize = 256;

/// Constructors that compile without a size limit.
const UNBOUNDED_REGEX: &[&str] = &[
    "Regex::new(",
    "RegexSet::new(",
    "Regex::from_str(",
    "parse::<Regex>",
    "regex!(",
    "lazy_regex!(",
];

const BUILDERS: &[&str] = &["RegexBuilder::new(", "RegexSetBuilder::new("];

/// Files that compile a run-time pattern after checking its length against
/// [`MAX_PATTERN`], with the reason. Each entry needs Adem's review. Empty on purpose.
pub(crate) const DYNAMIC_PATTERN_ALLOWED: &[(&str, &str)] = &[];

/// Regex compilation in one file's non-test code (SA-32, §14.6).
pub(crate) fn regex_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let Lexed { code, strings, .. } = lex(src);
    let tests = test_regions(&code);
    let mut out = Vec::new();
    for t in UNBOUNDED_REGEX {
        for p in find_token(&code, t) {
            let line = line_at(&code, p);
            if !in_regions(&tests, line) {
                out.push(at(
                    REGEX,
                    rel_path,
                    line,
                    format!("`{t}` sets no size limit; use RegexBuilder with size_limit (SA-32)"),
                ));
            }
        }
    }
    for t in BUILDERS {
        for p in find_token(&code, t) {
            let line = line_at(&code, p);
            if in_regions(&tests, line) {
                continue;
            }
            let open = p.saturating_add(t.len()).saturating_sub(1);
            let statement = code.get(p..).unwrap_or_default();
            let statement = statement.split(';').next().unwrap_or_default();
            if !statement.contains(".size_limit(") {
                out.push(at(
                    REGEX,
                    rel_path,
                    line,
                    "regex builder without `.size_limit(..)` (SA-32, §14.6)".to_owned(),
                ));
            }
            let arg = group(&code, open).unwrap_or_default().trim();
            if arg.is_empty() {
                let lit = strings.iter().find(|l| l.line >= line);
                if let Some(lit) = lit.filter(|l| l.text.chars().count() > MAX_PATTERN) {
                    out.push(at(
                        REGEX,
                        rel_path,
                        lit.line,
                        format!(
                            "pattern of {} characters; the limit is {MAX_PATTERN} (SA-32)",
                            lit.text.chars().count()
                        ),
                    ));
                }
            } else if !DYNAMIC_PATTERN_ALLOWED.iter().any(|(f, _)| *f == rel_path) {
                out.push(at(
                    REGEX,
                    rel_path,
                    line,
                    format!("run-time regex pattern: check its length ≤ {MAX_PATTERN} first and list the file in DYNAMIC_PATTERN_ALLOWED (SA-32)"),
                ));
            }
        }
    }
    out
}

pub(crate) fn check_regex(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for (rel_path, path) in rust_sources(root)? {
        out.extend(regex_violations(&rel_path, &read(&path)?));
    }
    Ok(out)
}

const PREALLOC: &str = "parser-preallocation";

/// Parser and decoder code (U48): the Kernel (CBOR, JSON, JOSE, COSE), the shared
/// dCBOR codec, the restriction lexer and the future `parse` crate.
pub(crate) const PARSER_PATHS: &[&str] = &[
    "crates/kernel/src/",
    "crates/suiss-crypto/src/",
    "crates/suiss-restriction/src/",
    "crates/parse/src/",
];

const PREALLOC_CALLS: &[&str] = &[
    "with_capacity(",
    ".reserve(",
    ".reserve_exact(",
    ".try_reserve(",
    ".try_reserve_exact(",
];

/// A capacity that cannot come from the wire: a literal, a constant, or the
/// length of data already in memory.
pub(crate) fn trusted_capacity(arg: &str) -> bool {
    let arg = arg.trim();
    let literal = !arg.is_empty()
        && arg.starts_with(|c: char| c.is_ascii_digit())
        && arg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    let last = arg.rsplit("::").next().unwrap_or(arg);
    let constant = !last.is_empty()
        && last.starts_with(|c: char| c.is_ascii_uppercase())
        && last
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    let in_memory = arg
        .strip_suffix(".len()")
        .is_some_and(|recv| !recv.is_empty() && !recv.contains('('));
    literal || constant || in_memory
}

/// Pre-allocations sized by an untrusted count in one parser file.
pub(crate) fn prealloc_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let code = lex(src).code;
    let tests = test_regions(&code);
    let mut out = Vec::new();
    let mut flag = |p: usize, what: &str, arg: &str| {
        let line = line_at(&code, p);
        if !in_regions(&tests, line) && !trusted_capacity(arg) {
            out.push(at(
                PREALLOC,
                rel_path,
                line,
                format!("`{what}({})`: no pre-allocation from a size read off the input; grow as items arrive (U48, §14.6)", arg.trim()),
            ));
        }
    };
    for t in PREALLOC_CALLS {
        for p in find_token(&code, t) {
            let open = p.saturating_add(t.len()).saturating_sub(1);
            let args = group(&code, open).unwrap_or_default();
            let first = split_top(args, ',').into_iter().next().unwrap_or_default();
            flag(p, t.trim_end_matches('('), first);
        }
    }
    for p in find_token(&code, "vec!") {
        let open = code
            .get(p..)
            .and_then(|s| s.find('['))
            .map_or(p, |o| p.saturating_add(o));
        let body = group(&code, open).unwrap_or_default();
        if let [_, n] = split_top(body, ';').as_slice() {
            flag(p, "vec![_; n]", n);
        }
    }
    out
}

pub(crate) fn check_prealloc(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for (rel_path, path) in rust_sources(root)? {
        if PARSER_PATHS.iter().any(|p| under(p, &rel_path)) {
            out.extend(prealloc_violations(&rel_path, &read(&path)?));
        }
    }
    Ok(out)
}

const TIMERS: &str = "no-semantic-timers";

/// Pure code that computes semantics (TI-10): the Kernel, the shared restriction and
/// codec crates, and every component's `domain` layer.
pub(crate) const TIMER_PATHS: &[&str] = &[
    "crates/kernel/src/",
    "crates/suiss-restriction/src/",
    "crates/suiss-crypto/src/",
    "crates/*/src/domain/",
    "crates/*/src/domain.rs",
];

/// Timers, sleeps, deadlines and wall clocks. Time enters as a trusted-time input.
const TIMER_TOKENS: &[&str] = &[
    "sleep(",
    "sleep_until(",
    "interval(",
    "interval_at(",
    "timeout(",
    "timeout_at(",
    "set_timeout",
    "Instant",
    "SystemTime",
    "std::time",
    "tokio::time",
    "async_std::task::sleep",
    "futures_timer",
    "Timer",
    "Delay::new",
    "Utc::now",
    "Local::now",
    "now_utc(",
    "Date::now",
    "web_time",
];

/// Timer crates pure code must not depend on.
const TIMER_CRATES: &[&str] = &[
    "tokio",
    "tokio-util",
    "async-std",
    "smol",
    "async-io",
    "futures-timer",
    "async-timer",
    "wasm-timer",
    "gloo-timers",
    "web-time",
    "instant",
];

/// Timer use in one pure file's non-test code (TI-10, T15).
pub(crate) fn timer_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let code = lex(src).code;
    let tests = test_regions(&code);
    let mut out = Vec::new();
    for t in TIMER_TOKENS {
        for p in find_token(&code, t) {
            let line = line_at(&code, p);
            if !in_regions(&tests, line) {
                out.push(at(
                    TIMERS,
                    rel_path,
                    line,
                    format!("`{}`: no semantic timers; time comes from the trusted-time input (TI-10, T15)", t.trim_end_matches('(')),
                ));
            }
        }
    }
    out
}

pub(crate) fn timer_dep_violations(root: &Path, md: &Metadata) -> Vec<Violation> {
    let mut out = Vec::new();
    for pkg in md.members() {
        let dir = rel(root, pkg.dir());
        let src = format!("{dir}/src/");
        if !TIMER_PATHS
            .iter()
            .any(|p| p.ends_with("/src/") && !p.contains('*') && *p == src)
        {
            continue;
        }
        for dep in pkg.deps.iter().filter(|d| d.kind == DepKind::Normal) {
            if TIMER_CRATES.contains(&dep.name.as_str()) {
                out.push(Violation {
                    rule: TIMERS,
                    path: PathBuf::from(format!("{dir}/Cargo.toml")),
                    message: format!("`{}`: no timers in pure code (TI-10, T15)", dep.name),
                });
            }
        }
    }
    out
}

pub(crate) fn check_timers(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for (rel_path, path) in rust_sources(root)? {
        if TIMER_PATHS.iter().any(|p| under(p, &rel_path)) {
            out.extend(timer_violations(&rel_path, &read(&path)?));
        }
    }
    out.extend(timer_dep_violations(
        root,
        &*crate::supply_chain::metadata::load(root)?,
    ));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::metadata::{fixture, parse};

    // SA-32
    #[test]
    fn unbounded_or_long_regex_is_rejected() {
        let src = "fn f() { let r = Regex::new(\"a+\"); }\n";
        assert_eq!(regex_violations("crates/x/src/a.rs", src).len(), 1);
        let long = format!(
            "fn f() {{ let r = RegexBuilder::new(\"{}\").size_limit(1 << 16).build(); }}\n",
            "a".repeat(MAX_PATTERN + 1)
        );
        assert_eq!(regex_violations("crates/x/src/a.rs", &long).len(), 1);
        let no_limit = "fn f() { let r = RegexBuilder::new(\"a+\").build(); }\n";
        assert_eq!(regex_violations("crates/x/src/a.rs", no_limit).len(), 1);
        let dynamic =
            "fn f(p: &str) { let r = RegexBuilder::new(p).size_limit(1 << 16).build(); }\n";
        assert_eq!(regex_violations("crates/x/src/a.rs", dynamic).len(), 1);
        let ok =
            "fn f() { let r = RegexBuilder::new(\"^[a-z]+$\").size_limit(1 << 16).build(); }\n";
        assert!(regex_violations("crates/x/src/a.rs", ok).is_empty());
    }

    // U48
    #[test]
    fn capacity_from_the_input_is_rejected() {
        let src = "fn f(n: usize) {\n let a: Vec<u8> = Vec::with_capacity(n);\n let b = vec![0u8; n];\n a.reserve(count);\n}\n";
        let v = prealloc_violations("crates/suiss-crypto/src/dcbor/decode.rs", src);
        assert_eq!(v.len(), 3);
        let ok = "fn f(e: &[u8]) {\n let a: Vec<u8> = Vec::with_capacity(e.len());\n let b = vec![0u8; 32];\n let c: Vec<u8> = Vec::with_capacity(MAX_ITEMS);\n let d = vec![1, 2];\n}\n";
        assert!(prealloc_violations("crates/kernel/src/codec.rs", ok).is_empty());
        let in_test = "#[cfg(test)]\nmod tests { fn t(n: usize) { let a: Vec<u8> = Vec::with_capacity(n); } }\n";
        assert!(prealloc_violations("crates/kernel/src/a.rs", in_test).is_empty());
    }

    #[test]
    fn trusted_capacities() {
        assert!(trusted_capacity("16"));
        assert!(trusted_capacity("limits::MAX_ITEMS"));
        assert!(trusted_capacity("entries.len()"));
        assert!(!trusted_capacity("n"));
        assert!(!trusted_capacity("header.count()"));
        assert!(!trusted_capacity("read_len(buf).len()"));
    }

    // TI-10, T15
    #[test]
    fn timers_in_pure_code_are_rejected() {
        let src =
            "fn f() { std::thread::sleep(d); let t = Instant::now(); tokio::time::interval(p); }\n";
        assert_eq!(timer_violations("crates/kernel/src/a.rs", src).len(), 4);
        let ok = "enum Bound { Interval(Window) }\nfn f(now: TrustedTime) {}\n";
        assert!(timer_violations("crates/kernel/src/a.rs", ok).is_empty());
        assert!(under(
            "crates/*/src/domain/",
            "crates/authority-core/src/domain/x.rs"
        ));
        assert!(!under(
            "crates/kernel/src/",
            "crates/restriction-analysis/src/solver.rs"
        ));
    }

    // TI-10
    #[test]
    fn timer_crate_in_pure_crate_is_rejected() {
        let mut kernel = fixture::member("crates/kernel", &[]);
        if let Some(deps) = kernel
            .get_mut("dependencies")
            .and_then(|d| d.as_array_mut())
        {
            deps.push(serde_json::json!({"name": "tokio", "kind": null}));
        }
        let md = parse(&fixture::metadata(&[kernel], &[])).unwrap();
        assert_eq!(timer_dep_violations(Path::new("/ws"), &md).len(), 1);
    }
}
