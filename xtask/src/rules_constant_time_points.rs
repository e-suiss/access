//! `constant-time-points` (CR-39, OP-159 m.3 (s)): every constant-time point names its function and the test that measures it.
//!
//! - Every point of CR-39 m.1 appears exactly once: the ten [ID] points and the [AU] additions.
//! - A point that applies names at least one `path#fn` whose file defines `fn <name>`, the
//!   secret comparison it relies on, and at least one `dudect::<test>` or `ctgrind::<test>`
//!   that `crates/crypto/tests/{dudect,ctgrind}.rs` defines.
//! - Only an [AU] point may say `applies = false`, and then it gives a reason.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;

pub(crate) const FILE: &str = "conformance/catalog/constant-time.toml";

/// CR-39 m.1: the ten [ID] points.
pub(crate) const ID_POINTS: [&str; 10] = [
    "id-opaque-token",
    "id-hmac-jws",
    "id-totp",
    "id-client-secret",
    "id-api-key",
    "id-csrf-state",
    "id-reset-link",
    "id-pkce",
    "id-device-code",
    "id-webauthn-challenge",
];

/// CR-39 m.1: the [AU] additions.
pub(crate) const AU_POINTS: [&str; 5] = [
    "au-nonce-jti",
    "au-basis-ref",
    "au-event-id",
    "au-status-list",
    "au-proof-commit",
];

/// The files that hold the measurements, by tool.
const MEASUREMENTS: [(&str, &str); 2] = [
    ("dudect", "crates/crypto/tests/dudect.rs"),
    ("ctgrind", "crates/crypto/tests/ctgrind.rs"),
];

/// One constant-time point.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Point {
    pub(crate) id: String,
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) functions: Vec<String>,
    #[serde(default)]
    pub(crate) secret: Option<String>,
    #[serde(default)]
    pub(crate) measured: Vec<String>,
    #[serde(default = "yes")]
    pub(crate) applies: bool,
    #[serde(default)]
    pub(crate) reason: Option<String>,
}

const fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Catalog {
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) point: Vec<Point>,
}

/// What exists in the repository for the points to name.
pub(crate) trait Sources {
    /// The text of the repository file `path`, if it exists.
    fn file(&self, path: &str) -> Option<String>;
}

fn violation(message: String) -> Violation {
    Violation {
        rule: "CR-39",
        path: PathBuf::from(FILE),
        message,
    }
}

/// Whether `src` defines a function named `name`.
pub(crate) fn defines(src: &str, name: &str) -> bool {
    let needle = format!("fn {name}");
    src.match_indices(&needle).any(|(at, _)| {
        let after = src
            .get(at.saturating_add(needle.len())..)
            .unwrap_or_default();
        let before = src.get(..at).unwrap_or_default();
        after.starts_with(['(', '<'])
            && before.chars().next_back().is_none_or(|c| c.is_whitespace())
    })
}

fn check_point(p: &Point, sources: &dyn Sources, out: &mut Vec<Violation>) {
    let id = &p.id;
    if p.title.trim().is_empty() {
        out.push(violation(format!("{id}: no title")));
    }
    if !p.applies {
        if !id.starts_with("au-") {
            out.push(violation(format!(
                "{id}: an [ID] point of CR-39 m.1 always applies"
            )));
        }
        if p.reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
            out.push(violation(format!(
                "{id}: does not apply but gives no reason"
            )));
        }
        if !p.functions.is_empty() || !p.measured.is_empty() {
            out.push(violation(format!(
                "{id}: does not apply but names functions or measurements"
            )));
        }
        return;
    }
    if p.functions.is_empty() {
        out.push(violation(format!("{id}: names no function")));
    }
    for f in &p.functions {
        let Some((path, name)) = f.split_once('#') else {
            out.push(violation(format!("{id}: {f:?} is not `path#fn`")));
            continue;
        };
        match sources.file(path) {
            None => out.push(violation(format!("{id}: {path} does not exist"))),
            Some(src) if !defines(&src, name) => {
                out.push(violation(format!("{id}: {path} defines no `fn {name}`")));
            }
            Some(_) => {}
        }
    }
    if p.secret.as_deref().is_none_or(|s| s.trim().is_empty()) {
        out.push(violation(format!(
            "{id}: names no Secret<N>, ct_eq or constant-time primitive"
        )));
    }
    if p.measured.is_empty() {
        out.push(violation(format!(
            "{id}: no dudect target or ctgrind test measures it"
        )));
    }
    for m in &p.measured {
        let found = m.split_once("::").and_then(|(tool, test)| {
            MEASUREMENTS
                .iter()
                .find(|(t, _)| *t == tool)
                .map(|(_, file)| (*file, test))
        });
        let Some((file, test)) = found else {
            out.push(violation(format!(
                "{id}: {m:?} is not `dudect::<test>` or `ctgrind::<test>`"
            )));
            continue;
        };
        if !sources.file(file).is_some_and(|src| defines(&src, test)) {
            out.push(violation(format!("{id}: {file} defines no `fn {test}`")));
        }
    }
}

/// Pure validation, separated for tests.
pub(crate) fn violations(catalog: &Catalog, sources: &dyn Sources) -> Vec<Violation> {
    let mut out = Vec::new();
    if catalog.version != 1 {
        out.push(violation(format!("version {} is not 1", catalog.version)));
    }
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for p in &catalog.point {
        let Some(known) = ID_POINTS
            .iter()
            .chain(AU_POINTS.iter())
            .find(|k| **k == p.id)
        else {
            out.push(violation(format!("{}: not a point of CR-39 m.1", p.id)));
            continue;
        };
        let k = seen.entry(known).or_default();
        *k = k.saturating_add(1);
        check_point(p, sources, &mut out);
    }
    for id in ID_POINTS.iter().chain(AU_POINTS.iter()) {
        match seen.get(id).copied().unwrap_or(0) {
            0 => out.push(violation(format!("{id} is missing"))),
            1 => {}
            k => out.push(violation(format!("{id} appears {k} times"))),
        }
    }
    out
}

struct Repo<'a>(&'a Path);

impl Sources for Repo<'_> {
    fn file(&self, path: &str) -> Option<String> {
        if path.contains("..") {
            return None;
        }
        std::fs::read_to_string(self.0.join(path)).ok()
    }
}

pub(crate) fn load(root: &Path) -> Result<Catalog, String> {
    let path = root.join(FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Runs `constant-time-points`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    Ok(violations(&load(root)?, &Repo(root)))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;

    impl Sources for Fixed {
        fn file(&self, path: &str) -> Option<String> {
            match path {
                "a.rs" => Some(String::from("pub fn verify(x: u8) {}\nfn other<T>() {}\n")),
                "crates/crypto/tests/dudect.rs" => Some(String::from("    fn target() {}\n")),
                "crates/crypto/tests/ctgrind.rs" => Some(String::from("fn clean() {}\n")),
                _ => None,
            }
        }
    }

    fn point(id: &str) -> Point {
        Point {
            id: id.to_owned(),
            title: String::from("t"),
            functions: vec![String::from("a.rs#verify")],
            secret: Some(String::from("ct_eq")),
            measured: vec![String::from("dudect::target")],
            applies: true,
            reason: None,
        }
    }

    fn full() -> Catalog {
        Catalog {
            version: 1,
            point: ID_POINTS
                .iter()
                .chain(AU_POINTS.iter())
                .map(|id| point(id))
                .collect(),
        }
    }

    fn messages(c: &Catalog) -> Vec<String> {
        violations(c, &Fixed)
            .into_iter()
            .map(|v| v.message)
            .collect()
    }

    // CR-39 m.1, OP-159 m.3 (s)
    #[test]
    fn every_point_is_mapped_and_measured() {
        assert_eq!(messages(&full()), Vec::<String>::new());
        let mut c = full();
        c.point.retain(|p| p.id != "id-totp");
        assert_eq!(messages(&c), vec![String::from("id-totp is missing")]);
        let mut c = full();
        c.point.push(point("id-pkce"));
        assert_eq!(messages(&c), vec![String::from("id-pkce appears 2 times")]);
        let mut c = full();
        c.point.push(point("id-everything"));
        assert_eq!(messages(&c).len(), 1);
    }

    // CR-39 m.1, m.5, OP-159 m.3 (s)
    #[test]
    fn a_point_without_a_function_or_measurement_is_refused() {
        let mut c = full();
        if let Some(p) = c.point.first_mut() {
            p.functions = vec![String::from("a.rs#missing"), String::from("b.rs#verify")];
            p.measured = vec![
                String::from("dudect::absent"),
                String::from("ctgrind::clean"),
                String::from("valgrind::x"),
            ];
            p.secret = None;
        }
        assert_eq!(messages(&c).len(), 5, "{:?}", messages(&c));
        let mut c = full();
        if let Some(p) = c.point.first_mut() {
            p.functions.clear();
            p.measured.clear();
        }
        assert_eq!(messages(&c).len(), 2);
    }

    // CR-39 m.1
    #[test]
    fn only_an_au_point_may_not_apply_and_only_with_a_reason() {
        let mut c = full();
        for p in &mut c.point {
            if p.id == "au-event-id" || p.id == "id-totp" {
                p.applies = false;
                p.functions.clear();
                p.measured.clear();
                p.secret = None;
                p.reason = Some(String::from("never compared"));
            }
        }
        assert_eq!(
            messages(&c),
            vec![String::from(
                "id-totp: an [ID] point of CR-39 m.1 always applies"
            )]
        );
        if let Some(p) = c.point.iter_mut().find(|p| p.id == "au-event-id") {
            p.reason = None;
        }
        assert_eq!(messages(&c).len(), 2);
    }

    #[test]
    fn defines_matches_whole_function_names() {
        assert!(defines("pub fn verify(x: u8)", "verify"));
        assert!(defines("fn other<T>()", "other"));
        assert!(!defines("fn verify_all(x: u8)", "verify"));
        assert!(!defines("fn_verify(", "verify"));
    }
}
