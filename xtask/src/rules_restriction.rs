//! Authorization-engine rules: no external authorization engine (§9.7A.7), Cedar
//! only in the forbid-only restriction crates (§5.8, L4, L8, MD-4) and the
//! `RestrictionPolicy` language version gate (INV-36, OP-119 m.8).

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{find_token, in_regions, lex, line_at, test_regions};
use crate::supply_chain::metadata::{DepKind, Metadata};
use crate::supply_chain::parse_lock;

fn v(rule: &'static str, path: &str, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(path),
        message,
    }
}

const ENGINES: &str = "no-external-authz";

/// §9.7A.7: `OpenFGA`, `SpiceDB`, Keto, casbin, oso and regorus (and other Rego and Zanzibar
/// engines) are not used. Matched as a package-name prefix.
pub(crate) const ENGINE_PREFIXES: &[&str] = &[
    "openfga",
    "spicedb",
    "authzed",
    "keto",
    "ory-keto",
    "casbin",
    "regorus",
    "burrego",
    "opa-wasm",
    "polar-core",
];

/// Exact names that would be too broad as prefixes.
pub(crate) const ENGINE_NAMES: &[&str] = &["oso", "oso-derive"];

/// Locked packages that are external authorization engines.
pub(crate) fn engine_violations(lock: &str) -> Result<Vec<Violation>, String> {
    Ok(parse_lock(lock)?
        .into_iter()
        .filter(|p| {
            ENGINE_NAMES.contains(&p.name.as_str())
                || ENGINE_PREFIXES
                    .iter()
                    .any(|pre| p.name == *pre || p.name.starts_with(&format!("{pre}-")) || p.name.starts_with(&format!("{pre}_")))
        })
        .map(|p| {
            v(
                ENGINES,
                "Cargo.lock",
                format!(
                    "`{}` {}: no external authorization engine; the decision is the Kernel's (§9.7A.7)",
                    p.name, p.version
                ),
            )
        })
        .collect())
}

pub(crate) fn check_engines(root: &Path) -> Result<Vec<Violation>, String> {
    engine_violations(&read(&root.join("Cargo.lock"))?)
}

const CEDAR: &str = "cedar-scope";

/// The forbid-only restriction engine and its control-plane analysis (OP-104, OP-105).
pub(crate) const CEDAR_DIRS: &[&str] = &["crates/suiss-restriction", "crates/restriction-analysis"];

fn in_cedar_dir(rel_path: &str) -> bool {
    CEDAR_DIRS
        .iter()
        .any(|d| rel_path == *d || rel_path.starts_with(&format!("{d}/")))
}

/// Cedar dependencies outside [`CEDAR_DIRS`]: Cedar `permit` never models positive
/// authority and `ReBAC` tuples are never canonical edges (§5.8, L4, L8, MD-4).
pub(crate) fn cedar_dep_violations(root: &Path, md: &Metadata) -> Vec<Violation> {
    let mut out = Vec::new();
    for pkg in md.members() {
        let dir = rel(root, pkg.dir());
        if in_cedar_dir(&dir) {
            continue;
        }
        for dep in pkg.deps.iter().filter(|d| d.kind != DepKind::Dev) {
            if dep.name.starts_with("cedar-policy") {
                out.push(v(
                    CEDAR,
                    &format!("{dir}/Cargo.toml"),
                    format!(
                        "`{}` outside the restriction crates; Cedar is forbid-only restriction, never positive authority (§5.8, L8, MD-4)",
                        dep.name
                    ),
                ));
            }
        }
    }
    out
}

/// `cedar_policy` paths in one Rust file outside [`CEDAR_DIRS`].
pub(crate) fn cedar_source_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    if in_cedar_dir(rel_path) {
        return Vec::new();
    }
    let code = lex(src).code;
    find_token(&code, "cedar_policy")
        .into_iter()
        .map(|p| {
            v(
                CEDAR,
                &format!("{rel_path}:{}", line_at(&code, p)),
                "Cedar is used only through esuiss-restriction (§5.8, L4, MD-4)".to_owned(),
            )
        })
        .collect()
}

pub(crate) fn check_cedar(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = cedar_dep_violations(root, &*crate::supply_chain::metadata::load(root)?);
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if path.extension().is_some_and(|e| e == "rs") && !rel_path.starts_with("xtask/") {
            out.extend(cedar_source_violations(&rel_path, &read(&path)?));
        }
    }
    Ok(out)
}

const CONFINE: &str = "solver-confinement";

/// Squeezed forms of a `Confine` that confines nothing.
const NO_OP_CONFINE: &[&str] = &["|_,_|Ok(())", "|_,_|{Ok(())}", "Result<()>{Ok(())}"];

/// What a file that builds a `Cvc5` must also contain: the `access-sandbox` solver lockdown.
const SANDBOX_CONFINE: &[&str] = &[
    "access_sandbox",
    "Profile::Solver",
    "allow_execute",
    ".confine(",
];

/// OP-123 m.2: in non-test code the solver `Confine` comes from `access-sandbox`. A file that
/// mentions `Cvc5` has no no-op `Confine`, and one that calls `Cvc5::pinned` builds the
/// `access_sandbox` solver lockdown.
pub(crate) fn confine_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    if is_test_file(rel_path) || rel_path.starts_with("xtask/") {
        return Vec::new();
    }
    let code = lex(src).code;
    let tests = test_regions(&code);
    let live = |at: usize| {
        let line = line_at(&code, at);
        (!in_regions(&tests, line)).then_some(line)
    };
    let live_tokens = |needle: &str| -> Vec<usize> {
        find_token(&code, needle)
            .into_iter()
            .filter_map(&live)
            .collect()
    };
    if live_tokens("Cvc5").is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut origin = Vec::new();
    let mut flat = String::new();
    for (at, c) in code.char_indices().filter(|(_, c)| !c.is_whitespace()) {
        origin.extend(std::iter::repeat_n(at, c.len_utf8()));
        flat.push(c);
    }
    for pattern in NO_OP_CONFINE {
        for (at, _) in flat.match_indices(pattern) {
            if let Some(line) = origin.get(at).and_then(|&o| live(o)) {
                out.push(v(
                    CONFINE,
                    &format!("{rel_path}:{line}"),
                    "a solver Confine that confines nothing; outside tests it is the access-sandbox solver lockdown (OP-123 m.2, OP-115 m.6)".to_owned(),
                ));
            }
        }
    }
    if !rel_path.starts_with("crates/restriction-analysis/") {
        for line in live_tokens("Cvc5::pinned") {
            let missing: Vec<&str> = SANDBOX_CONFINE
                .iter()
                .copied()
                .filter(|needle| live_tokens(needle).is_empty())
                .collect();
            if !missing.is_empty() {
                out.push(v(
                    CONFINE,
                    &format!("{rel_path}:{line}"),
                    format!(
                        "`Cvc5::pinned` without the access-sandbox solver lockdown (missing {}) (OP-123 m.2)",
                        missing.join(", ")
                    ),
                ));
            }
        }
    }
    out
}

pub(crate) fn check_confine(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        if path.extension().is_some_and(|e| e == "rs") {
            out.extend(confine_violations(&rel(root, &path), &read(&path)?));
        }
    }
    Ok(out)
}

const LANGUAGE: &str = "restriction-language";

/// INV-36, OP-119 m.8: the declared `RestrictionPolicy` language version.
pub(crate) const LANGUAGE_FILE: &str = "supply-chain/restriction-language.toml";

/// Packages whose version is the language's semantics.
const LANGUAGE_PACKAGES: &[&str] = &["cedar-policy", "cedar-policy-core"];

/// Compares the declaration with the lockfile and the workspace pin.
pub(crate) fn language_violations(
    declaration: &str,
    lock: &str,
    manifest: &str,
) -> Result<Vec<Violation>, String> {
    let table: toml::Table = declaration
        .parse()
        .map_err(|e| format!("{LANGUAGE_FILE}: {e}"))?;
    let mut out = Vec::new();
    if table
        .get("version")
        .and_then(toml::Value::as_integer)
        .is_none_or(|n| n < 1)
    {
        out.push(v(
            LANGUAGE,
            LANGUAGE_FILE,
            "`version` must be a positive integer (INV-36)".to_owned(),
        ));
    }
    let Some(declared) = table.get("cedar-policy").and_then(toml::Value::as_str) else {
        out.push(v(
            LANGUAGE,
            LANGUAGE_FILE,
            "`cedar-policy` must name the exact version the language is bound to (OP-119 m.8)"
                .to_owned(),
        ));
        return Ok(out);
    };
    let locked = parse_lock(lock)?;
    for name in LANGUAGE_PACKAGES {
        let versions: Vec<&str> = locked
            .iter()
            .filter(|p| p.name == *name)
            .map(|p| p.version.as_str())
            .collect();
        if versions.is_empty() {
            out.push(v(
                LANGUAGE,
                "Cargo.lock",
                format!("`{name}` is not locked; the restriction language needs it (INV-36)"),
            ));
        }
        for found in versions.into_iter().filter(|found| *found != declared) {
            out.push(v(
                LANGUAGE,
                "Cargo.lock",
                format!(
                    "`{name}` {found} differs from the declared {declared}; a new Cedar version is a new language version and passes the release gate (INV-36, OP-119 m.6, m.8)"
                ),
            ));
        }
    }
    let pin = manifest.parse::<toml::Table>().ok().and_then(|t| {
        let dep = t
            .get("workspace")?
            .get("dependencies")?
            .get("cedar-policy")?;
        dep.as_str()
            .or_else(|| dep.get("version").and_then(toml::Value::as_str))
            .map(str::to_owned)
    });
    if pin.as_deref() != Some(format!("={declared}").as_str()) {
        out.push(v(
            LANGUAGE,
            "Cargo.toml",
            format!(
                "[workspace.dependencies] cedar-policy must be pinned to \"={declared}\" (found {pin:?}) (OP-119 m.8)"
            ),
        ));
    }
    Ok(out)
}

pub(crate) fn check_language(root: &Path) -> Result<Vec<Violation>, String> {
    let path = root.join(LANGUAGE_FILE);
    if !path.exists() {
        return Ok(vec![v(
            LANGUAGE,
            LANGUAGE_FILE,
            "missing: the RestrictionPolicy language version is declared here (INV-36, OP-119 m.8)"
                .to_owned(),
        )]);
    }
    language_violations(
        &read(&path)?,
        &read(&root.join("Cargo.lock"))?,
        &read(&root.join("Cargo.toml"))?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::metadata::{fixture, parse};

    fn lock(pkgs: &[(&str, &str)]) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for (n, ver) in pkgs {
            let _ = write!(out, "[[package]]\nname = \"{n}\"\nversion = \"{ver}\"\n\n");
        }
        out
    }

    // §9.7A.7
    #[test]
    fn external_engines_are_rejected() {
        let l = lock(&[
            ("openfga-rs", "0.1.0"),
            ("spicedb-client", "0.1.0"),
            ("casbin", "2.0.0"),
            ("oso", "0.27.0"),
            ("regorus", "0.2.0"),
            ("ory-keto-client", "0.11.0"),
            ("osoxide", "1.0.0"),
            ("ketos", "0.12.0"),
            ("cedar-policy", "4.13.0"),
        ]);
        let names: Vec<String> = engine_violations(&l)
            .unwrap()
            .into_iter()
            .map(|x| x.message.split('`').nth(1).unwrap_or_default().to_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "openfga-rs",
                "spicedb-client",
                "casbin",
                "oso",
                "regorus",
                "ory-keto-client"
            ]
        );
    }

    // §5.8, L8, MD-4
    #[test]
    fn cedar_outside_the_restriction_crates_is_rejected() {
        let mut core = fixture::member("crates/authority-core", &[]);
        let mut restriction = fixture::member("crates/suiss-restriction", &[]);
        for m in [&mut core, &mut restriction] {
            if let Some(deps) = m.get_mut("dependencies").and_then(|d| d.as_array_mut()) {
                deps.push(serde_json::json!({"name": "cedar-policy", "kind": null}));
            }
        }
        let md = parse(&fixture::metadata(&[core, restriction], &[])).unwrap();
        assert_eq!(cedar_dep_violations(Path::new("/ws"), &md).len(), 1);
        let src = "use cedar_policy::PolicySet;\n";
        assert_eq!(
            cedar_source_violations("crates/authority-core/src/a.rs", src).len(),
            1
        );
        assert!(cedar_source_violations("crates/suiss-restriction/src/lib.rs", src).is_empty());
    }

    const MANIFEST: &str = "[workspace.dependencies]\ncedar-policy = { version = \"=4.13.0\", default-features = false }\n";

    // INV-36, OP-119 m.8
    #[test]
    fn language_version_follows_the_lockfile() {
        let decl = "version = 1\ncedar-policy = \"4.13.0\"\n";
        let good = lock(&[("cedar-policy", "4.13.0"), ("cedar-policy-core", "4.13.0")]);
        assert!(
            language_violations(decl, &good, MANIFEST)
                .unwrap()
                .is_empty()
        );
        let bumped = lock(&[("cedar-policy", "4.14.0"), ("cedar-policy-core", "4.14.0")]);
        assert_eq!(
            language_violations(decl, &bumped, MANIFEST).unwrap().len(),
            2
        );
        let loose = "[workspace.dependencies]\ncedar-policy = \"4\"\n";
        assert_eq!(language_violations(decl, &good, loose).unwrap().len(), 1);
        let no_version = "cedar-policy = \"4.13.0\"\n";
        assert_eq!(
            language_violations(no_version, &good, MANIFEST)
                .unwrap()
                .len(),
            1
        );
    }

    // OP-123 m.2
    #[test]
    fn no_op_confine_outside_tests_is_rejected() {
        let src = "fn wire() { let c = Cvc5::pinned(p, t, |_, _| Ok(())); }\n";
        assert_eq!(confine_violations("bins/x/src/main.rs", src).len(), 2);
        let fn_src = "use esuiss_restriction_analysis::Cvc5;\n\
            fn none(_: &mut Command, _: &Path) -> std::io::Result<()> {\n    Ok(())\n}\n";
        assert_eq!(confine_violations("bins/x/src/main.rs", fn_src).len(), 1);
        let in_crate = "pub struct Cvc5;\nfn f() -> Confine { |_, _| { Ok(()) } }\n";
        assert_eq!(
            confine_violations("crates/restriction-analysis/src/solver.rs", in_crate).len(),
            1
        );
    }

    // OP-123 m.2
    #[test]
    fn sandbox_confine_and_test_code_are_accepted() {
        let wired = "use access_sandbox::{LandlockAbi, Lockdown, Profile};\n\
            fn confine(c: &mut Command, s: &Path) -> std::io::Result<()> {\n\
                Lockdown::new(Profile::Solver, LandlockAbi::REQUIRED).allow_execute(s).confine(c).map_err(std::io::Error::other)\n\
            }\n\
            fn wire() { let c = Cvc5::pinned(p, t, confine); }\n";
        assert!(confine_violations("bins/x/src/main.rs", wired).is_empty());
        let test_only =
            "struct Cvc5;\n#[cfg(test)]\nfn f(h: [u8; 32]) -> Confine {\n    |_, _| Ok(())\n}\n";
        assert!(
            confine_violations("crates/restriction-analysis/src/solver.rs", test_only).is_empty()
        );
        let no_op = "fn wire() { Cvc5::pinned(p, t, |_, _| Ok(())) }\n";
        assert!(confine_violations("crates/restriction-analysis/tests/x.rs", no_op).is_empty());
        assert!(
            confine_violations("bins/x/src/main.rs", "fn f() -> io::Result<()> { Ok(()) }")
                .is_empty()
        );
    }
}
