//! The interop lab (IDP-40, OP-155 m.3 (q)):
//! - `interop-profile-tests`: every tolerance of a shipped interop profile and every system of
//!   the lab names a test that exists (Ek B 4937);
//! - `interop-lab`: the lab matrix is well formed, every container is pinned by digest, a live
//!   run names its CI secret, Keycloak is never an oracle (§14.8, Ek B 5064), and the public
//!   compatibility table is the one the matrix generates (Ek B 4936).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use super::files::{read, rel, walk};
use crate::Violation;

/// The lab matrix.
pub(crate) const LAB: &str = "conformance/interop/lab.toml";
/// The generated table.
pub(crate) const TABLE: &str = "conformance/interop/COMPATIBILITY.md";

const PROTOCOLS: &[(&str, &str)] = &[
    ("oidc", "OpenID Connect and OAuth"),
    ("saml", "SAML 2.0"),
    ("scim", "SCIM 2.0"),
    ("ldap", "LDAP"),
    ("kerberos", "Kerberos"),
    ("radius", "RADIUS"),
];
const KINDS: &[&str] = &["container", "package", "fixture", "live"];
const JOBS: &[&str] = &[
    "oidf-conformance",
    "interop-lab",
    "differential",
    "edge-interop",
    "kerberos",
];

fn v(rule: &'static str, path: &str, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(path),
        message,
    }
}

fn root_file(krate: &Path) -> PathBuf {
    let lib = krate.join("src/lib.rs");
    if lib.exists() {
        lib
    } else {
        krate.join("src/main.rs")
    }
}

fn module_dir(file: &Path) -> PathBuf {
    let parent = file.parent().map_or_else(PathBuf::new, Path::to_path_buf);
    match file.file_name().and_then(|n| n.to_str()) {
        Some("lib.rs" | "main.rs" | "mod.rs") => parent,
        _ => file
            .file_stem()
            .map_or(parent.clone(), |stem| parent.join(stem)),
    }
}

fn has_test_fn(text: &str, name: &str) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    lines.iter().enumerate().any(|(i, line)| {
        let t = line.trim_start();
        let declares = [
            format!("fn {name}("),
            format!("async fn {name}("),
            format!("pub fn {name}("),
        ]
        .iter()
        .any(|d| t.starts_with(d.as_str()));
        declares
            && lines
                .get(i.saturating_sub(4)..i)
                .unwrap_or_default()
                .iter()
                .any(|l| {
                    let l = l.trim_start();
                    l.starts_with("#[test]") || l.starts_with("#[tokio::test")
                })
    })
}

/// Resolves `path` (`module::…::test_fn`) to a test function of the crate in `krate`.
pub(crate) fn resolve_rust(root: &Path, krate: &str, path: &str) -> Result<(), String> {
    let dir = root.join(krate);
    let segs: Vec<&str> = path.split("::").collect();
    let Some((name, mods)) = segs.split_last() else {
        return Err(format!("`{path}` is empty"));
    };
    let ident = krate.rsplit('/').next().unwrap_or(krate).replace('-', "_");
    let (mut file, rest): (PathBuf, &[&str]) = match mods.split_first() {
        Some((first, tail)) if *first == ident => (root_file(&dir), tail),
        Some((first, tail)) if dir.join("tests").join(format!("{first}.rs")).exists() => {
            (dir.join("tests").join(format!("{first}.rs")), tail)
        }
        _ => (root_file(&dir), mods),
    };
    let mut inline = false;
    for seg in rest {
        if !inline {
            let base = module_dir(&file);
            let flat = base.join(format!("{seg}.rs"));
            let nested = base.join(seg).join("mod.rs");
            if flat.exists() {
                file = flat;
                continue;
            }
            if nested.exists() {
                file = nested;
                continue;
            }
            inline = true;
        }
        let text = read(&file)?;
        if !text.contains(&format!("mod {seg} {{")) && !text.contains(&format!("mod {seg};")) {
            return Err(format!(
                "`{path}`: no module `{seg}` in {}",
                rel(root, &file)
            ));
        }
    }
    let text = read(&file)?;
    if has_test_fn(&text, name) {
        Ok(())
    } else {
        Err(format!(
            "`{path}`: no test function `{name}` in {}",
            rel(root, &file)
        ))
    }
}

/// Resolves a lab test: `<crate dir>::<path>` or `script:<file>#<case>`.
pub(crate) fn resolve_lab_test(root: &Path, test: &str) -> Result<(), String> {
    if let Some(script) = test.strip_prefix("script:") {
        let (file, case) = script
            .split_once('#')
            .ok_or_else(|| format!("`{test}` names no case after `#`"))?;
        let body = read(&root.join(file)).map_err(|_| format!("`{test}`: no file {file}"))?;
        return if !case.is_empty() && body.contains(case) {
            Ok(())
        } else {
            Err(format!("`{test}`: {file} has no case `{case}`"))
        };
    }
    let (krate, path) = test
        .split_once("::")
        .ok_or_else(|| format!("`{test}` is neither `<crate dir>::<test path>` nor `script:`"))?;
    if !root.join(krate).join("Cargo.toml").exists() {
        return Err(format!("`{test}`: {krate} is not a crate"));
    }
    resolve_rust(root, krate, path)
}

fn tolerance_tests(path: &str, text: &str) -> Result<Vec<String>, String> {
    let json = Path::new(path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("json"));
    let value: serde_json::Value = if json {
        serde_json::from_str(text).map_err(|e| format!("{path}: {e}"))?
    } else {
        let t: toml::Table = text.parse().map_err(|e| format!("{path}: {e}"))?;
        serde_json::to_value(t).map_err(|e| format!("{path}: {e}"))?
    };
    Ok(value
        .get("tolerances")
        .and_then(serde_json::Value::as_array)
        .map(|ts| {
            ts.iter()
                .map(|t| {
                    t.get("test")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default())
}

/// `interop-profile-tests`.
pub(crate) fn check_tests(root: &Path) -> Result<Vec<Violation>, String> {
    const RULE: &str = "interop-profile-tests";
    let mut out = Vec::new();
    for file in walk(&root.join("crates"))? {
        let r = rel(root, &file);
        let parts: Vec<&str> = r.split('/').collect();
        let [_, krate, "profiles", name] = parts.as_slice() else {
            continue;
        };
        let ext = Path::new(name).extension().and_then(|e| e.to_str());
        if !matches!(ext, Some("toml" | "json")) {
            continue;
        }
        let text = read(&file)?;
        for test in tolerance_tests(&r, &text)? {
            if test.is_empty() {
                out.push(v(RULE, &r, String::from("a tolerance names no test case")));
                continue;
            }
            if let Err(e) = resolve_rust(root, &format!("crates/{krate}"), &test) {
                out.push(v(RULE, &r, e));
            }
        }
    }
    if let Ok(lab) = Lab::load(root) {
        for s in &lab.systems {
            if s.tests.is_empty() {
                out.push(v(RULE, LAB, format!("{} names no test", s.name)));
            }
            for t in &s.tests {
                if let Err(e) = resolve_lab_test(root, t) {
                    out.push(v(RULE, LAB, format!("{}: {e}", s.name)));
                }
            }
        }
    }
    Ok(out)
}

/// One counterpart of the lab.
#[derive(Debug, Default)]
pub(crate) struct System {
    pub(crate) name: String,
    pub(crate) protocol: String,
    pub(crate) role: String,
    pub(crate) kind: String,
    pub(crate) version: String,
    pub(crate) image: Option<String>,
    pub(crate) secret: Option<String>,
    pub(crate) oracle: bool,
    pub(crate) profile: Option<String>,
    pub(crate) job: Option<String>,
    pub(crate) tests: Vec<String>,
}

/// The lab matrix.
#[derive(Debug, Default)]
pub(crate) struct Lab {
    pub(crate) systems: Vec<System>,
}

fn s(t: &toml::Table, k: &str) -> Option<String> {
    t.get(k).and_then(toml::Value::as_str).map(str::to_owned)
}

impl Lab {
    pub(crate) fn load(root: &Path) -> Result<Self, String> {
        let text = read(&root.join(LAB))?;
        Self::parse(&text)
    }

    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let t: toml::Table = text.parse().map_err(|e| format!("{LAB}: {e}"))?;
        if t.get("version").and_then(toml::Value::as_integer) != Some(1) {
            return Err(format!("{LAB}: version must be 1"));
        }
        let systems = t
            .get("system")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| format!("{LAB}: no [[system]]"))?;
        let mut out = Vec::new();
        for (i, x) in systems.iter().enumerate() {
            let x = x
                .as_table()
                .ok_or_else(|| format!("{LAB}: system {i} is not a table"))?;
            for k in x.keys() {
                if !matches!(
                    k.as_str(),
                    "name"
                        | "protocol"
                        | "role"
                        | "kind"
                        | "version"
                        | "image"
                        | "secret"
                        | "oracle"
                        | "profile"
                        | "job"
                        | "tests"
                ) {
                    return Err(format!("{LAB}: system {i} has unknown key `{k}`"));
                }
            }
            out.push(System {
                name: s(x, "name").unwrap_or_default(),
                protocol: s(x, "protocol").unwrap_or_default(),
                role: s(x, "role").unwrap_or_default(),
                kind: s(x, "kind").unwrap_or_default(),
                version: s(x, "version").unwrap_or_default(),
                image: s(x, "image"),
                secret: s(x, "secret"),
                oracle: x
                    .get("oracle")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(false),
                profile: s(x, "profile"),
                job: s(x, "job"),
                tests: x
                    .get("tests")
                    .and_then(toml::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(toml::Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            });
        }
        Ok(Self { systems: out })
    }
}

fn pinned(image: &str) -> bool {
    image.split_once("@sha256:").is_some_and(|(name, d)| {
        !name.is_empty()
            && d.len() == 64
            && d.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The violations of the lab matrix itself.
pub(crate) fn lab_violations(lab: &Lab, workflows: &str) -> Vec<String> {
    let mut out = Vec::new();
    for x in &lab.systems {
        let n = &x.name;
        if n.is_empty() || x.role.is_empty() || x.version.is_empty() {
            out.push(format!(
                "system `{n}` needs a name, a role and a tested version"
            ));
        }
        if !PROTOCOLS.iter().any(|(p, _)| *p == x.protocol) {
            out.push(format!("{n}: unknown protocol `{}`", x.protocol));
        }
        if !KINDS.contains(&x.kind.as_str()) {
            out.push(format!("{n}: unknown kind `{}`", x.kind));
        }
        match (x.kind.as_str(), &x.image) {
            ("container", Some(i)) if pinned(i) => {}
            ("container", _) => out.push(format!(
                "{n}: a container is pinned by digest (`name@sha256:<64 hex>`)"
            )),
            (_, Some(_)) => out.push(format!("{n}: only a container names an image")),
            _ => {}
        }
        match (x.kind.as_str(), &x.secret) {
            ("live", Some(sec))
                if !sec.is_empty()
                    && sec
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') =>
            {
                if !workflows.contains(&format!("secrets.{sec} ")) {
                    out.push(format!(
                        "{n}: the interop-lab job does not pass the secret {sec}"
                    ));
                }
            }
            ("live", _) => out.push(format!("{n}: a live run names the CI secret it waits for")),
            (_, Some(_)) => out.push(format!("{n}: only a live run names a secret")),
            _ => {}
        }
        // §14.8, Ek B 5064
        if x.oracle && x.name.to_ascii_lowercase().contains("keycloak") {
            out.push(format!(
                "{n}: Keycloak is a counterpart only, never an oracle (§14.8)"
            ));
        }
        if x.oracle && x.kind != "container" {
            out.push(format!(
                "{n}: only a pinned open-source counterpart can be an oracle"
            ));
        }
        match &x.job {
            Some(j) if JOBS.contains(&j.as_str()) => {
                if !workflows.contains(&format!("\n  {j}:\n")) {
                    out.push(format!("{n}: no workflow defines the job `{j}`"));
                }
            }
            Some(j) => out.push(format!("{n}: unknown job `{j}`")),
            None => out.push(format!("{n}: names no CI job")),
        }
    }
    out
}

fn how(x: &System) -> String {
    match x.kind.as_str() {
        "container" => {
            let image = x.image.as_deref().unwrap_or_default();
            let (name, digest) = image.split_once("@sha256:").unwrap_or((image, ""));
            format!(
                "container `{name}` (`sha256:{}`)",
                digest.get(..12).unwrap_or(digest)
            )
        }
        "package" => String::from("distribution package on the CI runner"),
        "fixture" => String::from("recorded or documented requests"),
        _ => format!(
            "live, when the CI secret `{}` exists",
            x.secret.as_deref().unwrap_or_default()
        ),
    }
}

/// The public compatibility table generated from the lab matrix.
pub(crate) fn table(lab: &Lab) -> String {
    let mut out = String::from(
        "# Compatibility\n\n\
         Which systems Access is tested against, at which version, and how. CI runs every row \
         nightly and on every release tag; a failing row fails the run.\n\n\
         This file is generated from [`lab.toml`](lab.toml) by `cargo xtask interop-table`; do not \
         edit it by hand. An oracle is a reference whose answer the differential tests compare \
         against; every other row is a counterpart Access must work with.\n",
    );
    for (protocol, title) in PROTOCOLS {
        let rows: Vec<&System> = lab
            .systems
            .iter()
            .filter(|x| x.protocol == *protocol)
            .collect();
        if rows.is_empty() {
            continue;
        }
        let _ = write!(
            out,
            "\n## {title}\n\n| System | Role | Version tested | How | Profile | Oracle | Tests | CI job |\n|---|---|---|---|---|---|---|---|\n"
        );
        for x in rows {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} | `{}` |",
                x.name,
                x.role,
                x.version,
                how(x),
                x.profile
                    .as_deref()
                    .map_or_else(|| String::from("none"), |p| format!("`{p}`")),
                if x.oracle { "yes" } else { "no" },
                x.tests.len(),
                x.job.as_deref().unwrap_or_default(),
            );
        }
    }
    out
}

fn workflows(root: &Path) -> Result<String, String> {
    let mut all = String::new();
    for f in walk(&root.join(".github/workflows"))? {
        all.push_str(&read(&f)?);
        all.push('\n');
    }
    Ok(all)
}

/// `interop-lab`.
pub(crate) fn check_lab(root: &Path) -> Result<Vec<Violation>, String> {
    const RULE: &str = "interop-lab";
    let lab = match Lab::load(root) {
        Ok(l) => l,
        Err(e) => return Ok(vec![v(RULE, LAB, e)]),
    };
    let mut out: Vec<Violation> = lab_violations(&lab, &workflows(root)?)
        .into_iter()
        .map(|m| v(RULE, LAB, m))
        .collect();
    match std::fs::read_to_string(root.join(TABLE)) {
        Ok(t) if t == table(&lab) => {}
        _ => out.push(v(
            RULE,
            TABLE,
            String::from("out of date; run `cargo xtask interop-table`"),
        )),
    }
    Ok(out)
}

/// `cargo xtask interop-table`.
pub(crate) fn write_table(root: &Path) -> Result<(), String> {
    let lab = Lab::load(root)?;
    std::fs::write(root.join(TABLE), table(&lab)).map_err(|e| format!("{TABLE}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WF: &str = "jobs:\n  interop-lab:\n    x: 1\n  differential:\n    x: 1\n";

    fn lab(extra: &str) -> Lab {
        Lab::parse(&format!(
            "version = 1\n[[system]]\nname = \"SimpleSAMLphp\"\nprotocol = \"saml\"\nrole = \"service provider\"\nkind = \"container\"\nversion = \"2.4\"\nimage = \"composer@sha256:{}\"\noracle = true\njob = \"differential\"\ntests = [\"script:x#y\"]\n{extra}",
            "a".repeat(64)
        ))
        .unwrap()
    }

    // §14.8, Ek B 5064
    #[test]
    fn keycloak_is_never_an_oracle() {
        assert_eq!(lab_violations(&lab(""), WF), Vec::<String>::new());
        let k = lab(&format!(
            "[[system]]\nname = \"Keycloak\"\nprotocol = \"oidc\"\nrole = \"upstream provider\"\nkind = \"container\"\nversion = \"26\"\nimage = \"keycloak@sha256:{}\"\noracle = true\njob = \"interop-lab\"\ntests = [\"script:x#y\"]\n",
            "b".repeat(64)
        ));
        let m = lab_violations(&k, WF);
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].contains("never an oracle"));
    }

    // OP-155 m.3 (q)
    #[test]
    fn containers_are_pinned_and_live_runs_name_their_secret() {
        let unpinned = Lab::parse("version = 1\n[[system]]\nname = \"x\"\nprotocol = \"saml\"\nrole = \"r\"\nkind = \"container\"\nversion = \"1\"\nimage = \"composer:2\"\njob = \"interop-lab\"\ntests = [\"a\"]\n").unwrap();
        assert!(lab_violations(&unpinned, WF)[0].contains("digest"));
        let live = Lab::parse("version = 1\n[[system]]\nname = \"Okta\"\nprotocol = \"scim\"\nrole = \"r\"\nkind = \"live\"\nversion = \"1\"\njob = \"interop-lab\"\ntests = [\"a\"]\n").unwrap();
        assert!(lab_violations(&live, WF)[0].contains("secret"));
        let nojob = Lab::parse("version = 1\n[[system]]\nname = \"x\"\nprotocol = \"scim\"\nrole = \"r\"\nkind = \"fixture\"\nversion = \"1\"\njob = \"kerberos\"\ntests = [\"a\"]\n").unwrap();
        assert!(lab_violations(&nojob, WF)[0].contains("no workflow"));
    }

    // IDP-40, Ek B 4936
    #[test]
    fn the_table_lists_every_system_under_its_protocol() {
        let t = table(&lab(""));
        assert!(t.contains("## SAML 2.0"));
        assert!(t.contains("| SimpleSAMLphp | service provider | 2.4 | container `composer` (`sha256:aaaaaaaaaaaa`) | none | yes | 1 | `differential` |"));
        assert!(!t.contains("## SCIM"));
    }

    // IDP-40, Ek B 4937
    #[test]
    fn a_test_path_resolves_to_a_test_function() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        resolve_rust(
            root,
            "crates/identity-scim",
            "scim_profiles::entra::opt_flag",
        )
        .unwrap();
        resolve_rust(
            root,
            "crates/identity-saml",
            "identity_saml::domain::profile::tests::every_shipped_profile_loads",
        )
        .unwrap();
        assert!(
            resolve_rust(
                root,
                "crates/identity-scim",
                "scim_profiles::entra::nothing"
            )
            .is_err()
        );
        assert!(
            resolve_rust(
                root,
                "crates/identity-scim",
                "scim_profiles::nope::opt_flag"
            )
            .is_err()
        );
        assert!(resolve_lab_test(root, "script:xtask/src/rules_interop.rs#interop-lab").is_ok());
        let missing = format!("script:xtask/src/rules_interop.rs#{}", "z".repeat(40));
        assert!(resolve_lab_test(root, &missing).is_err());
    }
}
