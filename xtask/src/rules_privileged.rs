//! `no-privileged-path` (PI-14, OP-62, B21, B22, E24, OP-156 m.2 Q1): the auxiliary services and
//! the product twins use only what a third party can use.
//!
//! - A `services/*` crate depends (outside dev-dependencies) only on published workspace crates,
//!   the public ones a customer builds the same service with.
//! - No other workspace crate depends on a `services/*` crate outside dev-dependencies.
//! - Every Access endpoint the product twin names is a public one: a path of an `OpenAPI`
//!   document under `sdks/openapi/`, or an ADP protocol binding the ADP router serves.
//! - `conformance/seams/DEPENDENCIES.md` declares what each service still depends on and is
//!   what `cargo xtask seam-dependencies` writes from the code and
//!   `conformance/seams/declared.toml`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::Violation;
use crate::rules::files::{read, rel, walk};
use crate::supply_chain::metadata::{DepKind, Metadata};

const RULE: &str = "no-privileged-path";

/// The generated declaration.
pub(crate) const DEPENDENCIES: &str = "conformance/seams/DEPENDENCIES.md";

/// The declared dependencies that are not crates or endpoints.
const DECLARED: &str = "conformance/seams/declared.toml";

/// The product twin's sources.
const TWIN: &str = "services/product-twin/src";

/// The ADP protocol bindings (L1-ADP-5, L1-ADP-11): public by the protocol, not by an `OpenAPI`
/// document; each must still be a route of the ADP router.
const ADP_BINDINGS: [&str; 6] = [
    "/access/v1/evaluation",
    "/access/v1/evaluations",
    "/access/v1/explain",
    "/.well-known/authzen-configuration",
    "/.well-known/authzen-configuration/{domain}",
    "/.well-known/access-domain-metadata/{domain}",
];

/// The ADP router's source, where every binding must be served.
const ADP_ROUTER: &str = "crates/http/src/adp/adapters.rs";

/// The path prefixes Access serves; a service's literal under one of them is an Access endpoint.
const ACCESS_PREFIXES: [&str; 11] = [
    "/access/",
    "/.well-known/access-",
    "/.well-known/authzen-",
    "/.well-known/suiss-",
    "/realms/",
    "/proxy/",
    "/ssf/",
    "/admin/",
    "/console/",
    "/internal/",
    "/v1/",
];

fn v(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: path.into(),
        message,
    }
}

/// `path` with every segment holding a `{name}` (or `{}`) placeholder made `{}`, and any query
/// cut.
fn shape(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    path.split('/')
        .map(|seg| if seg.contains('{') { "{}" } else { seg })
        .collect::<Vec<_>>()
        .join("/")
}

/// The text of a source file without its inline `#[cfg(test)]` module.
fn production(text: &str) -> &str {
    text.find("#[cfg(test)]\nmod tests")
        .map_or(text, |i| text.get(..i).unwrap_or(text))
}

/// The string literals of `text` that name an Access path.
fn access_literals(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for piece in production(text).split('"').skip(1).step_by(2) {
        if piece.contains(char::is_whitespace) {
            continue;
        }
        if ACCESS_PREFIXES.iter().any(|p| piece.starts_with(p)) {
            out.insert(shape(piece));
        }
    }
    out
}

/// The public paths: every `OpenAPI` document's paths, shaped.
fn openapi_paths(root: &Path) -> Result<BTreeSet<String>, String> {
    let mut out = BTreeSet::new();
    let dir = root.join("sdks/openapi");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    for f in files {
        let doc: serde_json::Value =
            serde_json::from_str(&read(&f)?).map_err(|e| format!("{}: {e}", f.display()))?;
        if let Some(paths) = doc.get("paths").and_then(serde_json::Value::as_object) {
            out.extend(paths.keys().map(|p| shape(p)));
        }
    }
    Ok(out)
}

/// Whether the dependency at `dir` is a published crate: its manifest does not opt out.
fn published(root: &Path, dir: &str) -> bool {
    std::fs::read_to_string(root.join(dir).join("Cargo.toml")).is_ok_and(|t| {
        !t.lines()
            .any(|l| l.trim().replace(' ', "") == "publish=false")
    })
}

/// Whether `to` is a crate of the same service as `dir` (`services/<name>/…`): a service's own
/// sub-crates, such as the Linux client's NSS and PAM shells (OP-156 m.3 (p)).
pub(crate) fn same_service(dir: &str, to: &str) -> bool {
    let service = |p: &str| {
        let mut parts = p.split('/');
        match (parts.next(), parts.next()) {
            (Some("services"), Some(name)) if !name.is_empty() => Some(name.to_owned()),
            _ => None,
        }
    };
    service(dir).is_some_and(|s| service(to) == Some(s))
}

/// One service as the declaration lists it.
struct Service {
    name: String,
    dir: String,
    crates: BTreeSet<String>,
    endpoints: BTreeSet<String>,
}

fn services(root: &Path, md: &Metadata) -> Result<Vec<Service>, String> {
    let files = walk(root)?;
    let mut out = Vec::new();
    for pkg in md.members() {
        let dir = rel(root, pkg.dir());
        if !dir.starts_with("services/") {
            continue;
        }
        let crates = pkg
            .deps
            .iter()
            .filter(|d| d.kind != DepKind::Dev && d.path.is_some())
            .map(|d| d.name.clone())
            .collect();
        let mut endpoints = BTreeSet::new();
        for f in &files {
            let r = rel(root, f);
            let in_src = r
                .strip_prefix(&dir)
                .is_some_and(|rest| rest.starts_with("/src/"));
            if !in_src
                || f.extension().is_none_or(|x| x != "rs")
                || crate::rules::files::is_test_file(&r)
                || r.ends_with("/testing.rs")
                || r.contains("/testing/")
            {
                continue;
            }
            endpoints.extend(access_literals(&read(f)?));
        }
        out.push(Service {
            name: pkg.name.clone(),
            dir,
            crates,
            endpoints,
        });
    }
    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    Ok(out)
}

/// The crate and endpoint checks over `md`.
pub(crate) fn check_metadata(root: &Path, md: &Metadata) -> Vec<Violation> {
    let mut out = Vec::new();
    for pkg in md.members() {
        let dir = rel(root, pkg.dir());
        let manifest = format!("{dir}/Cargo.toml");
        for dep in pkg.deps.iter().filter(|d| d.kind != DepKind::Dev) {
            let Some(path) = &dep.path else { continue };
            let to = rel(root, path);
            if dir.starts_with("services/") && !published(root, &to) && !same_service(&dir, &to) {
                out.push(v(
                    &manifest,
                    format!(
                        "service `{}` depends on `{}` ({to}), which is not a published crate (PI-14, B21)",
                        pkg.name, dep.name
                    ),
                ));
            }
            if to.starts_with("services/") && !dir.starts_with("services/") {
                out.push(v(
                    &manifest,
                    format!(
                        "`{}` depends on the service `{}`; nothing in Access depends on a service (OP-62, B21)",
                        pkg.name, dep.name
                    ),
                ));
            }
        }
    }
    out
}

/// The endpoint check of the twin's sources against the public paths.
pub(crate) fn check_endpoints(
    twin: &BTreeMap<String, BTreeSet<String>>,
    public: &BTreeSet<String>,
) -> Vec<Violation> {
    let mut out = Vec::new();
    for (file, literals) in twin {
        for l in literals {
            if !public.contains(l) {
                out.push(v(
                    file,
                    format!(
                        "the product twin names `{l}`, which no public contract serves (PI-14)"
                    ),
                ));
            }
        }
    }
    out
}

fn public_paths(root: &Path) -> Result<(BTreeSet<String>, Vec<Violation>), String> {
    let mut public = openapi_paths(root)?;
    let router = read(&root.join(ADP_ROUTER))?;
    let mut out = Vec::new();
    for b in ADP_BINDINGS {
        if router.contains(&format!("\"{b}\"")) {
            public.insert(shape(b));
        } else {
            out.push(v(
                ADP_ROUTER,
                format!("the ADP binding `{b}` is not a route of the ADP router"),
            ));
        }
    }
    Ok((public, out))
}

fn twin_literals(root: &Path) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut out = BTreeMap::new();
    for f in walk(&root.join(TWIN))? {
        let r = rel(root, f.as_path());
        if f.extension().is_some_and(|x| x == "rs") {
            out.insert(r, access_literals(&read(&f)?));
        }
    }
    Ok(out)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Declared {
    #[serde(default)]
    declared: Vec<DeclaredEntry>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredEntry {
    service: String,
    dependency: String,
    why: String,
}

fn declared(root: &Path) -> Result<Vec<DeclaredEntry>, String> {
    let text = read(&root.join(DECLARED))?;
    let d: Declared = toml::from_str(&text).map_err(|e| format!("{DECLARED}: {e}"))?;
    Ok(d.declared)
}

/// The declaration's text.
fn render(services: &[Service], public: &BTreeSet<String>, declared: &[DeclaredEntry]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("# Service dependencies\n\n");
    s.push_str(
        "Generated by `cargo xtask seam-dependencies` from the code and `declared.toml`; \
         `cargo xtask check no-privileged-path` fails when it is stale.\n\n",
    );
    s.push_str(
        "Every auxiliary service and product twin is built the way a third party would build it: \
         on the published crates only, over Access's public endpoints. What each one still depends \
         on is listed here.\n",
    );
    for svc in services {
        let _ = write!(s, "\n## `{}` ({})\n\n", svc.name, svc.dir);
        s.push_str("Crates:\n\n");
        if svc.crates.is_empty() {
            s.push_str("- none\n");
        }
        for c in &svc.crates {
            let _ = writeln!(s, "- `{c}`");
        }
        s.push_str("\nAccess endpoints:\n\n");
        if svc.endpoints.is_empty() {
            s.push_str("- none\n");
        }
        for e in &svc.endpoints {
            let how = if public.contains(e) {
                "public"
            } else {
                "not in a public contract"
            };
            let _ = writeln!(s, "- `{e}` ({how})");
        }
        let own: Vec<&DeclaredEntry> = declared.iter().filter(|d| d.service == svc.name).collect();
        s.push_str("\nDeclared:\n\n");
        if own.is_empty() {
            s.push_str("- none\n");
        }
        for d in own {
            let _ = writeln!(s, "- {}: {}", d.dependency, d.why);
        }
    }
    s
}

fn generated(root: &Path) -> Result<(String, Vec<Violation>), String> {
    let md = crate::supply_chain::metadata::load(root)?;
    let (public, mut out) = public_paths(root)?;
    let svcs = services(root, &md)?;
    let declared = declared(root)?;
    for d in &declared {
        if !svcs.iter().any(|s| s.name == d.service) {
            out.push(v(
                DECLARED,
                format!("`{}` is not a service crate", d.service),
            ));
        }
    }
    Ok((render(&svcs, &public, &declared), out))
}

/// `cargo xtask check no-privileged-path`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let md = crate::supply_chain::metadata::load(root)?;
    let mut out = check_metadata(root, &md);
    let (public, unserved) = public_paths(root)?;
    out.extend(unserved);
    out.extend(check_endpoints(&twin_literals(root)?, &public));
    let (text, wrong) = generated(root)?;
    out.extend(wrong);
    let committed = std::fs::read_to_string(root.join(DEPENDENCIES)).unwrap_or_default();
    if committed != text {
        out.push(v(
            DEPENDENCIES,
            String::from("stale; run `cargo xtask seam-dependencies`"),
        ));
    }
    Ok(out)
}

/// `cargo xtask seam-dependencies`.
pub(crate) fn write(root: &Path) -> Result<(), String> {
    let (text, _) = generated(root)?;
    std::fs::write(root.join(DEPENDENCIES), text).map_err(|e| format!("{DEPENDENCIES}: {e}"))
}

#[cfg(test)]
mod tests {
    // OP-156 m.3 (p), PI-14
    #[test]
    fn a_service_may_use_its_own_sub_crates_only() {
        assert!(super::same_service(
            "services/linux-client/pam",
            "services/linux-client/module"
        ));
        assert!(super::same_service(
            "services/linux-client",
            "services/linux-client/module"
        ));
        assert!(!super::same_service(
            "services/proxy",
            "services/linux-client/module"
        ));
        assert!(!super::same_service(
            "services/linux-client",
            "crates/store"
        ));
    }

    use super::*;
    use crate::supply_chain::metadata::fixture::{member, metadata};
    use crate::supply_chain::metadata::parse;

    // PI-14, OP-62
    #[test]
    fn an_access_crate_depending_on_a_service_is_flagged() {
        let md = parse(&metadata(
            &[
                member("services/product-twin", &[]),
                member("crates/http", &[("services/product-twin", None)]),
            ],
            &[],
        ))
        .unwrap_or_default();
        let out = check_metadata(Path::new("/ws"), &md);
        assert!(
            out.iter()
                .any(|x| x.message.contains("depends on the service")),
            "{out:?}"
        );
    }

    // PI-14
    #[test]
    fn a_dev_dependency_on_a_service_is_not_a_path() {
        let md = parse(&metadata(
            &[
                member("services/product-twin", &[]),
                member(
                    "bins/access-server",
                    &[("services/product-twin", Some("dev"))],
                ),
            ],
            &[],
        ))
        .unwrap_or_default();
        assert!(check_metadata(Path::new("/ws"), &md).is_empty());
    }

    // PI-14, B21
    #[test]
    fn a_service_on_an_unpublished_crate_is_flagged() {
        let md = parse(&metadata(
            &[
                member("crates/store", &[]),
                member("services/product-twin", &[("crates/store", None)]),
            ],
            &[],
        ))
        .unwrap_or_default();
        let out = check_metadata(Path::new("/ws"), &md);
        assert!(
            out.iter()
                .any(|x| x.message.contains("not a published crate")),
            "{out:?}"
        );
    }

    // PI-14
    #[test]
    fn a_twin_endpoint_outside_the_public_contracts_is_flagged() {
        let public = BTreeSet::from([shape("/access/v1/evaluation")]);
        let twin = BTreeMap::from([(
            String::from("services/product-twin/src/wire.rs"),
            access_literals(
                "const A: &str = \"/access/v1/evaluation\";\nconst B: &str = \"/internal/v1/state\";\n",
            ),
        )]);
        let out = check_endpoints(&twin, &public);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].message.contains("/internal/v1/state"));
    }

    #[test]
    fn placeholders_and_inline_tests_do_not_count() {
        assert_eq!(
            shape("/access/v1/tenants/{tenant}/pairing?x=1"),
            "/access/v1/tenants/{}/pairing"
        );
        assert_eq!(
            shape("/.well-known/access-domain-metadata/sha-256:{domain}"),
            "/.well-known/access-domain-metadata/{}"
        );
        let found = access_literals(
            "const A: &str = \"/realms/{realm}/v1/x\";\n#[cfg(test)]\nmod tests {\n const B: &str = \"/internal/v1/y\";\n}\n",
        );
        assert_eq!(found, BTreeSet::from([String::from("/realms/{}/v1/x")]));
    }
}
