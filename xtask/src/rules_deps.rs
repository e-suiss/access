//! `dependency-direction` (OP-62, OP-76): internal crates may depend only on the
//! internal crates the OP-62 table allows.

use std::path::Path;

use crate::Violation;
use crate::rules::files::rel;
use crate::supply_chain::metadata::{DepKind, Metadata};

const RULE: &str = "dependency-direction";

/// The OP-62 crate classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Kernel,
    Suiss,
    /// `suiss-ledger`: shared, but has I/O-facing parts, so the Kernel may not use it (OP-93).
    SuissLedger,
    Proto,
    Parse,
    Crypto,
    Store,
    InternalApi,
    Authority,
    Identity,
    Http,
    Telemetry,
    Sandbox,
    Testkit,
    Bin,
    Bindings,
    Sdk,
    Service,
    Tooling,
}

/// Classifies a workspace crate by its directory relative to the root.
pub(crate) fn classify(dir: &str) -> Option<Class> {
    let (group, name) = dir.split_once('/').unwrap_or((dir, ""));
    let class = match (group, name) {
        ("crates", "kernel") => Class::Kernel,
        ("crates", "proto") => Class::Proto,
        ("crates", "parse") => Class::Parse,
        ("crates", "crypto") => Class::Crypto,
        ("crates", "store") => Class::Store,
        ("crates", "internal-api") => Class::InternalApi,
        ("crates", "http") => Class::Http,
        ("crates", "telemetry") => Class::Telemetry,
        ("crates", "sandbox") => Class::Sandbox,
        ("crates", "testkit") => Class::Testkit,
        ("crates", "suiss-ledger") => Class::SuissLedger,
        ("crates", n) if n.starts_with("suiss-") && !n.contains('/') => Class::Suiss,
        ("crates", n) if n.starts_with("authority-") && !n.contains('/') => Class::Authority,
        ("crates", n) if n.starts_with("identity-") && !n.contains('/') => Class::Identity,
        ("bins", n) if !n.is_empty() && !n.contains('/') => Class::Bin,
        ("sdks", n) if n == "bindings" || n.starts_with("bindings/") => Class::Bindings,
        ("sdks", n) if !n.is_empty() => Class::Sdk,
        ("services", n) if !n.is_empty() => Class::Service,
        ("xtask", "") => Class::Tooling,
        _ => return None,
    };
    Some(class)
}

/// The OP-62 table: the internal classes a crate of class `from` may depend on.
/// `None` means every class.
fn allowed_targets(from: Class) -> Option<&'static [Class]> {
    use Class::{
        Authority, Bin, Bindings, Crypto, Http, Identity, InternalApi, Kernel, Parse, Proto,
        Sandbox, Sdk, Service, Store, Suiss, SuissLedger, Telemetry, Testkit, Tooling,
    };
    let targets: &'static [Class] = match from {
        // OP-93
        Bin | Testkit => return None,
        // OP-93
        Kernel => &[Suiss],
        Tooling | Sandbox => &[],
        // OP-76
        Suiss | SuissLedger => &[Suiss, SuissLedger],
        // OP-93
        Proto | Telemetry => &[Kernel],
        Parse | Crypto | Store | Bindings | InternalApi => &[Kernel, Proto],
        // INV-12, SEC19
        Authority => &[
            Kernel,
            Proto,
            Parse,
            Crypto,
            Store,
            InternalApi,
            Telemetry,
            Authority,
        ],
        Identity => &[
            Kernel,
            Proto,
            Parse,
            Crypto,
            Store,
            InternalApi,
            Telemetry,
            Identity,
        ],
        // B21, B22, E24
        Service => &[Kernel, Proto, Sdk, Bindings],
        Sdk => &[Kernel, Proto, Bindings, Sdk],
        // OP-93, OP-62
        Http => &[Kernel, Proto, Telemetry, InternalApi, Authority, Identity],
    };
    Some(targets)
}

/// May a crate of class `from` depend on a crate of class `to`?
pub(crate) fn allowed(from: Class, to: Class) -> bool {
    // OP-93
    if to == Class::Testkit {
        return false;
    }
    // OP-76
    if matches!(to, Class::Suiss | Class::SuissLedger)
        && !matches!(from, Class::Tooling | Class::Kernel | Class::Sandbox)
    {
        return true;
    }
    allowed_targets(from).is_none_or(|targets| targets.contains(&to))
}

/// Checks every workspace crate's internal dependencies against the table.
pub(crate) fn check_metadata(root: &Path, md: &Metadata) -> Vec<Violation> {
    let mut out = Vec::new();
    for pkg in md.members() {
        let dir = rel(root, pkg.dir());
        let manifest = pkg
            .manifest_path
            .strip_prefix(root)
            .unwrap_or(&pkg.manifest_path)
            .to_path_buf();
        let Some(from) = classify(&dir) else {
            out.push(Violation {
                rule: RULE,
                path: manifest,
                message: format!(
                    "crate `{}` in `{dir}` has no OP-62 class; add its directory to xtask/src/rules_deps.rs",
                    pkg.name
                ),
            });
            continue;
        };
        for dep in pkg.deps.iter().filter(|d| d.kind != DepKind::Dev) {
            let Some(dep_path) = &dep.path else { continue };
            let dep_dir = rel(root, dep_path);
            let Some(to) = classify(&dep_dir) else {
                out.push(Violation {
                    rule: RULE,
                    path: manifest.clone(),
                    message: format!(
                        "depends on `{}` in `{dep_dir}`, which has no OP-62 class",
                        dep.name
                    ),
                });
                continue;
            };
            if !allowed(from, to) {
                out.push(Violation {
                    rule: RULE,
                    path: manifest.clone(),
                    message: format!(
                        "`{}` ({from:?}) must not depend on `{}` ({to:?}) (OP-62)",
                        pkg.name, dep.name
                    ),
                });
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let md = crate::supply_chain::metadata::load(root)?;
    Ok(check_metadata(root, &md))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::metadata::fixture::{member, metadata};
    use crate::supply_chain::metadata::parse;

    fn run(packages: &[serde_json::Value]) -> Vec<Violation> {
        let md = parse(&metadata(packages, &[])).unwrap_or_default();
        check_metadata(Path::new("/ws"), &md)
    }

    #[test]
    fn identity_crate_depending_on_authority_is_rejected() {
        let v = run(&[
            member("crates/authority-core", &[]),
            member("crates/identity-oauth", &[("crates/authority-core", None)]),
        ]);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn authority_crate_depending_on_identity_is_rejected() {
        let v = run(&[
            member("crates/identity-session", &[]),
            member(
                "crates/authority-core",
                &[("crates/identity-session", Some("build"))],
            ),
        ]);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn kernel_depending_on_any_access_crate_is_rejected() {
        let v = run(&[
            member("crates/proto", &[]),
            member("crates/kernel", &[("crates/proto", None)]),
        ]);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn suiss_crate_depending_on_access_crate_is_rejected() {
        let v = run(&[
            member("crates/store", &[]),
            member("crates/suiss-ledger", &[("crates/store", None)]),
        ]);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn kernel_may_use_shared_suiss_crypto() {
        let v = run(&[
            member("crates/suiss-crypto", &[]),
            member("crates/kernel", &[("crates/suiss-crypto", None)]),
        ]);
        assert!(v.is_empty());
    }

    // OP-93
    #[test]
    fn kernel_depending_on_suiss_ledger_is_rejected() {
        let v = run(&[
            member("crates/suiss-ledger", &[]),
            member("crates/kernel", &[("crates/suiss-ledger", None)]),
        ]);
        assert_eq!(v.len(), 1);
    }

    // OP-93
    #[test]
    fn http_may_use_plane_crates_but_telemetry_may_not_use_proto() {
        let ok = run(&[
            member("crates/authority-core", &[]),
            member("crates/http", &[("crates/authority-core", None)]),
        ]);
        assert!(ok.is_empty());
        let bad = run(&[
            member("crates/proto", &[]),
            member("crates/telemetry", &[("crates/proto", None)]),
        ]);
        assert_eq!(bad.len(), 1);
    }

    // OP-93
    #[test]
    fn normal_dependency_on_testkit_is_rejected() {
        let v = run(&[
            member("crates/testkit", &[]),
            member("crates/http", &[("crates/testkit", None)]),
        ]);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn service_depending_on_internal_crate_is_rejected() {
        let v = run(&[
            member("crates/store", &[]),
            member("services/executor", &[("crates/store", None)]),
        ]);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn dev_dependencies_are_not_checked() {
        let v = run(&[
            member("crates/authority-core", &[]),
            member(
                "crates/identity-oauth",
                &[("crates/authority-core", Some("dev"))],
            ),
        ]);
        assert!(v.is_empty());
    }

    #[test]
    fn bins_may_depend_on_everything() {
        let v = run(&[
            member("crates/authority-core", &[]),
            member("crates/identity-oauth", &[]),
            member(
                "bins/access-server",
                &[
                    ("crates/authority-core", None),
                    ("crates/identity-oauth", None),
                ],
            ),
        ]);
        assert!(v.is_empty());
    }

    #[test]
    fn crate_in_unknown_directory_fails_closed() {
        let v = run(&[member("crates/mystery", &[])]);
        assert_eq!(v.len(), 1);
        assert!(
            v.first()
                .is_some_and(|x| x.message.contains("no OP-62 class"))
        );
    }
}
