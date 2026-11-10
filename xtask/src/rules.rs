//! Architecture and code rules (OP-62, OP-63, OP-64, OP-66, OP-73, TI-9, R-2,
//! SA-21, CR-3, CR-11, CR-13, SA-32, U48, TI-10, INV-26, INV-36, §9.7A.7, OP-150 (e), TN-113, OP-47, OP-67, MUST-NEVER-6, IDI-11). Each check lives in a `rules_*` module.

#[path = "rules_comments.rs"]
mod comments;
#[path = "rules_crypto.rs"]
mod crypto;
#[path = "rules_custody.rs"]
mod custody;
#[path = "rules_deps.rs"]
pub(crate) mod deps;
#[path = "rules_edge.rs"]
mod edge;
#[path = "rules_files.rs"]
pub(crate) mod files;
#[path = "rules_fluent.rs"]
mod fluent;
#[path = "rules_interop.rs"]
pub(crate) mod interop;
#[path = "rules_iys.rs"]
mod iys;
#[path = "rules_lex.rs"]
pub(crate) mod lex;
#[path = "rules_limits.rs"]
mod limits;
#[path = "rules_manifest.rs"]
mod manifest;
#[path = "rules_personal.rs"]
mod personal;
#[path = "rules_privileged.rs"]
pub(crate) mod privileged;
#[path = "rules_profile.rs"]
mod profile;
#[path = "rules_progress.rs"]
mod progress;
#[path = "rules_restriction.rs"]
mod restriction;
#[path = "rules_seam.rs"]
mod seam;
#[path = "rules_source.rs"]
pub(crate) mod source;
#[path = "rules_switches.rs"]
pub(crate) mod switches;
#[path = "rules_telemetry.rs"]
mod telemetry;
#[path = "rules_ui_terms.rs"]
pub(crate) mod ui_terms;
#[path = "rules_vectors.rs"]
mod vectors;

use crate::Check;

/// `dependency-direction` with its source half, `no-authority-to-identity-write` (§5.12).
fn planes(root: &std::path::Path) -> Result<Vec<crate::Violation>, String> {
    let mut out = deps::check(root)?;
    out.extend(seam::check(root)?);
    Ok(out)
}

#[expect(clippy::too_many_lines, reason = "one entry per rule, in report order")]
pub(crate) fn checks() -> Vec<Check> {
    let mut all = telemetry::checks();
    all.extend(vec![
        Check {
            name: "dependency-direction",
            run: planes,
        },
        Check {
            name: "edge-isolation",
            run: edge::check,
        },
        Check {
            name: "kernel-purity",
            run: source::check_purity,
        },
        Check {
            name: "sql-only-in-store",
            run: source::check_sql,
        },
        Check {
            name: "no-physical-delete",
            run: source::check_delete,
        },
        Check {
            name: "personal-data",
            run: personal::check,
        },
        Check {
            name: "migration-hygiene",
            run: source::check_migrations,
        },
        Check {
            name: "no-dev-mode",
            run: switches::check,
        },
        Check {
            name: "unsafe-allowlist",
            run: source::check_unsafe,
        },
        Check {
            name: "todo-has-issue",
            run: source::check_todo,
        },
        Check {
            name: "comment-ids",
            run: comments::check,
        },
        Check {
            name: "panic-profile",
            run: profile::check,
        },
        Check {
            name: "secret-compare",
            run: source::check_secret_compare,
        },
        Check {
            name: "fail-closed",
            run: switches::check_fail_closed,
        },
        Check {
            name: "crypto-provider",
            run: crypto::check_provider,
        },
        Check {
            name: "no-batch-verify",
            run: crypto::check_batch,
        },
        Check {
            name: "hmac-scope",
            run: crypto::check_hmac,
        },
        Check {
            name: "no-rsa-authority",
            run: crypto::check_rsa,
        },
        Check {
            name: "regex-limits",
            run: limits::check_regex,
        },
        Check {
            name: "parser-preallocation",
            run: limits::check_prealloc,
        },
        Check {
            name: "no-semantic-timers",
            run: limits::check_timers,
        },
        Check {
            name: "no-external-authz",
            run: restriction::check_engines,
        },
        Check {
            name: "cedar-scope",
            run: restriction::check_cedar,
        },
        Check {
            name: "restriction-language",
            run: restriction::check_language,
        },
        Check {
            name: "solver-confinement",
            run: restriction::check_confine,
        },
        Check {
            name: "no-custody-key",
            run: custody::check,
        },
        Check {
            name: "shared-vectors",
            run: vectors::check,
        },
        Check {
            name: "endpoint-manifest",
            run: manifest::check,
        },
        Check {
            name: "forbidden-ui-terms",
            run: ui_terms::check,
        },
        Check {
            name: "ui-text-nodes",
            run: ui_terms::check_text_nodes,
        },
        Check {
            name: "fluent-catalog",
            run: fluent::check,
        },
        Check {
            name: "no-plan-progress",
            run: progress::check,
        },
        Check {
            name: "interop-profile-tests",
            run: interop::check_tests,
        },
        Check {
            name: "interop-lab",
            run: interop::check_lab,
        },
        // PI-14, OP-156 m.2 Q1
        Check {
            name: "no-privileged-path",
            run: privileged::check,
        },
        // IDP-37 (4), B23, E42, OP-156 m.2 Q9
        Check {
            name: "no-iys-client",
            run: iys::check,
        },
    ]);
    all
}
