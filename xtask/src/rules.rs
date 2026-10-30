//! Architecture and code rules (OP-62, OP-63, OP-64, OP-66, OP-73, TI-9, R-2,
//! SA-21, CR-3, CR-11, CR-13, SA-32, U48, TI-10, INV-26, INV-36, §9.7A.7). Each check lives in a `rules_*` module.

#[path = "rules_crypto.rs"]
mod crypto;
#[path = "rules_deps.rs"]
pub(crate) mod deps;
#[path = "rules_files.rs"]
pub(crate) mod files;
#[path = "rules_lex.rs"]
pub(crate) mod lex;
#[path = "rules_limits.rs"]
mod limits;
#[path = "rules_profile.rs"]
mod profile;
#[path = "rules_restriction.rs"]
mod restriction;
#[path = "rules_source.rs"]
pub(crate) mod source;
#[path = "rules_switches.rs"]
mod switches;
#[path = "rules_vectors.rs"]
mod vectors;

use crate::Check;

pub(crate) fn checks() -> Vec<Check> {
    vec![
        Check {
            name: "dependency-direction",
            run: deps::check,
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
            name: "shared-vectors",
            run: vectors::check,
        },
    ]
}
