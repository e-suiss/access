//! Architecture and code rules (OP-62, OP-63, OP-64, OP-66, OP-73, TI-9, R-2,
//! SA-21). Each check lives in a `rules_*` module.

#[path = "rules_deps.rs"]
pub(crate) mod deps;
#[path = "rules_files.rs"]
pub(crate) mod files;
#[path = "rules_lex.rs"]
pub(crate) mod lex;
#[path = "rules_profile.rs"]
mod profile;
#[path = "rules_source.rs"]
pub(crate) mod source;
#[path = "rules_switches.rs"]
mod switches;

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
    ]
}
