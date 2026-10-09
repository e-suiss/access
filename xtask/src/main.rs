//! Repository rule checks and development automation (OP-62, OP-69).

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "xtask is a developer CLI; it reports to the terminal"
)]

mod catalog;
mod policy;
mod rules;
mod supply_chain;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// One rule violation, reported as `path: [rule] message`.
#[derive(Debug)]
pub(crate) struct Violation {
    pub(crate) rule: &'static str,
    pub(crate) path: PathBuf,
    pub(crate) message: String,
}

/// A named check over the repository.
pub(crate) struct Check {
    pub(crate) name: &'static str,
    pub(crate) run: fn(&Path) -> Result<Vec<Violation>, String>,
}

fn checks() -> Vec<Check> {
    let mut all = Vec::new();
    all.extend(rules::checks());
    all.extend(supply_chain::checks());
    all.extend(catalog::checks());
    all.extend(policy::checks());
    all
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn run_checks(root: &Path, only: Option<&str>) -> ExitCode {
    if let Some(name) = only
        && !checks().iter().any(|check| check.name == name)
    {
        eprintln!("unknown check `{name}`; see `cargo xtask list`");
        return ExitCode::FAILURE;
    }
    let mut failed = false;
    for check in checks() {
        if only.is_some_and(|name| name != check.name) {
            continue;
        }
        match (check.run)(root) {
            Ok(violations) if violations.is_empty() => println!("ok    {}", check.name),
            Ok(violations) => {
                failed = true;
                println!("FAIL  {} ({} violations)", check.name, violations.len());
                for v in violations {
                    println!("      {}: [{}] {}", v.path.display(), v.rule, v.message);
                }
            }
            Err(error) => {
                failed = true;
                println!("ERROR {}: {error}", check.name);
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: cargo xtask <command>");
    eprintln!("  check [NAME]       run all rule checks, or only NAME");
    eprintln!("  list               list check names");
    eprintln!("  catalog            regenerate catalogs from the local spec (OP-81)");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = workspace_root();
    match args.first().map(String::as_str) {
        Some("check") => run_checks(&root, args.get(1).map(String::as_str)),
        Some("list") => {
            for check in checks() {
                println!("{}", check.name);
            }
            ExitCode::SUCCESS
        }
        Some("catalog") => match catalog::generate(&root) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("catalog: {error}");
                ExitCode::FAILURE
            }
        },
        _ => usage(),
    }
}
