//! Repository rule checks and development automation (OP-62, OP-69).

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "xtask is a developer CLI; it reports to the terminal"
)]

mod catalog;
mod civil;
mod evidence;
mod policy;
mod psirt;
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
    eprintln!("  interop-table      regenerate conformance/interop/COMPATIBILITY.md from lab.toml");
    eprintln!("  seam-dependencies  regenerate conformance/seams/DEPENDENCIES.md (PI-14)");
    eprintln!("  calibrate          measure password hashing on this host (OP-146 m.4 (f))");
    eprintln!(
        "  security-model     regenerate conformance/SECURITY-MODEL.md; --check only compares"
    );
    eprintln!(
        "  compliance-map     regenerate conformance/compliance/README.md; --check only compares"
    );
    eprintln!(
        "  evidence-pack DIR  the release evidence tarball and SHA256SUMS: [--release TAG] [--commit SHA] [--sbom FILE]..."
    );
    eprintln!(
        "  support-policy     regenerate SECURITY.md's support and fix time sections; --check only compares"
    );
    eprintln!(
        "  release-tag TAG    print the maintenance branch of a release tag of a supported minor"
    );
    eprintln!(
        "  psirt deadlines    CRA Art. 14 deadlines: --aware-at T [--fixed-at T] [--notified-at T]"
    );
    eprintln!("  advisory new ID    write an OSV advisory record and its GHSA and RustSec drafts");
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
        Some("interop-table") => match rules::interop::write_table(&root) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("interop-table: {error}");
                ExitCode::FAILURE
            }
        },
        Some("seam-dependencies") => match rules::privileged::write(&root) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("seam-dependencies: {error}");
                ExitCode::FAILURE
            }
        },
        Some("calibrate") => calibrate(&root),
        // OP-159 m.3 (gg)
        Some("security-model") => {
            match rules::security_model::write(&root, args.get(1).is_some_and(|a| a == "--check")) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("security-model: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        // SA-53, OP-159 m.3 (ii)
        Some("compliance-map") => report(
            "compliance-map",
            rules::compliance_map::write(&root, args.get(1).is_some_and(|a| a == "--check"))
                .map(|()| None),
        ),
        // OP-159 m.3 (ii), F-6
        Some("evidence-pack") => report(
            "evidence-pack",
            evidence::run(&root, args.get(1..).unwrap_or_default()).map(Some),
        ),
        // OP-68, OP-159 m.3 (jj)
        Some("support-policy") => report(
            "support-policy",
            rules::support_policy::write(&root, args.get(1).is_some_and(|a| a == "--check"))
                .map(|()| None),
        ),
        // B20, OP-68
        Some("release-tag") => report(
            "release-tag",
            args.get(1)
                .ok_or_else(|| String::from("usage: cargo xtask release-tag <tag>"))
                .and_then(|tag| rules::support_policy::release_tag(&root, tag))
                .map(Some),
        ),
        // SA-16, OP-159 m.3 (jj)
        Some("psirt") => report(
            "psirt",
            psirt::run(&root, args.get(1..).unwrap_or_default()).map(Some),
        ),
        // SA-15, OP-159 m.3 (jj)
        Some("advisory") => report(
            "advisory",
            match args.get(1).map(String::as_str) {
                Some("new") => {
                    rules::advisories::new(&root, args.get(2..).unwrap_or_default(), civil::now())
                        .map(|written| Some(written.join("\n")))
                }
                _ => Err(String::from("usage: cargo xtask advisory new <id> ...")),
            },
        ),
        _ => usage(),
    }
}

fn report(command: &str, result: Result<Option<String>, String>) -> ExitCode {
    match result {
        Ok(output) => {
            if let Some(output) = output {
                println!("{}", output.trim_end());
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{command}: {error}");
            ExitCode::FAILURE
        }
    }
}

/// OP-146 m.4 (f), OP-158 m.3 (y): runs the calibration example in release mode on this host
/// and passes its JSON report through.
fn calibrate(root: &Path) -> ExitCode {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = std::process::Command::new(cargo)
        .current_dir(root)
        .args([
            "run",
            "--quiet",
            "--release",
            "--locked",
            "-p",
            "access-identity-account",
            "--example",
            "calibrate",
        ])
        .status();
    match status {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(s) => {
            eprintln!("calibrate: {s}");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("calibrate: {error}");
            ExitCode::FAILURE
        }
    }
}
