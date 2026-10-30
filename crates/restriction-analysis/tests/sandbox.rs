//! The pinned cvc5 inside the solver sandbox (OP-115 m.6). Ignored unless the pinned solver is
//! configured: run `just smt-test`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use suiss_sandbox::{LandlockAbi, Lockdown, Profile};

const NEEDS: &str = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`";

fn solver() -> PathBuf {
    let Some(path) = std::env::var_os("ACCESS_CVC5") else {
        panic!("ACCESS_CVC5 is not set: {NEEDS}");
    };
    PathBuf::from(path)
}

fn confine(command: &mut Command, solver: &Path) -> std::io::Result<()> {
    Lockdown::new(Profile::Solver, LandlockAbi::REQUIRED)
        .allow_execute(solver)
        .confine(command)
        .map_err(std::io::Error::other)
}

fn run(script: &str, confined: bool) -> std::io::Result<Output> {
    let solver = solver();
    let mut cmd = Command::new(&solver);
    cmd.env_clear()
        .current_dir("/")
        .args(["--lang", "smt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if confined {
        confine(&mut cmd, &solver)?;
    }
    let mut child = cmd.spawn()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    child.wait_with_output()
}

const SAT: &str =
    "(set-logic QF_LIA)\n(declare-const x Int)\n(assert (> x 1))\n(check-sat)\n(exit)\n";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "esuiss-restriction-analysis-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// OP-115 m.6
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn pinned_cvc5_answers_inside_the_solver_sandbox() {
    let out = run(SAT, true).unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "sat");
}

// OP-115 m.6
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn pinned_cvc5_cannot_create_files_inside_the_solver_sandbox() {
    let dir = scratch("write");
    let open = dir.join("unconfined.out");
    let shut = dir.join("confined.out");
    let script = |path: &Path| {
        format!(
            "(set-option :regular-output-channel \"{}\")\n{SAT}",
            path.display()
        )
    };
    let out = run(&script(&open), false).unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read_to_string(&open).unwrap().trim(), "sat");

    let out = run(&script(&shut), true).unwrap();
    assert!(
        !shut.exists(),
        "the confined solver created {shut:?}: {out:?}"
    );
}

// OP-90, OP-115 m.6
#[test]
#[cfg(not(target_os = "linux"))]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn solver_does_not_start_without_its_sandbox() {
    use esuiss_restriction_analysis::{AnalysisError, Cvc5, Limits, Timeouts, analyze};
    let _ = (run, SAT, scratch);
    let schema = "entity A; entity R; action go appliesTo { principal: [A], resource: [R] };";
    let old = r#"@id("x") forbid(principal, action, resource);"#;
    let new = r#"@id("y") forbid(principal, action, resource) when { false };"#;
    let cvc5 = Cvc5::pinned(solver(), Timeouts::default(), confine).unwrap();
    assert_eq!(
        analyze(&cvc5, schema, old, new, Limits::default()),
        Err(AnalysisError::Sandbox)
    );
}
