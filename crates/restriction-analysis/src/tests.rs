use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::*;

const SCHEMA: &str = r"
entity Actor { tenant: String };
entity Resource { tenant: String };
type Ctx = { amount: Long };
action transfer appliesTo { principal: [Actor], resource: [Resource], context: Ctx };
";

const OLD: &str = r#"
@id("cross-tenant") forbid(principal, action, resource) when { principal.tenant != resource.tenant };
@id("big") @require("rs-step-up") forbid(principal, action, resource) when { context.amount > 10 };
"#;

const NEW: &str = r#"
@id("cross-tenant") forbid(principal, action, resource) when { principal.tenant != resource.tenant };
@id("big") @require("rs-step-up") forbid(principal, action, resource) when { context.amount > 5 };
"#;

fn script(name: &str, body: &str) -> (PathBuf, [u8; 32]) {
    let dir = std::env::temp_dir().join(format!(
        "esuiss-restriction-analysis-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cvc5");
    let text = format!("#!/bin/sh\n{body}\n");
    std::fs::write(&path, &text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    (path, Sha256::digest(text.as_bytes()).into())
}

fn quick(query_ms: u64, total_ms: u64) -> Timeouts {
    Timeouts {
        query: Duration::from_millis(query_ms),
        total: Duration::from_millis(total_ms),
    }
}

/// Limits no load reaches, for a fake solver that answers or exits at once: only its own answer
/// can end the analysis, never a time limit.
fn unhurried() -> Timeouts {
    quick(300_000, 600_000)
}

fn run(cvc5: &Cvc5, old: &str, new: &str) -> Result<Verdict, AnalysisError> {
    analyze(cvc5, SCHEMA, old, new, Limits::default())
}

// OP-105
#[test]
fn binary_not_matching_the_pin_is_never_started() {
    let marker = std::env::temp_dir().join(format!(
        "esuiss-restriction-analysis-{}-started",
        std::process::id()
    ));
    let (path, hash) = script("mismatch", &format!("touch '{}'", marker.display()));
    let mut wrong = hash;
    wrong[0] ^= 1;
    let cvc5 = Cvc5::with_hash(path, wrong, quick(5_000, 10_000));
    assert_eq!(run(&cvc5, OLD, NEW), Err(AnalysisError::PinMismatch));
    assert!(!marker.exists());
}

// OP-105
#[test]
fn binary_matching_the_pin_is_accepted() {
    let (path, hash) = script("match", "exit 0");
    assert_eq!(
        Cvc5::with_hash(path, hash, Timeouts::default()).verify(),
        Ok(())
    );
}

// OP-105
#[test]
fn missing_binary_fails_closed() {
    let cvc5 = Cvc5::with_hash(
        PathBuf::from("/nonexistent/cvc5"),
        [0; 32],
        Timeouts::default(),
    );
    assert_eq!(run(&cvc5, OLD, NEW), Err(AnalysisError::SolverUnavailable));
}

// OP-105
#[test]
fn hung_solver_query_times_out() {
    let (path, hash) = script("hang-query", "exec /bin/sleep 30");
    let cvc5 = Cvc5::with_hash(path, hash, quick(200, 20_000));
    let start = std::time::Instant::now();
    assert_eq!(run(&cvc5, OLD, NEW), Err(AnalysisError::Timeout));
    assert!(start.elapsed() < Duration::from_secs(10));
}

// OP-105
#[test]
fn whole_analysis_times_out() {
    let (path, hash) = script("hang-total", "exec /bin/sleep 30");
    let cvc5 = Cvc5::with_hash(path, hash, quick(60_000, 300));
    let start = std::time::Instant::now();
    assert_eq!(run(&cvc5, OLD, NEW), Err(AnalysisError::Timeout));
    assert!(start.elapsed() < Duration::from_secs(10));
}

// OP-105
#[test]
fn crashing_solver_fails_closed() {
    let (path, hash) = script("crash", "exit 3");
    let cvc5 = Cvc5::with_hash(path, hash, unhurried());
    assert_eq!(run(&cvc5, OLD, NEW), Err(AnalysisError::Solver));
}

// OP-105
#[test]
fn solver_answering_unknown_fails_closed() {
    let (path, hash) = script(
        "unknown",
        "while read -r line; do case \"$line\" in *check-sat*) echo unknown ;; esac; done",
    );
    let cvc5 = Cvc5::with_hash(path, hash, unhurried());
    assert_eq!(run(&cvc5, OLD, NEW), Err(AnalysisError::Unknown));
}

// OP-104 m.6
#[test]
fn require_reference_change_is_widening_without_a_solver() {
    let cvc5 = Cvc5::with_hash(
        PathBuf::from("/nonexistent/cvc5"),
        [0; 32],
        Timeouts::default(),
    );
    let new = OLD.replace("rs-step-up", "rs-other");
    let Ok(Verdict::Widening(w)) = run(&cvc5, OLD, &new) else {
        panic!("expected widening");
    };
    assert_eq!(
        w.reason,
        WideningReason::RequireChanged {
            id: "big".into(),
            old: "rs-step-up".into(),
            new: "rs-other".into()
        }
    );
}

// OP-104 m.1
#[test]
fn sets_outside_the_restriction_rules_are_rejected() {
    let cvc5 = Cvc5::with_hash(PathBuf::from("/nonexistent"), [0; 32], Timeouts::default());
    let permit = r#"@id("p") permit(principal, action, resource);"#;
    assert_eq!(
        run(&cvc5, permit, NEW),
        Err(AnalysisError::Old(CompileError::PermitNotAllowed))
    );
    assert_eq!(
        run(&cvc5, OLD, permit),
        Err(AnalysisError::New(CompileError::PermitNotAllowed))
    );
}

// §5.8, OP-105
#[test]
fn compare_on_timeout_is_unknown_never_equivalent() {
    let (path, hash) = script("compare-hang", "exec /bin/sleep 30");
    let cvc5 = Cvc5::with_hash(path, hash, quick(200, 20_000));
    let start = std::time::Instant::now();
    let change = compare(&cvc5, SCHEMA, OLD, NEW, Limits::default());
    assert_eq!(change, Change::Unknown(AnalysisError::Timeout));
    assert_ne!(change, Change::Equivalent);
    assert!(start.elapsed() < Duration::from_secs(10));
    let missing = Cvc5::with_hash(
        PathBuf::from("/nonexistent/cvc5"),
        [0; 32],
        quick(200, 20_000),
    );
    assert_eq!(
        compare(&missing, SCHEMA, OLD, OLD, Limits::default()),
        Change::Unknown(AnalysisError::SolverUnavailable)
    );
}

// §5.8, OP-105
#[test]
fn compare_on_solver_unknown_is_unknown() {
    let (path, hash) = script(
        "compare-unknown",
        "while read -r line; do case \"$line\" in *check-sat*) echo unknown ;; esac; done",
    );
    let cvc5 = Cvc5::with_hash(path, hash, unhurried());
    assert_eq!(
        compare(&cvc5, SCHEMA, OLD, NEW, Limits::default()),
        Change::Unknown(AnalysisError::Unknown)
    );
}

// OP-104 m.6, §5.8
#[test]
fn compare_sees_a_require_change_as_widening_without_a_solver() {
    let cvc5 = Cvc5::with_hash(PathBuf::from("/nonexistent"), [0; 32], Timeouts::default());
    let new = OLD.replace("rs-step-up", "rs-other");
    assert!(matches!(
        compare(&cvc5, SCHEMA, OLD, &new, Limits::default()),
        Change::Widening(_)
    ));
    let permit = r#"@id("p") permit(principal, action, resource);"#;
    assert_eq!(
        compare(&cvc5, SCHEMA, OLD, permit, Limits::default()),
        Change::Unknown(AnalysisError::New(CompileError::PermitNotAllowed))
    );
}
