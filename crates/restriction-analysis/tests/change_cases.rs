//! The OQ-MD2 spike change cases against the pinned cvc5 (OP-105). Ignored unless the pinned
//! solver is configured: run `just smt-test`. The solver runs only inside its Linux sandbox
//! (OP-115 m.6, OP-90).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::Path;
#[cfg(target_os = "linux")]
use std::time::Duration;

use access_sandbox::{LandlockAbi, Lockdown, Profile};
#[cfg(target_os = "linux")]
use esuiss_restriction_analysis::Side;
use esuiss_restriction_analysis::{
    AnalysisError, Cvc5, Limits, Timeouts, Verdict, Widening, WideningReason, analyze,
};

#[cfg(target_os = "linux")]
const NEEDS: &str = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`";

const SCHEMA: &str = r"
entity Actor { tenant: String, assurance: Long };
entity Resource { tenant: String, kind: String, owner?: Actor };
type Ctx = { amount: Long, lineage_depth: Long, risk: Long, new_device: Bool };
action transfer, read appliesTo { principal: [Actor], resource: [Resource], context: Ctx };
";

const OLD: &str = r#"
@id("cross-tenant") forbid(principal, action, resource) when { principal.tenant != resource.tenant };
@id("big-transfer") @require("rs-step-up")
forbid(principal, action == Action::"transfer", resource) when { context.amount > 10000 };
@id("risky") @require("rs-fresh-auth")
forbid(principal, action, resource) when { context.risk >= 70 || context.new_device };
@id("deep-lineage") forbid(principal, action, resource) when { context.lineage_depth > 3 };
"#;

/// The solver profile (OP-115 m.6), as the analysis binary wires it.
fn confine(command: &mut std::process::Command, solver: &Path) -> std::io::Result<()> {
    Lockdown::new(Profile::Solver, LandlockAbi::REQUIRED)
        .allow_execute(solver)
        .confine(command)
        .map_err(std::io::Error::other)
}

#[cfg(target_os = "linux")]
fn cvc5() -> Cvc5 {
    let Some(path) = std::env::var_os("ACCESS_CVC5") else {
        panic!("ACCESS_CVC5 is not set: {NEEDS}");
    };
    Cvc5::pinned(
        path,
        Timeouts {
            query: Duration::from_secs(60),
            total: Duration::from_secs(300),
        },
        confine,
    )
    .unwrap()
}

#[cfg(target_os = "linux")]
fn check(new: &str) -> Result<Verdict, AnalysisError> {
    analyze(&cvc5(), SCHEMA, OLD, new, Limits::default())
}

fn edit(from: &str, to: &str) -> String {
    assert!(OLD.contains(from), "{from}");
    OLD.replace(from, to)
}

fn widening(v: Result<Verdict, AnalysisError>) -> Widening {
    match v {
        Ok(Verdict::Widening(w)) => w,
        other => panic!("expected widening, got {other:?}"),
    }
}

// OP-105
#[test]
fn binary_other_than_the_pinned_cvc5_is_refused() {
    let sh = Cvc5::pinned("/bin/sh", Timeouts::default(), confine).unwrap();
    assert_eq!(
        analyze(&sh, SCHEMA, OLD, OLD, Limits::default()),
        Err(AnalysisError::PinMismatch)
    );
}

// OP-105
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn same_set_is_equivalent() {
    assert_eq!(check(OLD), Ok(Verdict::Equivalent));
}

// OP-105
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn a_tightened_thresholds_and_new_require_is_narrowing() {
    let new = edit("> 10000", "> 5000").replace("> 3", "> 2")
        + r#"@id("kyc") @require("rs-claim-kyc") forbid(principal, action, resource) when { context.amount > 100 };"#;
    assert_eq!(check(&new), Ok(Verdict::Narrowing));
}

// OP-105
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn a2_require_to_deny_is_narrowing() {
    let new = edit(
        r#"@id("risky") @require("rs-fresh-auth")"#,
        r#"@id("risky")"#,
    );
    assert_eq!(check(&new), Ok(Verdict::Narrowing));
}

// OP-105
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn b1_dropped_disjunct_is_widening_of_the_requirement() {
    let w = widening(check(&edit(" || context.new_device", "")));
    assert_eq!(
        w.reason,
        WideningReason::Require {
            reference: "rs-fresh-auth".into()
        }
    );
    assert!(w.counterexample.is_some());
}

// OP-105
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn b2_deleted_forbid_is_widening_with_a_counterexample() {
    let w = widening(check(&edit(
        r#"@id("deep-lineage") forbid(principal, action, resource) when { context.lineage_depth > 3 };"#,
        "",
    )));
    assert_eq!(w.reason, WideningReason::Deny);
    let cex = w.counterexample.unwrap();
    assert!(cex.request.contains("lineage_depth"), "{cex:?}");
}

// OP-105
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn b3_deny_to_require_is_widening() {
    let w = widening(check(&edit(
        r#"@id("cross-tenant")"#,
        r#"@id("cross-tenant") @require("rs-step-up")"#,
    )));
    assert_eq!(w.reason, WideningReason::Deny);
}

// OP-104 m.6
#[test]
fn b4_changed_require_reference_is_widening_before_any_solver_run() {
    let unused = Cvc5::pinned("/nonexistent/cvc5", Timeouts::default(), confine).unwrap();
    let new = edit(r#"@require("rs-step-up")"#, r#"@require("rs-step-up-v2")"#);
    let w = widening(analyze(&unused, SCHEMA, OLD, &new, Limits::default()));
    assert_eq!(
        w.reason,
        WideningReason::RequireChanged {
            id: "big-transfer".into(),
            old: "rs-step-up".into(),
            new: "rs-step-up-v2".into()
        }
    );
}

// OP-104 m.6
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn b4_requirement_moved_to_another_policy_is_widening() {
    let new = edit(
        r#"@id("big-transfer") @require("rs-step-up")"#,
        r#"@id("big-transfer-v2") @require("rs-step-up-v2")"#,
    );
    let w = widening(check(&new));
    assert_eq!(
        w.reason,
        WideningReason::Require {
            reference: "rs-step-up".into()
        }
    );
}

// OP-105
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn b5_extra_conjunct_is_widening() {
    let w = widening(check(&edit(
        "context.lineage_depth > 3",
        "context.lineage_depth > 3 && context.risk > 0",
    )));
    assert_eq!(w.reason, WideningReason::Deny);
}

// OP-105
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn c_equivalent_rewrite_is_equivalent() {
    let new = r#"
@id("deep") forbid(principal, action, resource) when { !(context.lineage_depth <= 3) };
@id("risky-device") @require("rs-fresh-auth") forbid(principal, action, resource) when { context.new_device };
@id("tenant") forbid(principal, action, resource) when { resource.tenant != principal.tenant };
@id("big-transfer") @require("rs-step-up")
forbid(principal, action == Action::"transfer", resource) when { context.amount >= 10001 };
@id("risky") @require("rs-fresh-auth") forbid(principal, action, resource) unless { context.risk < 70 };
"#;
    assert_eq!(check(new), Ok(Verdict::Equivalent));
}

// OP-104 m.5
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn d_policy_that_can_overflow_is_reported() {
    let new = OLD.to_owned()
        + r#"@id("overflow") forbid(principal, action, resource) when { context.amount * 1000000000000 < 0 };"#;
    match check(&new) {
        Ok(Verdict::MayError(e)) => {
            assert_eq!((e.side, e.id.as_str()), (Side::New, "overflow"));
            assert!(e.counterexample.is_some());
        }
        other => panic!("expected MayError, got {other:?}"),
    }
}

// OP-104 m.5
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn d_old_set_that_can_error_is_reported() {
    let old = OLD.to_owned()
        + r#"@id("overflow") forbid(principal, action, resource) when { context.amount * 1000000000000 < 0 };"#;
    match analyze(&cvc5(), SCHEMA, &old, OLD, Limits::default()) {
        Ok(Verdict::MayError(e)) => assert_eq!(e.side, Side::Old),
        other => panic!("expected MayError, got {other:?}"),
    }
}

// OP-105
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn e_optional_entity_attribute_is_narrowing() {
    let new = OLD.to_owned()
        + r#"@id("owner-assurance") forbid(principal, action, resource) when { resource has owner && resource.owner.assurance < 1 };"#;
    assert_eq!(check(&new), Ok(Verdict::Narrowing));
}
