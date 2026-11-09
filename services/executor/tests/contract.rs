//! OP-65, OP-154 m.3 (u): the committed executor contract (`sdks/openapi/executor-v1.json`)
//! against the code. `ACCESS_UPDATE_CONTRACTS=1` rewrites the contract.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::path::PathBuf;

use access_executor::contract::{ROUTES, openapi};
use serde_json::Value;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi/executor-v1.json")
}

// OP-65
#[test]
fn committed_openapi_matches_the_code() {
    let mut expected = serde_json::to_string_pretty(&openapi()).unwrap();
    expected.push('\n');
    let p = path();
    if std::env::var_os("ACCESS_UPDATE_CONTRACTS").is_some() {
        std::fs::write(&p, &expected).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&p).unwrap_or_default();
    assert_eq!(
        serde_json::from_str::<Value>(&committed).ok(),
        serde_json::from_str::<Value>(&expected).ok(),
        "{} is stale; run `just executor-contract`",
        p.display()
    );
}

// OP-154 m.4
#[test]
fn every_declared_route_is_served() {
    let doc = openapi();
    for r in ROUTES {
        assert_eq!(
            doc["paths"][r.path][r.verb.name()]["x-suiss-served"],
            Value::Bool(true),
            "{}",
            r.operation
        );
    }
}

// OP-154 m.3 (u), B21, AG-40, Ek B 4600
#[test]
fn the_executor_reports_and_never_decides() {
    let text = openapi().to_string();
    for forbidden in ["allow", "decision", "grant_issue", "approve"] {
        assert!(!text.contains(&format!("\"{forbidden}\"")), "{forbidden}");
    }
}
