//! OP-65, CMP-16: the committed experience contract (`sdks/openapi/experience-v1.json`) against
//! the code. `ACCESS_UPDATE_CONTRACTS=1` rewrites it.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::path::PathBuf;

use access_experience::contract::openapi;
use serde_json::Value;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi/experience-v1.json")
}

// OP-65, CMP-16
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
        "{} is stale; run `just experience-contract`",
        p.display()
    );
}

// XI-3, IA-2, OP-153 m.3 (v)
#[test]
fn the_contract_has_no_write_route() {
    let doc = openapi();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            let read = method == "get" || path.ends_with("/hub") || path.ends_with("/hub/plan");
            assert!(read, "{method} {path}");
        }
    }
    let text = doc.to_string();
    for forbidden in ["action_required", "pending", "queued", "commit"] {
        assert!(
            !text.contains(&format!("\"{forbidden}\"")),
            "{forbidden} in the contract"
        );
    }
}
