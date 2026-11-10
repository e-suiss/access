//! OP-65, OP-155 m.3 (p), m.4: the committed verifier contract (`sdks/openapi/vc-verifier-v1.json`)
//! is what the route table produces. `ACCESS_UPDATE_CONTRACTS=1` rewrites the document.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use access_vc_verifier::contract::{ROUTES, openapi};
use serde_json::Value;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi/vc-verifier-v1.json")
}

// OP-65, OP-155 m.4
#[test]
fn committed_openapi_matches_the_code() {
    let doc = openapi();
    for r in ROUTES {
        let op = &doc["paths"][r.path][r.verb.name()];
        assert_eq!(op["operationId"], r.operation);
        assert_eq!(
            op["responses"].get("501").is_some(),
            !r.live,
            "{}",
            r.operation
        );
    }
    let ops: BTreeSet<_> = ROUTES.iter().map(|r| r.operation).collect();
    assert_eq!(ops.len(), ROUTES.len());
    let mut expected = serde_json::to_string_pretty(&doc).unwrap();
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
        "{} is stale; run `just vc-verifier-contract`",
        p.display()
    );
}
