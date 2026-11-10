//! OP-65, OP-156 m.4, m.15 (c): the committed Access Proxy contract (`sdks/openapi/proxy-v1.json`) is
//! what the route table produces, and every reserved path is answered by Access's forward-auth check. `ACCESS_UPDATE_CONTRACTS=1` rewrites the document.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use access_proxy::contract::{ROUTES, openapi};
use serde_json::Value;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi/proxy-v1.json")
}

// OP-65, OP-156 m.4, m.15 (c)
#[test]
fn committed_openapi_matches_the_code() {
    let doc = openapi();
    for r in ROUTES {
        let op = &doc["paths"][r.path][r.verb.name()];
        assert_eq!(op["operationId"], r.operation);
        assert!(op["responses"].get("501").is_none(), "{}", r.operation);
        assert_eq!(op["x-suiss-served-by"], "/proxy/v1/check/{engine}");
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
        "{} is stale; run `just proxy-contract`",
        p.display()
    );
}
