//! The committed hosted Frontend API document (`sdks/openapi/frontend-v1.json`) is what the
//! route table produces (OP-65, TN-133, OP-153 m.4). `ACCESS_UPDATE_CONTRACTS=1` rewrites it.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_identity_ui::domain::frontend_v1::{ROUTES, openapi};

mod support;

use support::{check_file, pretty, root};

// OP-65, OP-153 m.4, TN-112
#[test]
fn committed_frontend_v1_matches_the_route_table() {
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
    check_file(&root().join("frontend-v1.json"), &pretty(&doc));
}
