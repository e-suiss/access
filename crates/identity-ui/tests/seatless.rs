//! Approvers join without a seat (§18.5, §18.7 B5, §8.17.9.5, C26, OP-157 m.3 (u), Ek B 5559):
//! the Approval Surface and the contribution path never read a seat or a license.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::Path;

fn source(relative: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(relative)).unwrap()
}

// §18.5, §18.7 B5, OP-157 m.3 (u), Ek B 5559
#[test]
fn neither_the_approval_surface_nor_the_contribution_path_asks_for_a_seat() {
    for file in [
        "src/app/approve.rs",
        "src/domain/approval.rs",
        "../authority-core/src/app/approval.rs",
    ] {
        let text = source(file).to_lowercase();
        for word in ["seat", "licens", "licenc"] {
            assert!(
                !text.contains(word),
                "{file} mentions {word:?}: an approver needs no seat (§18.5, B5)"
            );
        }
    }
}
