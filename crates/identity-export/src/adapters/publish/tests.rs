#![allow(clippy::unwrap_used, reason = "test code")]

use super::*;

// OP-37, U52
#[test]
fn a_note_has_one_key_per_log_and_size() {
    assert_eq!(
        note_key("access.example/identity-audit/cell-a", 7),
        "checkpoints/access.example_identity-audit_cell-a/00000000000000000007.note"
    );
    assert_ne!(note_key("a", 7), note_key("a", 8));
}
