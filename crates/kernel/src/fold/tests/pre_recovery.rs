//! `recovery/1/pre-recovery.json`: `nonce-closed/pre-recovery` (TI-RT3, U28, SEC22 R1 (c)).

use alloc::format;
use alloc::vec::Vec;

use super::super::*;
use crate::vector_rules::{field, golden_in};

// TI-RT3, U28, Ek B 6121
#[test]
fn pre_recovery_vectors_match() {
    let at = 5_000;
    let cases = [
        (
            "issued-before-with-an-unknown-nonce-is-closed",
            4_999,
            false,
        ),
        ("issued-before-with-a-known-nonce-re-commits", 4_999, true),
        ("issued-at-the-recovery-is-open", 5_000, false),
        ("issued-after-is-open", 6_000, false),
    ];
    let mut lines = Vec::new();
    for (id, iat, known) in cases {
        let closed = pre_recovery(iat, at, known);
        lines.push(format!(
            "  {{\"id\": \"{id}\", {}, \"iat\": {iat}, \"recovered_at\": {at}, \"nonce_known\": {known}, \"closed\": {closed}}}",
            field(&["TI-RT3", "U28"]),
        ));
    }
    assert!(pre_recovery(1, 2, false) && !pre_recovery(1, 2, true));
    let json = format!(
        "{{\n \"rule\": \"OP-158\",\n \"track\": \"recovery\",\n \"version\": 1,\n \"operation\": \"recovery.pre_recovery\",\n \"cases\": [\n{}\n ]\n}}\n",
        lines.join(",\n")
    );
    golden_in(
        "recovery/1",
        "pre-recovery.json",
        include_str!("../../../../../conformance/vectors/recovery/1/pre-recovery.json"),
        &json,
    );
}
