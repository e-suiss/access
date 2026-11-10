//! OP-156 m.3 (p), m.4: the daemon's operations and answer kinds are those of
//! `conformance/cddl/linux-client.cddl`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;

use access_linux_client::contract::{KINDS, OPS};

fn cddl() -> String {
    let p =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cddl/linux-client.cddl");
    std::fs::read_to_string(p).unwrap()
}

fn quoted_after(text: &str, key: &str) -> Vec<String> {
    text.match_indices(key)
        .filter_map(|(i, _)| {
            let rest = text.get(i.checked_add(key.len())?..)?;
            let rest = rest.trim_start().strip_prefix('"')?;
            Some(rest.split('"').next()?.to_owned())
        })
        .collect()
}

// OP-156 m.3 (p)
#[test]
fn the_socket_contract_is_the_cddl() {
    let text = cddl();
    let mut ops = quoted_after(&text, "op:");
    ops.sort_unstable();
    let mut ours: Vec<_> = OPS.iter().map(|s| (*s).to_owned()).collect();
    ours.sort_unstable();
    assert_eq!(ops, ours);
    let mut kinds = quoted_after(&text, "kind:");
    kinds.sort_unstable();
    let mut ours: Vec<_> = KINDS.iter().map(|s| (*s).to_owned()).collect();
    ours.sort_unstable();
    assert_eq!(kinds, ours);
}
