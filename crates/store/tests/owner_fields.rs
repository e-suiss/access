//! Owner fields are fixed at creation (TN-Y2, §12.5.2, TN-114, C16, OP-157 m.3 (t), Ek B 5453):
//! no store update path moves a passkey, a refresh token or a directory app password (API key)
//! to another subject, so an update can never hand a credential to someone else.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::Path;

const CREDENTIAL_TABLES: [&str; 3] = [
    "webauthn_credentials",
    "oauth_refresh_tokens",
    "ldap_credentials",
];

const OWNER_COLUMNS: [&str; 3] = ["subject_id", "owner_id", "holder"];

fn rs_files(dir: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(std::fs::read_to_string(&path).unwrap());
        }
    }
}

/// The SET list of each `UPDATE access.<table>` in `source`.
fn set_lists<'a>(source: &'a str, table: &str) -> Vec<&'a str> {
    let needle = format!("UPDATE access.{table}");
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = source.get(from..).and_then(|s| s.find(&needle)) {
        let start = from + i + needle.len();
        let rest = &source[start..];
        let end = rest
            .find("WHERE")
            .or_else(|| rest.find('"'))
            .unwrap_or(rest.len());
        out.push(&rest[..end]);
        from = start;
    }
    out
}

// TN-Y2, §12.5.2, C16, OP-157 m.3 (t), Ek B 5453
#[test]
fn no_update_path_changes_a_credentials_owner() {
    let mut sources = Vec::new();
    rs_files(
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut sources,
    );
    assert!(!sources.is_empty());
    let mut updates = 0;
    for source in &sources {
        for table in CREDENTIAL_TABLES {
            for set in set_lists(source, table) {
                updates += 1;
                for column in OWNER_COLUMNS {
                    assert!(
                        !set.contains(column),
                        "an update of access.{table} touches its owner field {column}: {set}"
                    );
                }
            }
        }
    }
    assert!(
        updates > 0,
        "the store still updates credentials: the scan found none"
    );
}
