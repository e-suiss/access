//! The management API contract (OP-65 m.3, TN-112, OP-151 m.4): `sdks/openapi/admin-v1.json`
//! and `sdks/openapi/problems.json` are generated from code and must equal the committed files;
//! every committed contract keeps the OP-65 formats. `ACCESS_UPDATE_CONTRACTS=1` rewrites them
//! (`just admin-contract`).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use access_http::api::manifest::MANIFEST;
use access_http::api::schema::openapi;
use access_http::problem::{CODES, catalogue};
use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi")
}

fn pretty(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap();
    s.push('\n');
    s
}

fn check_file(name: &str, expected: &str) {
    let path = root().join(name);
    if std::env::var_os("ACCESS_UPDATE_CONTRACTS").is_some() {
        std::fs::write(&path, expected).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == expected,
        "{} is stale; run `just admin-contract`",
        path.display()
    );
}

// OP-65 m.3, TN-112, OP-151 m.4: generated from code, never edited by hand
#[test]
fn committed_admin_openapi_matches_the_code() {
    check_file("admin-v1.json", &pretty(&openapi()));
}

// OP-65, OP-149 m.12: the problem code catalogue is the registry
#[test]
fn committed_problem_catalogue_matches_the_registry() {
    check_file("problems.json", &pretty(&catalogue()));
    let mut seen = BTreeSet::new();
    for c in CODES {
        assert!(seen.insert(c.code), "{} listed twice", c.code);
        assert!(
            c.code
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'-' || b == b'_'),
            "{}",
            c.code
        );
        assert!((400..=599).contains(&c.status), "{}", c.code);
    }
}

// TN-113: every manifest row is an operation of the contract, with its surface and scope
#[test]
fn every_manifest_row_is_in_the_contract() {
    let doc = openapi();
    for row in MANIFEST {
        let op = &doc["paths"][row.path][row.verb.name()];
        assert_eq!(op["operationId"], row.operation_id);
        assert_eq!(op["x-access-surface"], row.surface.name());
    }
}

/// Property names a standard defines (OP-65 family 1: the standard's own spelling).
const STANDARD_NAMES: &[&str] = &["x5t#S256"];

fn snake(name: &str) -> bool {
    name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn walk(node: &Value, path: &str, out: &mut Vec<String>) {
    match node {
        Value::Object(o) => {
            if let Some(Value::Object(props)) = o.get("properties") {
                for (name, schema) in props {
                    if !snake(name) && !STANDARD_NAMES.contains(&name.as_str()) {
                        out.push(format!("{path}: property `{name}` is not snake_case"));
                    }
                    let is_string = schema.get("type") == Some(&Value::from("string"));
                    if name.ends_with("_at")
                        && is_string
                        && schema.get("format") != Some(&Value::from("date-time"))
                    {
                        out.push(format!(
                            "{path}/{name}: an RFC 3339 time needs format date-time"
                        ));
                    }
                    if (name == "position" || name.ends_with("_position"))
                        && schema.get("type") == Some(&Value::from("integer"))
                    {
                        out.push(format!("{path}/{name}: a position is a string"));
                    }
                }
            }
            let integer = match o.get("type") {
                Some(Value::String(t)) => t == "integer",
                Some(Value::Array(ts)) => ts.contains(&Value::from("integer")),
                _ => false,
            };
            if integer {
                let wide = matches!(
                    o.get("format").and_then(Value::as_str),
                    Some("int64" | "uint64")
                );
                let beyond = o
                    .get("maximum")
                    .and_then(Value::as_f64)
                    .is_some_and(|m| m > 9_007_199_254_740_991.0);
                if wide || beyond {
                    out.push(format!("{path}: a 64-bit integer is a string"));
                }
            }
            if o.get("$ref").is_none()
                && o.get("type") == Some(&Value::from("string"))
                && o.get("description")
                    .and_then(Value::as_str)
                    .is_some_and(|d| d.starts_with("RFC 3339"))
                && o.get("format") != Some(&Value::from("date-time"))
            {
                out.push(format!("{path}: an RFC 3339 time needs format date-time"));
            }
            for (k, v) in o {
                walk(v, &format!("{path}/{k}"), out);
            }
        }
        Value::Array(a) => {
            for (i, v) in a.iter().enumerate() {
                walk(v, &format!("{path}/{i}"), out);
            }
        }
        _ => {}
    }
}

// OP-65 m.4, OP-8: snake_case fields, RFC 3339 times as date-time, 64-bit integers as strings,
// across every committed API contract
#[test]
fn every_contract_keeps_the_api_formats() {
    let mut problems = Vec::new();
    let mut files = 0;
    for entry in std::fs::read_dir(root()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        files += 1;
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        walk(&doc, &name, &mut problems);
    }
    assert!(files >= 5, "the contracts were not found");
    assert!(problems.is_empty(), "{problems:#?}");
}
