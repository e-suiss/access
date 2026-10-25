//! Rule citations written into generated conformance vectors, and the golden-file check
//! (TI-RT12).

extern crate std;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// The `"rules": [...]` member for a vector case or file header.
pub(crate) fn field(rules: &[&str]) -> String {
    let list: Vec<String> = rules.iter().map(|r| format!("\"{r}\"")).collect();
    format!("\"rules\": [{}]", list.join(", "))
}

/// Lowercase hex.
pub(crate) fn hex(b: &[u8]) -> String {
    use core::fmt::Write as _;
    b.iter().fold(String::new(), |mut h, x| {
        let _ = write!(h, "{x:02x}");
        h
    })
}

/// Writes `json` to `conformance/vectors/core/1/<file>` under `ACCESS_UPDATE_VECTORS`, else
/// asserts it equals `committed`, the file's `include_str!` content.
pub(crate) fn golden(file: &str, committed: &str, json: &str) {
    #[cfg(not(target_os = "wasi"))]
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        let path = format!(
            "{}/../../conformance/vectors/core/1/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::write(path, json).unwrap();
        return;
    }
    assert_eq!(
        committed, json,
        "{file}: run with ACCESS_UPDATE_VECTORS=1 and review the diff"
    );
}
