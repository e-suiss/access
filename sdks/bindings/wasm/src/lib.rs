//! WebAssembly binding of the Access Kernel (OP-8, OP-83).

#![forbid(unsafe_code)]

use std::fmt::Write as _;

use wasm_bindgen::prelude::wasm_bindgen;

/// Kernel public API version as `"major.minor"`.
///
/// OP-8 TS profile: numbers cross into TypeScript as `bigint` or string, never `number`.
#[wasm_bindgen(js_name = apiVersion)]
#[must_use]
pub fn api_version() -> String {
    format_version(access_kernel::API_VERSION)
}

fn format_version(version: access_kernel::ApiVersion) -> String {
    let mut out = String::new();
    let _ = write!(out, "{}.{}", version.major, version.minor);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use access_kernel::ApiVersion;

    #[test]
    fn formats_kernel_api_version() {
        assert_eq!(api_version(), "0.0");
        assert_eq!(
            format_version(ApiVersion {
                major: 12,
                minor: 3
            }),
            "12.3"
        );
    }
}
