//! CR-55 m.8, CR-56.
#![no_main]

#[path = "common.rs"]
mod common;

use access_kernel::verify::PureBackend;
use access_kernel::verify::jws::{ClaimRules, Origin, check_claims, verify_compact};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(token) = std::str::from_utf8(data) {
        let _ = verify_compact(&PureBackend, token, &common::keys(), "access-receipt+jwt", Origin::External);
    }
    let rules = ClaimRules { issuer: "i", audience: "a", now: 1_000_000, skew_ms: 60_000 };
    let _ = check_claims(data, &rules);
});
