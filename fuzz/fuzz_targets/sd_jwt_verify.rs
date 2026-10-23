//! CR-55 m.7.
#![no_main]

#[path = "common.rs"]
mod common;

use access_kernel::verify::PureBackend;
use access_kernel::verify::jws::Origin;
use access_kernel::verify::sd_jwt::{Rules, verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = std::str::from_utf8(data) {
        let rules = Rules { typ: "access-pap+sd-jwt", audience: "a", nonce: "n", now: 1_000_000, skew_ms: 60_000 };
        let _ = verify(&PureBackend, p, &common::keys(), &rules, Origin::Native);
    }
});
