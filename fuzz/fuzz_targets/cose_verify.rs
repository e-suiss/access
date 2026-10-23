//! CR-55 m.6.
#![no_main]

#[path = "common.rs"]
mod common;

use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::verify_sign1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = verify_sign1(&PureBackend, data, &common::keys(), "application/access-receipt+cbor");
});
