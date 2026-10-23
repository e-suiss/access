//! CR-10, OP-106 m.1: accepted input re-encodes to the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use suiss_crypto::dcbor::{Limits, decode, encode};

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = decode(data, Limits::CEILING) {
        assert_eq!(encode(&v, Limits::CEILING).ok().as_deref(), Some(data));
    }
});
