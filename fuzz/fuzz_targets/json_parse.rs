//! OP-110 m.2, CR-56 row 18.
#![no_main]

use access_kernel::json::{b64url_decode, b64url_encode, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse(data, 4096);
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(bytes) = b64url_decode(s)
    {
        assert_eq!(b64url_encode(&bytes), s);
    }
});
