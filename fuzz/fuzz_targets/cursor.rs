//! SA-T9, OP-155 m.3 (g), TN-112, OP-159 m.3 (cc): the SCIM cursor reader never panics, opens
//! only cursors of its own list, and the listing cursor context binds the query it came from.
#![no_main]
#![allow(dead_code, unreachable_pub, reason = "the router's module, compiled in for fuzzing")]

#[path = "../../crates/http/src/api/domain/page.rs"]
mod page;
#[path = "../../crates/http/src/api/domain/trace.rs"]
mod trace;

use std::sync::OnceLock;

use access_crypto::scim_cursor::CursorKey;
use libfuzzer_sys::fuzz_target;

fn key() -> Option<&'static CursorKey> {
    static KEY: OnceLock<Option<CursorKey>> = OnceLock::new();
    KEY.get_or_init(|| CursorKey::generate().ok()).as_ref()
}

fuzz_target!(|data: &[u8]| {
    let Some(key) = key() else {
        return;
    };
    let now = 1_800_000_000_000_u64;
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = key.open(b"Users", text, now);
        if let Ok(params) = page::parameters(Some(text), &[page::PAGE_SIZE, page::CURSOR]) {
            let a = page::cursor_context("/scim/v2/Users", "scim", &params);
            let b = page::cursor_context("/scim/v2/Groups", "scim", &params);
            assert_ne!(a, b);
        }
    }
    let sealed = key.seal(b"Users", data, now);
    assert_eq!(key.open(b"Users", &sealed, now).ok().as_deref(), Some(data));
    assert!(key.open(b"Groups", &sealed, now).is_err());
});
