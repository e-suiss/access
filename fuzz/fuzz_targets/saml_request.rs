//! §10.6.1, IDI-8, RUSTSEC-2024-0437: the parser worker's SAML request reader and exclusive
//! c14n never panic and never accept a message they cannot read back from one tree. The worker's
//! own modules are compiled in as they are.
#![no_main]
#![allow(dead_code, unreachable_pub, reason = "the worker's modules, compiled in for fuzzing")]

#[path = "../../bins/access-parser-worker/src/c14n.rs"]
mod c14n;
#[path = "../../bins/access-parser-worker/src/dom.rs"]
mod dom;
#[path = "../../bins/access-parser-worker/src/dsig.rs"]
mod dsig;
#[path = "../../bins/access-parser-worker/src/parse.rs"]
mod parse;
#[path = "../../bins/access-parser-worker/src/saml.rs"]
mod saml;

use access_edge_core::saml::Context;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(doc) = dom::read(data) {
        if let Ok(once) = c14n::canonical(&doc, 0, None, &[]) {
            if let Ok(again) = dom::read(once.as_bytes()) {
                assert_eq!(c14n::canonical(&again, 0, None, &[]).ok(), Some(once));
            }
        }
    }
    let ctx = Context {
        inflate: data.first().is_some_and(|b| b & 1 == 1),
        certs: Vec::new(),
        require_signature: false,
    };
    if let Ok(input) = ctx.encode(data) {
        let _ = saml::request(&input);
    }
});
