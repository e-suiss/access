//! SA-T9, SA-44, IDI-8, OP-159 m.3 (cc): the parser worker's exclusive c14n never panics, is
//! idempotent on every element subtree, and drops an excluded subtree. The worker's own modules
//! are compiled in as they are.
#![no_main]
#![allow(dead_code, unreachable_pub, reason = "the worker's modules, compiled in for fuzzing")]

#[path = "../../bins/access-parser-worker/src/c14n.rs"]
mod c14n;
#[path = "../../bins/access-parser-worker/src/dom.rs"]
mod dom;
#[path = "../../bins/access-parser-worker/src/parse.rs"]
mod parse;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (selector, xml) = data.split_first().unwrap_or((&0, &[]));
    let Ok(doc) = dom::read(xml) else {
        return;
    };
    let Ok(nodes) = doc.subtree(0) else {
        return;
    };
    let pick = |n: u8| nodes.get(usize::from(n) % nodes.len().max(1)).copied();
    let apex = pick(*selector).unwrap_or(0);
    let without = pick(selector.rotate_left(4)).filter(|w| *w != apex);
    let inclusive = [String::from("ds"), String::from("saml")];
    for prefixes in [&inclusive[..0], &inclusive[..]] {
        if let Ok(once) = c14n::canonical(&doc, apex, without, prefixes) {
            if let Ok(again) = dom::read(once.as_bytes()) {
                if without.is_none() {
                    assert_eq!(c14n::canonical(&again, 0, None, prefixes).ok(), Some(once));
                } else {
                    let _ = c14n::canonical(&again, 0, None, prefixes);
                }
            }
        }
    }
});
