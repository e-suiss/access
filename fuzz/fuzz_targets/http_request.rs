//! SA-T9, R-5, OP-159 m.3 (cc): the router's header, query and JSON body extractors never panic:
//! `traceparent`, `If-Match`, the listing query and its cursor context, and a JSON Merge Patch
//! body after the JSON limits. The router's own modules are compiled in as they are.
#![no_main]
#![allow(dead_code, unreachable_pub, reason = "the router's modules, compiled in for fuzzing")]

#[path = "../../crates/http/src/api/domain/conditional.rs"]
mod conditional;
#[path = "../../crates/http/src/api/domain/merge_patch.rs"]
mod merge_patch;
#[path = "../../crates/http/src/api/domain/page.rs"]
mod page;
#[path = "../../crates/http/src/api/domain/trace.rs"]
mod trace;

use libfuzzer_sys::fuzz_target;

const LISTED: [&str; 3] = [page::PAGE_SIZE, page::CURSOR, page::FILTER];

fuzz_target!(|data: &[u8]| {
    let (selector, rest) = data.split_first().unwrap_or((&0, &[]));
    let text = String::from_utf8_lossy(rest);
    match selector % 4 {
        0 => {
            if let Some(t) = trace::TraceContext::parse(&text) {
                assert_eq!(t.request_id().len(), 32);
            }
        }
        1 => {
            let current = conditional::etag("client", "c-1", rest);
            let _ = conditional::if_match(text.split(','), Some(&current));
            let _ = conditional::if_match(text.split(','), None);
            assert!(conditional::if_match([current.as_str()], Some(&current)).is_ok());
        }
        2 => {
            if let Ok(params) = page::parameters(Some(&text), &LISTED) {
                let _ = page::page_size(&params);
                let context = page::cursor_context("/admin/v1/realms/x/clients", "realm", &params);
                assert!(!context.is_empty());
                let link = page::next_link("/admin/v1/realms/x/clients", &params, &text);
                assert!(link.starts_with('<'));
            }
        }
        _ => {
            if access_parse::json::check(rest, 64 * 1024, 32).is_ok()
                && let Ok(patch) = serde_json::from_slice::<serde_json::Value>(rest)
            {
                let members = ["displayName", "enabled", "redirect_uris"];
                if merge_patch::check(&patch, &members).is_ok() {
                    let mut target = serde_json::json!({ "displayName": "x", "enabled": true });
                    let _ = merge_patch::apply(&mut target, &patch);
                }
            }
        }
    }
});
