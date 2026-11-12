//! SA-T9, R-4, SAI-2, GHSA-r5fr-9gmv-jggh, OP-159 m.3 (cc): the SCIM filter and PATCH path
//! parsers check depth before they recurse and never panic, and the admin REST filter subset
//! accepts only named attributes.
#![no_main]

use access_parse::scim::protocol;
use libfuzzer_sys::fuzz_target;

const ATTRIBUTES: [&str; 4] = ["userName", "displayName", "emails.value", "meta.lastModified"];

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = protocol::parse(text);
    let _ = protocol::parse_path(text);
    let _ = protocol::attr_path(text);
    let _ = access_parse::scim::parse(text, &ATTRIBUTES);
});
