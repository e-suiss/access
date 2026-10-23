//! OP-103 criterion 6, OP-104 m.2.
#![no_main]

use libfuzzer_sys::fuzz_target;
use suiss_restriction::{Engine, Limits};

const SCHEMA: &str = r"
entity Actor { tenant: String, assurance: Long };
entity Resource { tenant: String, kind: String, owner?: Actor };
type Ctx = { amount: Long, lineage_depth: Long, cited_claims: Set<String>, risk: Long, new_device: Bool, now: Long };
action transfer, read appliesTo { principal: [Actor], resource: [Resource], context: Ctx };
";

fuzz_target!(|data: &[u8]| {
    if let Ok(src) = std::str::from_utf8(data) {
        let _ = Engine::compile(SCHEMA, src, Limits::default());
    }
});
