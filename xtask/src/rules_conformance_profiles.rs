//! `conformance-profiles` (§9.1 L3, P2, OP-157 m.3 (s)): every profile under `conformance/profiles/` names only vector traces, PEP cases and CDDL files that exist.
//! Pre-declared by OP-157 m.4 (a); lane V12 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `conformance-profiles`; the slot reports nothing until lane V12 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
