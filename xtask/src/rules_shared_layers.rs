//! `shared-layers` (PI-18, OP-70, OP-159 m.3 (kk)): normative text and vectors of the layers shared with Work live only under protocol and conformance.
//! Pre-declared by OP-159 m.4 (a); lane J10 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `shared-layers`; the slot reports nothing until lane J10 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
