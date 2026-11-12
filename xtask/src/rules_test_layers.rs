//! `test-layers` (SA-59, OP-159 m.3 (bb)): every test layer names an existing recipe or CI job, and phase 0–1 layers are active.
//! Pre-declared by OP-159 m.4 (a); lane J7 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `test-layers`; the slot reports nothing until lane J7 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
