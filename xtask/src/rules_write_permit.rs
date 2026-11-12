//! `write-permit` (OP-91, INV-12, OP-159 m.3 (ee)): only the authority core builds a write permit, and the permit has no public field.
//! Pre-declared by OP-159 m.4 (a); lane J7 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `write-permit`; the slot reports nothing until lane J7 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
