//! `formal-manifest` (CR-46, CR-50, MD-15, OP-159 m.3 (y)): every formal target in the manifest names existing evidence for its status.
//! Pre-declared by OP-159 m.4 (a); lane J6 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `formal-manifest`; the slot reports nothing until lane J6 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
