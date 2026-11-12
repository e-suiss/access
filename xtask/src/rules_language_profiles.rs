//! `language-profiles` (MD-2, SA-20, OP-159 m.3 (dd)): every R-1…R-7 cell names an existing enforcing mechanism.
//! Pre-declared by OP-159 m.4 (a); lane J7 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `language-profiles`; the slot reports nothing until lane J7 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
