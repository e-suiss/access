//! `no-kill-switch` (CI-13, OP-157 m.3 (i)): no admin or operator path writes authority state without an Exercise, and no endpoint disables everything at once.
//! Pre-declared by OP-157 m.4 (a); lane V4 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `no-kill-switch`; the slot reports nothing until lane V4 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
