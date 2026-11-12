//! `constant-time-points` (CR-39, OP-159 m.3 (s)): every constant-time point names its function and the test that measures it.
//! Pre-declared by OP-159 m.4 (a); lane J4 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `constant-time-points`; the slot reports nothing until lane J4 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
