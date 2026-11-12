//! `support-policy` (OP-68, OP-159 m.3 (jj)): the supported versions table and the support policy come from the same data.
//! Pre-declared by OP-159 m.4 (a); lane J10 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `support-policy`; the slot reports nothing until lane J10 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
