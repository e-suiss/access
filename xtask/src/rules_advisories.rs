//! `advisories` (OP-159 m.3 (jj)): every advisory record is OSV-shaped and carries a CVSS v4 vector.
//! Pre-declared by OP-159 m.4 (a); lane J10 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `advisories`; the slot reports nothing until lane J10 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
