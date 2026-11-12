//! `compliance-map` (SA-53, OP-159 m.3 (ii)): every compliance control cites catalog rows and existing tests, and makes no new claim.
//! Pre-declared by OP-159 m.4 (a); lane J9 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `compliance-map`; the slot reports nothing until lane J9 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
