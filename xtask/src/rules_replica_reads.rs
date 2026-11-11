//! `replica-reads` (OPI-2, OP-54-RL2, OP-158 m.3 (n)): no security query family is served from the read replica pool.
//! Pre-declared by OP-158 m.4 (a); lane W7 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `replica-reads`; the slot reports nothing until lane W7 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
