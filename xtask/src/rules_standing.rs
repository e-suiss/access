//! `no-standing-admin` (OP-54-RL10, OP-157 m.3 (j)): no migration or seed creates a standing or password-bearing admin row, and `access-server` has no emergency admin path.
//! Pre-declared by OP-157 m.4 (a); lane V5 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `no-standing-admin`; the slot reports nothing until lane V5 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
