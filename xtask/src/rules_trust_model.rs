//! `trust-model` (SEC5, SA-7, OP-159 m.3 (gg)): the trust model names every component with what it is trusted with and what contains it.
//! Pre-declared by OP-159 m.4 (a); lane J8 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `trust-model`; the slot reports nothing until lane J8 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
