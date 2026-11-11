//! `degraded-paths` (TI-9, SEC27, SI-22, OP-158 m.3 (s)): degraded mode is only the TI-9/SEC27/SI-22 paths; no fail-open, grace-window or allow-on-error pattern and no error branch that returns ALLOW.
//! Pre-declared by OP-158 m.4 (a); lane W8 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `degraded-paths`; the slot reports nothing until lane W8 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
