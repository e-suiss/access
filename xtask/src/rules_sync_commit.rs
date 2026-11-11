//! `sync-commit` (OP-54-RL6, OP-158 m.3 (n)): security writes run with `synchronous_commit = on`; only the OPERATIONAL telemetry connection uses `local`.
//! Pre-declared by OP-158 m.4 (a); lane W7 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `sync-commit`; the slot reports nothing until lane W7 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
