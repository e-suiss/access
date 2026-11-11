//! `validity-paths` (EP-1…EP-10, OP-158 m.3 (t)): every validity path in `validity-paths.toml` declares its cache-miss, partition and restart behaviour and its staleness, and no path promises both DB-down validation and revocation within 250 ms.
//! Pre-declared by OP-158 m.4 (a); lane W8 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `validity-paths`; the slot reports nothing until lane W8 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
