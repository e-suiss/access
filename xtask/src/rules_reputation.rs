//! `no-reputation-score` (MUST-NEVER-8, OP-157 m.3 (m)): Access computes no global reputation or trust score.
//! Pre-declared by OP-157 m.4 (a); lane V7 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `no-reputation-score`; the slot reports nothing until lane V7 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
