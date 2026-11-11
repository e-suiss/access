//! `no-pending-queue` (X5, C26, OP-157 m.3 (u)): Access holds no pending-change table or queue endpoint; governance quorum lives in the coordinator.
//! Pre-declared by OP-157 m.4 (a); lane V8 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `no-pending-queue`; the slot reports nothing until lane V8 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
