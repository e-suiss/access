//! `attention-model` (§8.6, OP-157 m.3 (m)): no timer or job writes an action the attention table marks as never automatic.
//! Pre-declared by OP-157 m.4 (a); lane V7 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `attention-model`; the slot reports nothing until lane V7 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
