//! `recovery-custody` (SEC20, U16, OP-158 m.3 (m)): no Access signer, HSM label or configuration holds a recovery key; recovery keys stay outside the provider.
//! Pre-declared by OP-158 m.4 (a); lane W6 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `recovery-custody`; the slot reports nothing until lane W6 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
