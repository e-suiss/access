//! `support-template` (MD-9, TN-71, OP-157 m.3 (c)): a support Grant template names no reserved or support-protected `idp.account` action.
//! Pre-declared by OP-157 m.4 (a); lane V1 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `support-template`; the slot reports nothing until lane V1 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
