//! `layer-order` (GHSA-84jc-3hj2-hwc7, OP-158 m.3 (v)): authentication and limits run before the expensive extractors in every router.
//! Pre-declared by OP-158 m.4 (a); lane W11 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `layer-order`; the slot reports nothing until lane W11 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
