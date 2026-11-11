//! `tofu-infra-only` (OP-158 m.3 (p)): `deploy/tofu/**` provisions infrastructure only and makes no `idp.*` or ADP call.
//! Pre-declared by OP-158 m.4 (a); lane W9 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `tofu-infra-only`; the slot reports nothing until lane W9 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
