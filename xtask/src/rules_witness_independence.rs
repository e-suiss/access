//! `witness-independence` (SI-12, B13, OP-158 m.3 (d)): a Domain Metadata witness set has at least two witnesses and one whose operator is independent of the provider.
//! Pre-declared by OP-158 m.4 (a); lane W2 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `witness-independence`; the slot reports nothing until lane W2 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
