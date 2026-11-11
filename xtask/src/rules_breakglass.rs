//! `breakglass-isolation` (OP-46, CMP-25, G63, OP-157 m.3 (j)): `bins/access-breakglass` shares no code with `access-server` and depends on no database, Redis, signer, Relay, risk engine or MFA orchestrator.
//! Pre-declared by OP-157 m.4 (a); lane V5 fills the body.

use std::path::Path;

use crate::Violation;

/// Runs `breakglass-isolation`; the slot reports nothing until lane V5 writes its body.
#[expect(
    clippy::unnecessary_wraps,
    reason = "every Check returns a Result; the body comes with its lane"
)]
pub(crate) fn check(_root: &Path) -> Result<Vec<Violation>, String> {
    Ok(Vec::new())
}
