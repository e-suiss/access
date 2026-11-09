//! The token vault's reads of the authority plane in this process (G59, U66, OP-154 m.3 (t)):
//! an allowed Exercise's kept receipt and what the head says of it, and the operating system's
//! randomness.

use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_identity_vault::domain::release::Allowed;
use access_identity_vault::ports::{Exercises, Random, Unavailable};
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;

use super::Plane;

impl<K, B, S, C> Exercises for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn allowed(
        &self,
        domain: [u8; 32],
        exercise: [u8; 32],
        intent: &IntentEnvelope,
    ) -> Result<Option<Allowed>, Unavailable> {
        let basis = self
            .domains
            .release_basis(Digest(domain), Digest(exercise), intent)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "vault release read failed");
                Unavailable
            })?;
        Ok(basis.map(|b| Allowed {
            pep: b.pep,
            principal: b.principal.map(|p| p.0),
            actor: b.actor.map(|p| p.0),
            tier: b.tier,
            basis_live: b.basis_live,
            position: b.position,
        }))
    }
}

/// The operating system's randomness.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        for chunk in out.chunks_mut(32) {
            let b: [u8; 32] = access_crypto::random::bytes().map_err(|_| Unavailable)?;
            let n = chunk.len();
            chunk.copy_from_slice(b.get(..n).ok_or(Unavailable)?);
        }
        Ok(())
    }
}
