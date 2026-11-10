//! The SSH certificate authority's reads of a domain's head (OP-156 m.3 (o)), at the leader's
//! trusted time.

use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use access_kernel::meta::HoldingRef;
use access_kernel::model::{ActionRef, CanonicalAuthority, Id};

use super::Domains;
use crate::CoreError;
use crate::ports::{Binding, Keys, Salts};

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// The live Grants of `party` in `domain` that cover `action`.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader.
    pub async fn ssh_holdings(
        &self,
        domain: Digest,
        party: Id,
        action: &ActionRef,
    ) -> Result<Vec<(HoldingRef, CanonicalAuthority)>, CoreError> {
        let (guard, now) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        led.core.ssh_holdings(&party, action, now).await
    }

    /// Whether the basis of the projection `exercise` of `domain` made stands.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader.
    pub async fn projection_standing(
        &self,
        domain: Digest,
        exercise: Digest,
    ) -> Result<Option<bool>, CoreError> {
        let (guard, _) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        led.core.projection_standing(&exercise).await
    }
}
