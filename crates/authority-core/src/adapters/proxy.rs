//! Forward-auth's reads of a domain's head (OP-156 m.3 (l)), at the leader's trusted time.

use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{ActionRef, Id};

use super::Domains;
use crate::CoreError;
use crate::ports::{Binding, Keys, Salts};

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// The live Grants of `party` in `domain` that cover `action`, with their basis and the
    /// end of their validity.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader.
    pub async fn proxy_bases(
        &self,
        domain: Digest,
        party: Id,
        action: &ActionRef,
    ) -> Result<Vec<(ExerciseBasis, u64)>, CoreError> {
        let (guard, now) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        led.core.proxy_bases(&party, action, now).await
    }
}
