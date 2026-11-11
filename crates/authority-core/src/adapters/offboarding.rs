//! What offboarding a Party would touch, read at the domain's leader (§8.17.9.6, OP-157
//! m.3 (v)).

use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use access_kernel::model::Id;

use super::Domains;
use crate::CoreError;
use crate::app::offboarding::Channels;
use crate::ports::{Binding, Keys, Salts};

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// What offboarding `party` in `domain` would touch at `now`; `None` for a Party the domain
    /// does not know.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader.
    pub async fn offboarding(
        &self,
        domain: Digest,
        party: Id,
        now: u64,
    ) -> Result<Option<Channels>, CoreError> {
        let guard = self.leading(domain).await?;
        let Some(led) = guard.as_ref() else {
            return Err(CoreError::Unavailable("leader"));
        };
        led.core.offboarding(&party, now).await
    }
}
