//! The actor binding of the identity plane's `idp.*` commits (§13.4 G54, MD-14, OP-149
//! m.16 (a)): which Party's live Instance signed an Exercise.

use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use access_kernel::model::Id;

use super::Domains;
use crate::CoreError;
use crate::ports::{Binding, Keys, Salts};

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// The Party of the live Instance of `domain` whose key signed `ais`; `None` when the key
    /// is no live Instance's there.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader.
    pub async fn signer_party(&self, domain: Digest, ais: &[u8]) -> Result<Option<Id>, CoreError> {
        let guard = self.leading(domain).await?;
        let Some(led) = guard.as_ref() else {
            return Err(CoreError::Unavailable("leader"));
        };
        led.core.signer_party(ais).await
    }

    /// The live Instances of `party` in `domain` at the head (AG-21, OP-154 m.3 (f)).
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader.
    pub async fn party_instances(&self, domain: Digest, party: Id) -> Result<Vec<Id>, CoreError> {
        let guard = self.leading(domain).await?;
        let Some(led) = guard.as_ref() else {
            return Err(CoreError::Unavailable("leader"));
        };
        led.core.live_instances_of(&party).await
    }
}
