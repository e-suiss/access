//! The support access reads of a domain's head the identity plane drafts a person's support Grant
//! with (OP-157 m.3 (f)): the person's self-anchor and the case system's Acceptance.

use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use access_kernel::model::Id;

use super::Domains;
use crate::CoreError;
use crate::app::templates::support::Facts;
use crate::ports::{Binding, Keys, Salts};

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// The support [`Facts`] of `party` and the case system `issuer` in `domain`.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader.
    pub async fn support_facts(
        &self,
        domain: Digest,
        party: Id,
        issuer: Id,
    ) -> Result<Facts, CoreError> {
        let (guard, _) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        led.core.support_facts(&party, &issuer).await
    }
}
