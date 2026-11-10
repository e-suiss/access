//! One's cloud key permission's reads of a domain's head (OP-156 m.3 (w)), at the leader's
//! trusted time.

use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use access_kernel::model::Id;

use super::Domains;
use crate::CoreError;
use crate::app::one::MandateStanding;
use crate::ports::{Binding, Keys, Salts};

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// Where the Mandate `mandate` of `domain` stands now for the action `name` of `namespace`.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader.
    pub async fn mandate_standing(
        &self,
        domain: Digest,
        mandate: Id,
        action: (&str, &str),
    ) -> Result<MandateStanding, CoreError> {
        let (guard, now) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        led.core.mandate_standing(&mandate, action, now).await
    }
}
