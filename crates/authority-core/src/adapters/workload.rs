//! A trust domain's acceptance as the identity plane reads it (OP-154 m.3 (r), AG-30).

use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use access_kernel::model::Id;

use super::Domains;
use crate::CoreError;
use crate::ports::{Binding, Keys, Salts};

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// Whether a live Acceptance of `domain` lets `issuer` sign `class` for `use_` now.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader or trusted time.
    pub async fn issuer_accepted(
        &self,
        domain: Digest,
        issuer: Id,
        (use_, class): (&str, &str),
    ) -> Result<bool, CoreError> {
        let mut guard = self.leading(domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        let now = led
            .clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        led.core.issuer_accepted(&issuer, (use_, class), now).await
    }
}
