//! A reviewer's campaign items, read at the domain's leader (IDP-39 (3), OP-157 m.3 (w)).

use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use access_kernel::model::Id;

use super::Domains;
use crate::CoreError;
use crate::app::review::Reviewed;
use crate::ports::{Binding, Keys, Salts};

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// The live Grants in `reviewer`'s lineage in `domain`.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader.
    pub async fn review_items(
        &self,
        domain: Digest,
        reviewer: Id,
    ) -> Result<Vec<Reviewed>, CoreError> {
        let guard = self.leading(domain).await?;
        let Some(led) = guard.as_ref() else {
            return Err(CoreError::Unavailable("leader"));
        };
        led.core.review_items(&reviewer).await
    }
}
