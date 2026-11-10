//! The Linux client's read of a domain's head (OP-156 m.3 (p)).

use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use access_kernel::model::{ActionRef, CanonicalAuthority, Id, ResourceRef};

use super::Domains;
use crate::CoreError;
use crate::ports::{Binding, Keys, Salts};

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// The live Grants in `domain` held by a named Party that cover `action` on `resource`.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader.
    pub async fn linux_members(
        &self,
        domain: Digest,
        action: &ActionRef,
        resource: &ResourceRef,
        limit: u32,
    ) -> Result<Vec<(Id, CanonicalAuthority)>, CoreError> {
        let (guard, _) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        led.core.linux_members(action, resource, limit).await
    }
}
