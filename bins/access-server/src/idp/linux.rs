//! The Linux client's read of the authority plane in this process (OP-156 m.3 (p)).

use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_internal_api::idp::Unavailable;
use access_internal_api::linux::{LinuxGrants, Member};
use access_kernel::digest::Digest;
use access_kernel::model::{ActionRef, ResourceRef};

use super::Plane;

impl<K, B, S, C> LinuxGrants for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn members(
        &self,
        domain: Digest,
        action: ActionRef,
        resource: ResourceRef,
        limit: u32,
    ) -> Result<Vec<Member>, Unavailable> {
        let held = self
            .domains
            .linux_members(domain, &action, &resource, limit)
            .await
            .map_err(|e| Unavailable(e.to_string()))?;
        Ok(held
            .into_iter()
            .map(|(party, authority)| Member { party, authority })
            .collect())
    }
}
