//! The SSH certificate authority's reads of the authority plane in this process (OP-156 m.3
//! (o)): a Party's live `ssh.login` Grants and whether a projection's basis stands.

use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_internal_api::idp::Unavailable;
use access_internal_api::ssh::{SshGrants, SshHolding, Standing};
use access_kernel::digest::Digest;
use access_kernel::model::{ActionRef, Id};

use super::Plane;

impl<K, B, S, C> SshGrants for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn holdings(
        &self,
        domain: Digest,
        party: Id,
        action: ActionRef,
    ) -> Result<Vec<SshHolding>, Unavailable> {
        let held = self
            .domains
            .ssh_holdings(domain, party, &action)
            .await
            .map_err(|e| Unavailable(e.to_string()))?;
        Ok(held
            .into_iter()
            .map(|(holding, authority)| SshHolding { holding, authority })
            .collect())
    }

    async fn standing(&self, domain: Digest, exercise: Digest) -> Result<Standing, Unavailable> {
        match self.domains.projection_standing(domain, exercise).await {
            Ok(Some(true)) => Ok(Standing::Stands),
            Ok(Some(false)) => Ok(Standing::Ended),
            Ok(None) => Ok(Standing::Unknown),
            Err(e) => Err(Unavailable(e.to_string())),
        }
    }
}
