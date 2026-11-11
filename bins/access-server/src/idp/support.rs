//! Support access against the authority plane in this process (OP-157 m.3 (f), (g)): the person's
//! and the operator's own Exercises, committed as the identity plane's PEP once a live Instance of
//! the session's Party is seen to have signed them, and the facts a support Grant is drafted
//! with.

use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_identity_admin::ports::Decider as _;
use access_internal_api::idp::{Submission, Unavailable, Verdict};
use access_internal_api::support::{SupportAuthority, SupportFacts};
use access_kernel::digest::Digest;
use access_kernel::model::Id;

use super::Plane;

impl<K, B, S, C> SupportAuthority for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn commit(&self, s: Submission) -> Result<Verdict, Unavailable> {
        // §13.4 G54
        if s.actor.is_none() {
            return Err(Unavailable(String::from("actor-required")));
        }
        self.decide(s).await
    }

    async fn facts(
        &self,
        domain: Digest,
        party: Id,
        issuer: Id,
    ) -> Result<SupportFacts, Unavailable> {
        let f = self
            .domains
            .support_facts(domain, party, issuer)
            .await
            .map_err(|e| Unavailable(e.to_string()))?;
        Ok(SupportFacts {
            anchor: f.anchor,
            acceptance: f.acceptance,
        })
    }
}
