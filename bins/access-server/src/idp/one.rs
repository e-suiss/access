//! One's cloud key permissions against the authority plane in this process (OP-156 m.3 (w),
//! E59): the device Instance's own Exercise, committed as the identity plane's PEP once a live
//! Instance of the session's Party is seen to have signed it, and where a Mandate stands.

use access_authority_core::app::one::MandateStanding as Core;
use access_authority_core::domain::Request;
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_internal_api::idp::{ACTOR_BINDING, Unavailable, Verdict};
use access_internal_api::one::{CloudKeyAuthority, CloudKeyExercise, MandateStanding};
use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::model::Id;

use super::{Plane, verdict};

impl<K, B, S, C> CloudKeyAuthority for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn commit(&self, e: CloudKeyExercise) -> Result<Verdict, Unavailable> {
        // §13.4 G54, E59 (2)
        match self.domains.signer_party(e.domain, &e.ais).await {
            Ok(Some(p)) if p == e.actor => {}
            Ok(_) => {
                return Ok(Verdict::Refused {
                    code: String::from(ACTOR_BINDING),
                    errors: Vec::new(),
                });
            }
            Err(err) => return verdict(&err),
        }
        let request = Request {
            domain: e.domain,
            mode: Mode::Commit,
            nonce: e.nonce,
            intent: e.intent,
            payload: None,
            basis: e.basis,
            capacity: e.capacity,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        };
        self.commit(request, e.ais, (e.pep, None)).await
    }

    async fn mandate(
        &self,
        domain: Digest,
        mandate: Id,
        action: (&str, &str),
    ) -> Result<MandateStanding, Unavailable> {
        match self.domains.mandate_standing(domain, mandate, action).await {
            Ok(Core::Covers(until)) => Ok(MandateStanding::Covers(until)),
            Ok(Core::Ended) => Ok(MandateStanding::Ended),
            Ok(Core::Unknown) => Ok(MandateStanding::Unknown),
            Err(e) => Err(Unavailable(e.to_string())),
        }
    }
}
