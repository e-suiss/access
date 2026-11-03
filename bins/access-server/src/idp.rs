//! The in-process seam between the planes for `idp.*` (OP-62, MD-14, TN-111): the identity
//! plane's ports, served by the authority core of this process.

use std::sync::Arc;

use access_authority_core::CoreError;
use access_authority_core::adapters::{Domains, OsSalts};
use access_authority_core::app::Incoming;
use access_authority_core::domain::Request;
use access_authority_core::genesis;
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::adapters::create_genesis;
use access_authority_sequencer::ports::Clock;
use access_identity_admin::ports::{Decider, Governance};
use access_internal_api::idp::{
    Committed, GenesisOpened, GenesisOrder, Submission, Unavailable, Verdict,
};
use access_kernel::combinator::{Mode, Outcome};
use access_kernel::digest::Digest;
use access_store::Pool;
use access_store::authority::find_nonce;
use access_store::scope::DomainId;

/// The authority plane as the identity plane's [`Decider`] and [`Governance`].
pub(crate) struct Plane<K, B: Binding, S: Salts, C> {
    domains: Arc<Domains<K, B, S, C>>,
    sequencer: Pool,
    app: Pool,
    clock: C,
}

impl<K, B: Binding, S: Salts, C> Plane<K, B, S, C> {
    /// Over the domains this process leads.
    pub(crate) const fn new(
        domains: Arc<Domains<K, B, S, C>>,
        sequencer: Pool,
        app: Pool,
        clock: C,
    ) -> Self {
        Self {
            domains,
            sequencer,
            app,
            clock,
        }
    }
}

fn refused(e: &CoreError) -> Verdict {
    Verdict::Refused {
        code: String::from(e.code()),
    }
}

impl<K, B, S, C> Decider for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn decide(&self, s: Submission) -> Result<Verdict, Unavailable> {
        let domain = s.domain;
        let nonce = s.nonce.clone();
        let inc = Incoming {
            request: Request {
                domain,
                mode: Mode::Commit,
                nonce: s.nonce,
                intent: s.intent,
                payload: None,
                basis: s.basis,
                capacity: s.capacity,
                proofs: Vec::new(),
                exercise: None,
                consistency: None,
            },
            ais: Some(s.ais),
            pep: s.pep,
            explain: false,
        };
        let r = match self.domains.exercise(&inc).await {
            Ok(r) => r,
            Err(e) => return Ok(refused(&e)),
        };
        if r.decision.outcome != Outcome::Allow {
            return Ok(Verdict::NotAllowed {
                decision: r.decision,
                position: r.record,
            });
        }
        let (Some(exercise), Some(_)) = (r.exercise, r.record) else {
            return Err(Unavailable(String::from("allow-without-record")));
        };
        // EI-25: what is bound is the nonce's recorded ALLOW, read back from the log
        let row = find_nonce(&self.app, &DomainId::from_bytes(domain.0), &nonce)
            .await
            .map_err(|e| Unavailable(e.to_string()))?
            .filter(|n| n.outcome == "allow")
            .ok_or_else(|| Unavailable(String::from("allow-not-recorded")))?;
        Ok(Verdict::Committed(Committed {
            domain,
            nonce,
            position: row.decision_pos,
            intent: Digest(row.intent_digest),
            exercise,
            replayed: r.replayed,
        }))
    }
}

impl<K, B, S, C> Governance for Plane<K, B, S, C>
where
    K: Send + Sync,
    B: Binding + Send + Sync,
    S: Salts + Send + Sync,
    C: Clock + Clone + Send + Sync,
{
    async fn open(&self, order: GenesisOrder) -> Result<GenesisOpened, Unavailable> {
        let fields =
            genesis::realm(&order, &mut OsSalts).map_err(|e| Unavailable(e.to_string()))?;
        // OP-129 m.1
        let now = self
            .clock
            .clone()
            .now()
            .await
            .map_err(|e| Unavailable(e.to_string()))?;
        let domain = create_genesis(&self.sequencer, order.tenant, fields, now)
            .await
            .map_err(|e| Unavailable(e.to_string()))?;
        Ok(GenesisOpened { domain })
    }
}

#[cfg(test)]
mod tests;
