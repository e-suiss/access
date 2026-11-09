//! The token vault's read of an allowed Exercise (G59, U66, EI-26, OP-154 m.3 (t)): only a kept
//! receipt for exactly the presented intent answers, so an Exercise without one is no release.

use access_authority_sequencer::ports::Clock;
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::model::Id;
use access_kernel::tier::Tier;

use super::Domains;
use crate::CoreError;
use crate::ports::{Binding, Keys, Salts};

/// An allowed Exercise as a release sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseBasis {
    /// The PEP the decision was addressed to.
    pub pep: String,
    /// Position of the decision record.
    pub position: u64,
    /// The Party acted for.
    pub principal: Option<Id>,
    /// The actor Instance's Party.
    pub actor: Option<Id>,
    /// The tier from the accepted Action Schema; `None` without one.
    pub tier: Option<Tier>,
    /// Whether its basis stands now.
    pub basis_live: bool,
}

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// The allowed Exercise `exercise` of `domain` when its kept receipt is for `intent`;
    /// `None` for an Exercise never allowed, one whose receipt was not kept, or another intent.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader.
    pub async fn release_basis(
        &self,
        domain: Digest,
        exercise: Digest,
        intent: &IntentEnvelope,
    ) -> Result<Option<ReleaseBasis>, CoreError> {
        let Some(record) = self.exercise_record(domain, exercise).await? else {
            return Ok(None);
        };
        let Some(payload) = record.receipt else {
            return Ok(None);
        };
        let receipt = access_kernel::receipt::Receipt::from_bytes(&payload)
            .map_err(|_| CoreError::Protocol("receipt"))?;
        let digest = intent_digest(intent).map_err(|_| CoreError::Protocol("intent"))?;
        if receipt.intent != digest || receipt.exercise != exercise || receipt.domain != domain {
            return Ok(None);
        }
        let (guard, now) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        let facts = led.core.release_facts(&receipt, intent, now).await?;
        Ok(Some(ReleaseBasis {
            pep: receipt.audience,
            position: record.position,
            principal: facts.principal,
            actor: facts.actor,
            tier: facts.tier,
            basis_live: facts.basis_live,
        }))
    }
}
