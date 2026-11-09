//! What a token vault release needs of an allowed Exercise (G59, U66, EI-26, OP-154 m.3 (t)):
//! from its receipt and the head, the Party it acted for, the actor's Party, its consequence
//! tier from the accepted Action Schema, and whether its basis still stands. A read: it decides
//! nothing and changes nothing.

use access_authority_sequencer::ports::DomainLog;
use access_kernel::combinator::Capacity;
use access_kernel::intent::IntentEnvelope;
use access_kernel::model::Id;
use access_kernel::receipt::Receipt;
use access_kernel::tier::{self, Tier};

use crate::CoreError;
use crate::app::Authority;
use crate::ports::{Binding, Reader, Salts};

/// What the head says of an allowed Exercise's receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseFacts {
    /// The Party acted for: the principal of `for(P)`, else the actor Instance's Party.
    pub principal: Option<Id>,
    /// The actor Instance's Party.
    pub actor: Option<Id>,
    /// The tier from the accepted Action Schema of the intent's action; `None` without one.
    pub tier: Option<Tier>,
    /// Whether the receipt's basis stands now (INV-5).
    pub basis_live: bool,
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The release facts of `receipt`, for the intent it was allowed for, at `now`.
    ///
    /// # Errors
    /// [`CoreError`] for a failed read.
    pub async fn release_facts(
        &self,
        receipt: &Receipt,
        intent: &IntentEnvelope,
        now: u64,
    ) -> Result<ReleaseFacts, CoreError> {
        let actor = match &receipt.instance {
            Some(i) => self.instance_party(i).await.ok(),
            None => None,
        };
        let principal = match receipt.capacity {
            Capacity::For(p) => Some(p),
            Capacity::Own => actor,
        };
        let schema = self
            .settled(|snap| crate::domain::accepted_schema(snap, &intent.action, now))
            .await?;
        let tier = schema.map(|s| tier::of(intent, None, false, Some(&s)));
        let basis_live = self.basis_live(&receipt.basis).await?;
        Ok(ReleaseFacts {
            principal,
            actor,
            tier,
            basis_live,
        })
    }
}
