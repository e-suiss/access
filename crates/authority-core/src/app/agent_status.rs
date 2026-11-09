//! The ADP search kind `agent-status` (A-11, §9.7, E26, OP-154 m.3 (w)): an agent Instance's
//! own summary. It names that Instance, whether it is live, its Mandate and the Grants its Party
//! holds, each with what it covers, its horizon and the budget left in its current window.
//! Nothing about any other Party's delegations is in it, the principal's included. Advisory and
//! never recorded, like every search (A-10, C30).

use access_authority_sequencer::ports::DomainLog;
use access_kernel::codec::Canonical;
use access_kernel::meta::{self, Actor, GrantState, InstanceState, MandateState, View as _, kind};
use access_kernel::model::{ActionRef, BudgetDimension, Id};
use suiss_crypto::dcbor::Value;

use crate::CoreError;
use crate::app::Authority;
use crate::domain::{budget_key, read};
use crate::ports::{Binding, Reader, Salts};

/// What is left of one budget.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BudgetLeft {
    /// `count`, or the amount's unit.
    pub dimension: String,
    /// The window's capacity, releases included.
    pub capacity: u64,
    /// What is left.
    pub remaining: u64,
}

/// One Grant the agent's Party holds.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeldGrant {
    /// The Grant.
    pub grant: Id,
    /// The actions it covers now.
    pub actions: Vec<ActionRef>,
    /// Its horizon.
    pub until: u64,
    /// Its budgets.
    pub budgets: Vec<BudgetLeft>,
}

/// The agent Instance's summary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentStatus {
    /// The Instance.
    pub instance: Id,
    /// Its Party.
    pub party: Id,
    /// Whether the Instance is live.
    pub live: bool,
    /// The actions its live Mandate names and its horizon.
    pub mandate: Option<(Vec<ActionRef>, u64)>,
    /// The Grants its Party holds.
    pub holdings: Vec<HeldGrant>,
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The status of `actor`'s own Instance at `now`; `None` when the actor is not an agent.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn agent_status(
        &self,
        actor: &Actor,
        now: u64,
    ) -> Result<Option<AgentStatus>, CoreError> {
        let (agent, live, mandate) = self
            .settled(|snap| {
                let agent = meta::actor_is_agent(snap, &actor.party);
                let live = read::<InstanceState>(snap, kind::INSTANCE, &actor.instance)
                    .is_some_and(|i| i.ended.is_none() && i.party == actor.party);
                let ids = match snap.get(&meta::key(kind::MANDATES, &actor.instance)) {
                    Some(Value::Array(ids)) => ids,
                    _ => Vec::new(),
                };
                let mandate = ids.iter().find_map(|id| {
                    let id = Id::from_value(id).ok()?;
                    let m: MandateState = read(snap, kind::MANDATE, &id)?;
                    m.ended.is_none().then(|| {
                        let a = &m.envelope.authority.actions;
                        (
                            a.exact.iter().cloned().collect::<Vec<_>>(),
                            m.envelope.constraints.validity.until,
                        )
                    })
                });
                (agent, live, mandate)
            })
            .await?;
        if !agent {
            return Ok(None);
        }
        let mut holdings = Vec::new();
        for h in self.holdings(actor, now).await? {
            let Some(g) = self
                .settled(|snap| read::<GrantState>(snap, kind::GRANT, &h.grant))
                .await?
            else {
                continue;
            };
            let mut budgets = Vec::new();
            for (i, term) in g.content.authority.constraints.budget.iter().enumerate() {
                let (key, _) = budget_key(&h.grant, i, term.window, now);
                let used = self.counter(&key).await?;
                let capacity = term
                    .capacity
                    .saturating_add(self.counter(&meta::released_key(&key)).await?);
                budgets.push(BudgetLeft {
                    dimension: match &term.dimension {
                        BudgetDimension::Count => String::from("count"),
                        BudgetDimension::Amount(u) => u.clone(),
                    },
                    capacity,
                    remaining: capacity.saturating_sub(used),
                });
            }
            holdings.push(HeldGrant {
                grant: h.grant,
                actions: h.actions,
                until: g.content.authority.constraints.validity.until,
                budgets,
            });
        }
        Ok(Some(AgentStatus {
            instance: actor.instance,
            party: actor.party,
            live,
            mandate,
            holdings,
        }))
    }
}
