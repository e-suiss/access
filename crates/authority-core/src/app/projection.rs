//! What an authority token projection needs from the core besides its `projection.issue`
//! decision (§9.9.3 rule 4, §9.9.4, MD-10): the consequence tier of what it carries and the
//! domain-pairwise references of the parties it names.

use std::collections::{BTreeMap, BTreeSet};

use access_authority_sequencer::ports::DomainLog;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::meta::{self, InstanceState, kind};
use access_kernel::model::{ActionRef, Id, Window};
use access_kernel::tier::{self, Tier};

use crate::CoreError;
use crate::app::Authority;
use crate::ports::{Binding, Reader, Salts};

fn bare(action: &ActionRef) -> IntentEnvelope {
    IntentEnvelope {
        action: action.clone(),
        resources: Vec::new(),
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window { from: 0, until: 0 },
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The highest consequence tier among `actions`, each by its accepted Action Schema, and
    /// `intent` by its schema and amounts (§13.7.1, OP-141 m.35 (g)). `None` when one of them
    /// is a meta-action or has no accepted schema: such authority is never projected into a
    /// token (meta-actions go through AIS + `commit`, §9.9.3 rule 4).
    pub(crate) async fn projected_tier(
        &self,
        actions: &BTreeSet<ActionRef>,
        intent: Option<&IntentEnvelope>,
        now: u64,
    ) -> Result<Option<Tier>, CoreError> {
        let mut all: Vec<IntentEnvelope> = actions.iter().map(bare).collect();
        all.extend(intent.cloned());
        if all.iter().any(|i| i.action.namespace == meta::NAMESPACE) {
            return Ok(None);
        }
        let schemas = self
            .settled(|snap| {
                all.iter()
                    .map(|i| crate::domain::accepted_schema(snap, &i.action, now))
                    .collect::<Vec<_>>()
            })
            .await?;
        let mut top = Tier::Ct0;
        for (i, s) in all.iter().zip(schemas) {
            let Some(s) = s else {
                return Ok(None);
            };
            top = top.max(tier::of(i, None, false, Some(&s)));
        }
        Ok(Some(top))
    }

    /// The domain-pairwise reference of the Party of `instance` (P52, MD-10).
    pub(crate) async fn instance_ref(&self, instance: &Id) -> Result<Id, CoreError> {
        let party = self
            .settled(|snap| {
                crate::domain::read::<InstanceState>(snap, kind::INSTANCE, instance)
                    .map(|i| i.party)
            })
            .await?
            .ok_or(CoreError::Protocol("instance"))?;
        self.party_ref(&party)
    }

    /// Every Party `intent` names, with its domain-pairwise reference (P52, MD-10).
    pub(crate) fn intent_refs(
        &self,
        intent: &IntentEnvelope,
    ) -> Result<BTreeMap<Id, Id>, CoreError> {
        let mut out = BTreeMap::new();
        let named = intent
            .recipient
            .iter()
            .chain(intent.params.values().filter_map(|v| match v {
                ParamValue::Subject(p) => Some(p),
                _ => None,
            }));
        for p in named {
            out.insert(*p, self.party_ref(p)?);
        }
        Ok(out)
    }
}
