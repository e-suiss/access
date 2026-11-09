//! A Party's live Instances (AG-21, OP-154 m.3 (f)): the agent registry's audit and revocation
//! unit, what an agent's `revoke-all` ends one `instance_terminate` at a time.

use access_authority_sequencer::ports::DomainLog;
use access_kernel::codec::Canonical as _;
use access_kernel::meta::{self, InstanceState, kind};
use access_kernel::model::Id;
use access_kernel::verify::cose::PublicKey;
use suiss_crypto::dcbor::Value;

use crate::CoreError;
use crate::app::Authority;
use crate::ports::{Binding, Reader, Salts};

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The live Instances of `party` at the head, in the order the domain created them.
    ///
    /// # Errors
    /// [`CoreError`] for a failed read.
    pub async fn live_instances_of(&self, party: &Id) -> Result<Vec<Id>, CoreError> {
        Ok(self
            .live_instance_states_of(party)
            .await?
            .into_iter()
            .map(|(i, _)| i)
            .collect())
    }

    /// The keys of the live Instances of `party` at the head, in the order the domain created
    /// them (OP-154 m.3 (aa)).
    ///
    /// # Errors
    /// [`CoreError`] for a failed read.
    pub async fn live_instance_keys_of(&self, party: &Id) -> Result<Vec<PublicKey>, CoreError> {
        Ok(self
            .live_instance_states_of(party)
            .await?
            .into_iter()
            .map(|(_, s)| s.key)
            .collect())
    }

    /// The Party and current key of the live Instance `instance` at the head; `None` for an
    /// ended or unknown one (L21, OP-154 m.3 (s)).
    ///
    /// # Errors
    /// [`CoreError`] for a failed read.
    pub async fn live_instance_key(
        &self,
        instance: &Id,
    ) -> Result<Option<(Id, PublicKey)>, CoreError> {
        let rows = self.fetch(&[meta::key(kind::INSTANCE, instance)]).await?;
        Ok(rows
            .into_iter()
            .next()
            .and_then(|(_, v, _)| v)
            .and_then(|v| InstanceState::from_value(&v).ok())
            .filter(|s| s.ended.is_none())
            .map(|s| (s.party, s.key)))
    }

    async fn live_instance_states_of(
        &self,
        party: &Id,
    ) -> Result<Vec<(Id, InstanceState)>, CoreError> {
        let index = self.fetch(&[meta::key(kind::INSTANCES, party)]).await?;
        let ids: Vec<Id> = match index.into_iter().next().and_then(|(_, v, _)| v) {
            Some(Value::Array(list)) => {
                list.iter().filter_map(|v| Id::from_value(v).ok()).collect()
            }
            _ => Vec::new(),
        };
        let keys: Vec<Vec<u8>> = ids.iter().map(|i| meta::key(kind::INSTANCE, i)).collect();
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let rows = self.fetch(&keys).await?;
        Ok(ids
            .into_iter()
            .zip(rows)
            .filter_map(|(i, (_, v, _))| {
                v.as_ref()
                    .and_then(|v| InstanceState::from_value(v).ok())
                    .filter(|s| s.ended.is_none() && s.party == *party)
                    .map(|s| (i, s))
            })
            .collect())
    }
}
