//! Who signed an Exercise, for the actor binding of the identity plane's `idp.*` commits
//! (§13.4 G54, MD-14, OP-149 m.16 (a)): the Party of the live Instance whose key signed its AIS.

use access_authority_sequencer::ports::DomainLog;
use access_kernel::codec::Canonical as _;
use access_kernel::meta::{self, InstanceState, View as _, kind};
use access_kernel::model::Id;

use crate::CoreError;
use crate::app::{Authority, kid_of};
use crate::ports::{Binding, Reader, Salts};

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The Party of the live Instance whose key signed `ais`; `None` when the key is no live
    /// Instance's.
    ///
    /// # Errors
    /// [`CoreError`] for an AIS without a key id or a failed read.
    pub(crate) async fn signer_party(&self, ais: &[u8]) -> Result<Option<Id>, CoreError> {
        let kid = kid_of(ais)?;
        self.settled(|snap| {
            let id = snap
                .get(&meta::key_index(&kid))
                .and_then(|v| Id::from_value(&v).ok())?;
            crate::domain::read::<InstanceState>(snap, kind::INSTANCE, &id)
                .filter(|i| i.ended.is_none())
                .map(|i| i.party)
        })
        .await
    }
}
