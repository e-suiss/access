//! What the Linux client reads of the head (OP-156 m.3 (p), IDP-32): the named holders of live
//! Grants that cover an action on a resource, from the derived index's candidates. A read: it
//! decides nothing and changes nothing.

use access_authority_sequencer::ports::DomainLog;
use access_kernel::algebra::resource_le;
use access_kernel::combinator::HopStatus;
use access_kernel::meta::{GrantState, kind};
use access_kernel::model::{
    ActionRef, CanonicalAuthority, Id, ResourceRef, ResourceSelector, SubjectSelector,
};

use crate::CoreError;
use crate::app::Authority;
use crate::app::publishing::settle;
use crate::domain::{Snapshot, lineage_hops, read};
use crate::ports::{Binding, Reader, Salts};

/// Most Grants one index page holds.
const PAGE: u32 = 100;

fn live(view: &Snapshot, grant: &Id) -> Option<GrantState> {
    let (hops, _) = lineage_hops(view, grant)?;
    if hops.iter().all(|h| h.status == HopStatus::Active) {
        read(view, kind::GRANT, grant)
    } else {
        None
    }
}

fn covers(authority: &CanonicalAuthority, action: &ActionRef, resource: &ResourceRef) -> bool {
    let set = &authority.authority;
    let acts = set.actions.exact.contains(action)
        || set
            .actions
            .prefix
            .iter()
            .any(|(n, _)| *n == action.namespace);
    acts && resource_le(&ResourceSelector::Exact(resource.clone()), &set.resource)
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The live Grants held by a named Party that cover `action` on `resource`, at most
    /// `limit`, each with its holder.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn linux_members(
        &self,
        action: &ActionRef,
        resource: &ResourceRef,
        limit: u32,
    ) -> Result<Vec<(Id, CanonicalAuthority)>, CoreError> {
        let mut out = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .reader
                .grants_in(&resource.namespace, after, PAGE)
                .await?;
            for g in &page {
                let Some(state) = settle(&self.reader, |snap| live(snap, g)).await? else {
                    continue;
                };
                if !covers(&state.content.authority, action, resource) {
                    continue;
                }
                if let SubjectSelector::Party(p) = state.content.holder {
                    out.push((p, state.content.authority));
                    if out.len() >= usize::try_from(limit).unwrap_or(usize::MAX) {
                        return Ok(out);
                    }
                }
            }
            if page.len() < PAGE as usize {
                return Ok(out);
            }
            after = page.last().copied();
        }
    }
}
