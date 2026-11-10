//! What the realm's SSH certificate authority reads of the head (OP-156 m.3 (o), IDP-32): a
//! Party's live Grants that cover `ssh.login`, with the episode a `holding` basis names, and
//! whether a projection's basis still stands. Reads: they decide nothing and change nothing.

use access_authority_sequencer::ports::DomainLog;
use access_kernel::digest::Digest;
use access_kernel::meta::{self, GrantState, HoldingRef, View as _, kind};
use access_kernel::model::{ActionRef, CanonicalAuthority, Id, SubjectSelector};

use crate::CoreError;
use crate::app::Authority;
use crate::app::publishing::settle;
use crate::domain::{Snapshot, lineage_hops, read};
use crate::ports::{Binding, Reader, Salts};

/// Most Grants one read walks.
const PAGE: u32 = 100;

fn live(view: &Snapshot, grant: &Id) -> Option<GrantState> {
    let (hops, _) = lineage_hops(view, grant)?;
    if hops
        .iter()
        .all(|h| h.status == access_kernel::combinator::HopStatus::Active)
    {
        read(view, kind::GRANT, grant)
    } else {
        None
    }
}

fn covers(authority: &CanonicalAuthority, action: &ActionRef) -> bool {
    let set = &authority.authority.actions;
    set.exact.contains(action) || set.prefix.iter().any(|(n, _)| *n == action.namespace)
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The live Grants `party` holds now whose actions cover `action`, each with the
    /// `holding` basis that names it.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn ssh_holdings(
        &self,
        party: &Id,
        action: &ActionRef,
        now: u64,
    ) -> Result<Vec<(HoldingRef, CanonicalAuthority)>, CoreError> {
        let candidates = self.reader.grants_for(party, None, PAGE).await?;
        let mut out = Vec::new();
        for g in candidates {
            let Some(state) = settle(&self.reader, |snap| live(snap, &g)).await? else {
                continue;
            };
            if !covers(&state.content.authority, action) {
                continue;
            }
            let since = match &state.content.holder {
                SubjectSelector::Party(p) if p == party => Some(state.since),
                SubjectSelector::Pred(c) => {
                    let mut snap = Snapshot::default();
                    self.episode(&mut snap, c, party, now).await?
                }
                _ => None,
            };
            let Some(since) = since else { continue };
            out.push((
                HoldingRef {
                    grant: g,
                    holder: *party,
                    since,
                },
                state.content.authority,
            ));
        }
        Ok(out)
    }

    /// Whether the basis of the projection that `exercise` made stands now; `None` when the
    /// head holds no such projection.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn projection_standing(&self, exercise: &Digest) -> Result<Option<bool>, CoreError> {
        let key = meta::exercise_key(kind::PROJECTION, exercise);
        let basis = self
            .settled(|snap| {
                let v = snap.get(&key)?;
                meta::exercise_basis(v.get("basis")?).ok()
            })
            .await?;
        match basis {
            None => Ok(None),
            Some(b) => self.basis_live(&b).await.map(Some),
        }
    }
}
