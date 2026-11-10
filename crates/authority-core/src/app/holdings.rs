//! A Party's live Grants that cover one action, each with the basis that names it (OP-156
//! m.3 (l), (o)): what the SSH certificate authority drafts from and what forward-auth's
//! eligibility check names. A read: it decides nothing and changes nothing.

use access_authority_sequencer::ports::DomainLog;
use access_kernel::meta::{ExerciseBasis, GrantState, HoldingRef, kind};
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
    /// The live Grants `party` holds now whose actions cover `action`, held by name, as a
    /// member of a rule-shaped holder now, or by everyone, each with its basis and authority.
    ///
    /// # Errors
    /// The reader's errors.
    pub(crate) async fn covering(
        &self,
        party: &Id,
        action: &ActionRef,
        now: u64,
    ) -> Result<Vec<(ExerciseBasis, CanonicalAuthority)>, CoreError> {
        let candidates = self.reader.grants_for(party, None, PAGE).await?;
        let mut out = Vec::new();
        for g in candidates {
            let Some(state) = settle(&self.reader, |snap| live(snap, &g)).await? else {
                continue;
            };
            if !covers(&state.content.authority, action) {
                continue;
            }
            let holding = |since| {
                ExerciseBasis::Holding(HoldingRef {
                    grant: g,
                    holder: *party,
                    since,
                })
            };
            let basis = match &state.content.holder {
                SubjectSelector::Party(p) if p == party => Some(holding(state.since)),
                SubjectSelector::Pred(c) => {
                    let mut snap = Snapshot::default();
                    self.episode(&mut snap, c, party, now).await?.map(holding)
                }
                SubjectSelector::Public => Some(ExerciseBasis::Public(g)),
                _ => None,
            };
            if let Some(b) = basis {
                out.push((b, state.content.authority));
            }
        }
        Ok(out)
    }
}
