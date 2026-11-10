//! What forward-auth reads of the head (OP-156 m.3 (l), IDP-30): the live Grants a Party holds
//! that cover a proxy's action, each with the basis an eligibility check names and the end of
//! its validity, the decision's horizon. A read: it decides nothing and changes nothing; the
//! eligibility check decides.

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
    /// The live Grants `party` holds now whose actions cover `action`, each with its basis and
    /// the end of its validity, ms.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn proxy_bases(
        &self,
        party: &Id,
        action: &ActionRef,
        now: u64,
    ) -> Result<Vec<(ExerciseBasis, u64)>, CoreError> {
        let candidates = self.reader.grants_for(party, None, PAGE).await?;
        let mut out = Vec::new();
        for g in candidates {
            let Some(state) = settle(&self.reader, |snap| live(snap, &g)).await? else {
                continue;
            };
            let validity = state.content.authority.constraints.validity;
            if !covers(&state.content.authority, action) || validity.until <= now {
                continue;
            }
            let basis = match &state.content.holder {
                SubjectSelector::Party(p) if p == party => {
                    Some(ExerciseBasis::Holding(HoldingRef {
                        grant: g,
                        holder: *party,
                        since: state.since,
                    }))
                }
                SubjectSelector::Pred(c) => {
                    let mut snap = Snapshot::default();
                    self.episode(&mut snap, c, party, now).await?.map(|since| {
                        ExerciseBasis::Holding(HoldingRef {
                            grant: g,
                            holder: *party,
                            since,
                        })
                    })
                }
                SubjectSelector::Public => Some(ExerciseBasis::Public(g)),
                _ => None,
            };
            if let Some(b) = basis {
                out.push((b, validity.until));
            }
        }
        Ok(out)
    }
}
