//! What the identity plane's consent record reads of a Grant (§11.6 rule 1, P58, EI-18,
//! OP-154 m.3 (k)): whether it stands at the head, who holds it, and the Party whose Instance
//! signed the `grant.issue` that created it. A read: it decides nothing and changes nothing.

use access_authority_sequencer::ports::DomainLog;
use access_kernel::algebra::{Catalog, child_within_parent};
use access_kernel::digest::Digest;
use access_kernel::meta::{self, GrantBasis, GrantContent, GrantState, HoldingRef, kind};
use access_kernel::model::{DelegationTerms, Id, SubjectSelector};

use crate::CoreError;
use crate::app::Authority;
use crate::domain::{Snapshot, read};
use crate::ports::{Binding, Reader, Salts};

/// A Grant as a consent record sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantFacts {
    /// The Grant.
    pub grant: Id,
    /// Its holder, when it is one Party.
    pub holder: Option<Id>,
    /// Whether it stands at `now`: not ended, inside its validity, every Grant above it live.
    pub live: bool,
}

/// Whether Grant `g` stands at `now` in `snap`, its lineage included (INV-5).
fn stands(snap: &Snapshot, g: &Id, now: u64) -> Option<GrantFacts> {
    let first: GrantState = read(snap, kind::GRANT, g)?;
    let holder = match first.content.holder {
        SubjectSelector::Party(p) => Some(p),
        _ => None,
    };
    let mut live = false;
    let mut at = *g;
    for _ in 0..meta::MAX_LINEAGE {
        let Some(s) = read::<GrantState>(snap, kind::GRANT, &at) else {
            break;
        };
        let v = &s.content.authority.constraints.validity;
        if s.ended.is_some() || now < v.from || v.until <= now {
            break;
        }
        match s.content.basis {
            GrantBasis::Anchor(_) => {
                live = true;
                break;
            }
            GrantBasis::Holding(h) => at = h.grant,
        }
    }
    Some(GrantFacts {
        grant: *g,
        holder,
        live,
    })
}

/// Most Grants of one Party a consent basis is looked for in.
const CONSENT_PAGE: u32 = 100;

/// The consent Grant a person issues to themselves from `parent`, which they hold since its
/// issue: the same authority, requirements and validity, passed on no further, in their own
/// capacity (§11.6, P58, OP-154 m.3 (k)); `None` when `parent` may not be passed on.
fn consent_content(
    parent: &GrantState,
    grant: Id,
    party: Id,
) -> Option<(HoldingRef, GrantContent)> {
    let p = &parent.content.authority;
    if p.delegation.depth == 0 {
        return None;
    }
    let holder = SubjectSelector::Party(party);
    let mut authority = p.clone();
    authority.delegation = DelegationTerms {
        depth: 0,
        downstream_holder_class: p.delegation.downstream_holder_class.clone(),
    };
    if !child_within_parent(&authority, p, &holder, &Catalog::default()) {
        return None;
    }
    let h = HoldingRef {
        grant,
        holder: party,
        since: parent.since,
    };
    Some((
        h,
        GrantContent {
            basis: GrantBasis::Holding(h),
            holder,
            authority,
            agency: std::collections::BTreeSet::from([access_kernel::combinator::Capacity::Own]),
            named: None,
        },
    ))
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The first Grant, by id, that `party` holds as itself at `now`, that stands and that it
    /// may pass on, with the consent Grant it would issue from it (§11.6, EI-18); `None` when
    /// it holds none.
    ///
    /// # Errors
    /// [`CoreError`] for a failed read.
    pub async fn consent_basis(
        &self,
        party: &Id,
        now: u64,
    ) -> Result<Option<(HoldingRef, GrantContent)>, CoreError> {
        let mut ids = self.reader.grants_for(party, None, CONSENT_PAGE).await?;
        ids.sort();
        for g in ids {
            let found = self
                .settled(|snap| {
                    let facts = stands(snap, &g, now)?;
                    let state: GrantState = read(snap, kind::GRANT, &g)?;
                    Some((facts, state))
                })
                .await?;
            let Some((facts, state)) = found else {
                continue;
            };
            if !facts.live || facts.holder != Some(*party) {
                continue;
            }
            if let Some(out) = consent_content(&state, g, *party) {
                return Ok(Some(out));
            }
        }
        Ok(None)
    }

    /// Grant `grant` at the head at `now`; `None` when the domain has no such Grant.
    ///
    /// # Errors
    /// [`CoreError`] for a failed read.
    pub async fn grant_facts(&self, grant: &Id, now: u64) -> Result<Option<GrantFacts>, CoreError> {
        self.settled(|snap| stands(snap, grant, now)).await
    }

    /// The Grant the `grant.issue` Exercise `exercise` created, at `now`; `None` when that
    /// Exercise created none.
    ///
    /// # Errors
    /// [`CoreError`] for a failed read.
    pub async fn issued_by(
        &self,
        exercise: &Digest,
        now: u64,
    ) -> Result<Option<GrantFacts>, CoreError> {
        let grant = meta::object_id(exercise, kind::GRANT, 0);
        self.grant_facts(&grant, now).await
    }

    /// The Party of Instance `instance`, ended or not; `None` for an unknown one.
    ///
    /// # Errors
    /// [`CoreError`] for a failed read.
    pub async fn party_of_instance(&self, instance: &Id) -> Result<Option<Id>, CoreError> {
        self.settled(|s| read::<meta::InstanceState>(s, kind::INSTANCE, instance).map(|i| i.party))
            .await
    }
}
