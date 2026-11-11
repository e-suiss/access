//! Access review and inventory hygiene on the authority side (IDP-39 (3), LFP-18, XI-19,
//! §8.17.12, OP-157 m.3 (w)). Both are reads: they decide nothing and change nothing.
//!
//! - A campaign's items are the live Grants in the reviewer's own lineage: issued from one of
//!   the reviewer's holdings, or under an Anchor the reviewer roots, at any depth. A reviewer
//!   never sees another manager's team. Removing an item is the reviewer's own `grant.revoke`.
//! - Hygiene marks a delegation that was not used for [`UNUSED_DAYS`] days, ends within
//!   [`EXPIRING_DAYS`] days, or is broad (any resource of a namespace, an action prefix, or
//!   onward delegation). A mark is a suggestion only; nothing changes by itself.

use std::collections::{BTreeMap, BTreeSet};

use access_authority_sequencer::ports::DomainLog;
use access_kernel::codec::Canonical;
use access_kernel::meta::{
    self, AnchorState, ExerciseBasis, GrantBasis, GrantState, HoldingRef, Root, kind,
};
use access_kernel::model::{
    ActionRef, CanonicalAuthority, Id, ResourceSelector, SubjectSelector, Window,
};
use access_kernel::record::{RecordEnvelope, RecordKind};
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;
use crate::app::Authority;
use crate::app::hub::{Hygiene, LOG_WINDOW};
use crate::app::publishing::settle;
use crate::domain::{Snapshot, lineage_hops, read};
use crate::ports::{Binding, Reader, Salts};

/// A delegation not used for this many days is marked unused (PD).
pub const UNUSED_DAYS: u64 = 90;

/// A delegation that ends within this many days is marked expiring (PD).
pub const EXPIRING_DAYS: u64 = 7;

const DAY_MS: u64 = 86_400_000;

/// One item of a campaign: a live Grant in the reviewer's lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reviewed {
    /// The Grant.
    pub grant: Id,
    /// Who holds it.
    pub holder: SubjectSelector,
    /// What it allows.
    pub actions: Vec<ActionRef>,
    /// On what.
    pub resource: ResourceSelector,
    /// When.
    pub validity: Window,
    /// The position it was issued at.
    pub since: u64,
    /// The holding or Anchor it was issued from.
    pub basis: GrantBasis,
    /// Whether it may be passed on.
    pub delegable: bool,
    /// How many live Grants derive from it: what removing it would also end.
    pub derived: u64,
    /// The basis the reviewer revokes it on: the reviewer's holding it derives from, or the
    /// Anchor the reviewer roots.
    pub via: ExerciseBasis,
}

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

fn prefix_of(k: &str) -> Vec<u8> {
    let mut p = meta::key(k, &Id([0; 16]));
    p.truncate(p.len().saturating_sub(16));
    p
}

fn id_of_key(key: &[u8]) -> Option<Id> {
    match dcbor::decode(key, Limits::CEILING).ok()? {
        Value::Array(items) => Id::from_value(items.get(1)?).ok(),
        _ => None,
    }
}

fn roots(root: &Root, party: &Id) -> bool {
    match root {
        Root::Sole(p) => p == party,
        Root::Joint { parties, .. } => parties.contains(party),
    }
}

/// The Grants above `grant` in `grants`, nearest first, and the Anchor its lineage starts at
/// when every Grant on the way is known.
fn ancestors(grants: &BTreeMap<Id, GrantState>, grant: &Id) -> (Vec<(Id, Id)>, Option<Id>) {
    let mut out = Vec::new();
    let mut at = *grant;
    for _ in 0..meta::MAX_LINEAGE {
        let Some(s) = grants.get(&at) else {
            return (out, None);
        };
        match s.content.basis {
            GrantBasis::Anchor(a) => return (out, Some(a)),
            GrantBasis::Holding(h) => {
                out.push((h.grant, h.holder));
                at = h.grant;
            }
        }
    }
    (out, None)
}

/// The basis `reviewer` revokes `grant` on when it is in the reviewer's lineage (IDP-39 (3)):
/// the nearest Grant on the way up issued from the reviewer's holding, or the Anchor the
/// lineage starts at when the reviewer roots it; `None` outside the lineage.
#[must_use]
pub fn lineage_basis(
    grants: &BTreeMap<Id, GrantState>,
    rooted: &BTreeSet<Id>,
    reviewer: &Id,
    grant: &Id,
) -> Option<ExerciseBasis> {
    let (up, anchor) = ancestors(grants, grant);
    if let Some((g, _)) = up.iter().find(|(_, holder)| holder == reviewer) {
        return Some(ExerciseBasis::Holding(HoldingRef {
            grant: *g,
            holder: *reviewer,
            since: grants.get(g)?.since,
        }));
    }
    anchor
        .filter(|a| rooted.contains(a))
        .map(ExerciseBasis::Anchor)
}

/// Whether `grant` is in `reviewer`'s lineage (IDP-39 (3)).
#[must_use]
pub fn in_lineage(
    grants: &BTreeMap<Id, GrantState>,
    rooted: &BTreeSet<Id>,
    reviewer: &Id,
    grant: &Id,
) -> bool {
    lineage_basis(grants, rooted, reviewer, grant).is_some()
}

/// Whether `authority` is broad (§8.17.12): any resource of a namespace, an action prefix, or
/// onward delegation.
#[must_use]
pub fn broad(authority: &CanonicalAuthority) -> bool {
    let wildcard = match &authority.authority.resource {
        ResourceSelector::Exact(_) => false,
        ResourceSelector::Structural(s) => {
            s.prefix.is_empty() && s.kind.is_none() && s.attrs.is_empty()
        }
    };
    wildcard || !authority.authority.actions.prefix.is_empty() || authority.delegation.depth > 0
}

/// The hygiene marks of `grant` at `now` (XI-19): `issued_at` is when it was issued, `used` whether
/// an allowed use cites it inside the window the log was read over, and `covered` whether that
/// window reaches back [`UNUSED_DAYS`] days. `None` when nothing is marked.
#[must_use]
pub fn marks(
    grant: Id,
    state: &GrantState,
    now: u64,
    issued_at: Option<u64>,
    (used, covered): (bool, bool),
) -> Option<Hygiene> {
    let a = &state.content.authority;
    let until = a.constraints.validity.until;
    let expiring = until > now && until - now <= EXPIRING_DAYS.saturating_mul(DAY_MS);
    let old =
        issued_at.is_some_and(|t| now.saturating_sub(t) >= UNUSED_DAYS.saturating_mul(DAY_MS));
    let unused = old && covered && !used;
    let broad = broad(a);
    (expiring || unused || broad).then_some(Hygiene {
        grant,
        unused,
        expiring,
        broad,
    })
}

/// The Grants allowed uses cited in the last [`LOG_WINDOW`] records, and whether that window
/// reaches back [`UNUSED_DAYS`] days before `now`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecentUses {
    /// Grants an allowed use rested on.
    pub grants: BTreeSet<Id>,
    /// Whether the window covers the unused period.
    pub covered: bool,
}

fn field<'a>(r: &'a RecordEnvelope, name: &str) -> Option<&'a Value> {
    r.fields.get(name).map(|f| &f.value)
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// Every live Grant with its state, and the Anchors `party` roots.
    async fn grants_and_roots(
        &self,
        party: &Id,
    ) -> Result<(BTreeMap<Id, GrantState>, BTreeSet<Id>), CoreError> {
        let mut rooted = BTreeSet::new();
        for (key, value, _) in self.scan(&prefix_of(kind::ANCHOR)).await? {
            let (Some(anchor), Some(v)) = (id_of_key(&key), value) else {
                continue;
            };
            if let Ok(s) = AnchorState::from_value(&v)
                && s.ended.is_none()
                && roots(&s.root, party)
            {
                rooted.insert(anchor);
            }
        }
        let mut grants = BTreeMap::new();
        for (key, value, _) in self.scan(&prefix_of(kind::GRANT)).await? {
            let (Some(grant), Some(_)) = (id_of_key(&key), value) else {
                continue;
            };
            if let Some(state) = settle(&self.reader, |snap| live(snap, &grant)).await? {
                grants.insert(grant, state);
            }
        }
        Ok((grants, rooted))
    }

    /// The items of `reviewer`'s campaign now (IDP-39 (3), OP-157 m.3 (w)): every live Grant in
    /// the reviewer's lineage that the reviewer does not hold by name, oldest first.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn review_items(&self, reviewer: &Id) -> Result<Vec<Reviewed>, CoreError> {
        let (grants, rooted) = self.grants_and_roots(reviewer).await?;
        let mut derived: BTreeMap<Id, u64> = BTreeMap::new();
        for g in grants.keys() {
            for (up, _) in ancestors(&grants, g).0 {
                let n = derived.entry(up).or_default();
                *n = n.saturating_add(1);
            }
        }
        let mut out: Vec<Reviewed> = grants
            .iter()
            .filter(|(_, s)| s.content.holder != SubjectSelector::Party(*reviewer))
            .filter_map(|(g, s)| {
                let via = lineage_basis(&grants, &rooted, reviewer, g)?;
                let a = &s.content.authority;
                Some(Reviewed {
                    grant: *g,
                    holder: s.content.holder.clone(),
                    actions: a.authority.actions.exact.iter().cloned().collect(),
                    resource: a.authority.resource.clone(),
                    validity: a.constraints.validity,
                    since: s.since,
                    basis: s.content.basis,
                    delegable: a.delegation.depth > 0,
                    derived: derived.get(g).copied().unwrap_or(0),
                    via,
                })
            })
            .collect();
        out.sort_by_key(|r| (r.since, r.grant));
        Ok(out)
    }

    /// The allowed uses of the last [`LOG_WINDOW`] records at `now` (§8.17.12).
    ///
    /// # Errors
    /// The reader's errors.
    pub(crate) async fn recent_uses(&self, now: u64) -> Result<RecentUses, CoreError> {
        let last = self.reader.position_at(now).await?.unwrap_or(0);
        if last == 0 {
            return Ok(RecentUses {
                grants: BTreeSet::new(),
                covered: true,
            });
        }
        let first = last.saturating_sub(LOG_WINDOW.saturating_sub(1)).max(1);
        let covered = first == 1
            || self
                .reader
                .recorded_at(first)
                .await?
                .is_some_and(|t| now.saturating_sub(t) >= UNUSED_DAYS.saturating_mul(DAY_MS));
        let mut opened: BTreeMap<Vec<u8>, Id> = BTreeMap::new();
        let mut grants = BTreeSet::new();
        let mut from = first;
        while from <= last {
            let to = from.saturating_add(255).min(last);
            for bytes in self.reader.log(from, to).await? {
                let r = RecordEnvelope::from_bytes(&bytes)
                    .map_err(|_| CoreError::Protocol("record"))?;
                let Some(Value::Bytes(nonce)) = field(&r, "nonce") else {
                    continue;
                };
                match r.header.kind {
                    RecordKind::Opening => {
                        if let Some(meta::ExerciseBasis::Holding(h)) =
                            field(&r, "basis").and_then(|v| meta::exercise_basis(v).ok())
                        {
                            opened.insert(nonce.clone(), h.grant);
                        }
                    }
                    RecordKind::Decision => {
                        let allowed = matches!(
                            field(&r, "outcome").and_then(|o| o.get("outcome")),
                            Some(Value::Text(t)) if t == "allow"
                        );
                        if allowed && let Some(g) = opened.get(nonce) {
                            grants.insert(*g);
                        }
                    }
                    _ => {}
                }
            }
            from = to.saturating_add(1);
        }
        Ok(RecentUses { grants, covered })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::arithmetic_side_effects,
        reason = "test code"
    )]

    use access_kernel::meta::{GrantContent, HoldingRef};
    use access_kernel::model::{
        ActionSet, AuthoritySet, ConstraintSet, DelegationTerms, ResourceRef, Structural,
    };

    use super::*;

    fn authority(resource: ResourceSelector, depth: u64, until: u64) -> CanonicalAuthority {
        CanonicalAuthority {
            authority: AuthoritySet {
                actions: ActionSet::default(),
                resource,
                params: BTreeMap::new(),
                recipient: None,
                purpose: None,
            },
            constraints: ConstraintSet {
                validity: Window { from: 0, until },
                conditions: BTreeSet::new(),
                budget: BTreeSet::new(),
            },
            delegation: DelegationTerms {
                depth,
                downstream_holder_class: None,
            },
            requirements: BTreeSet::new(),
        }
    }

    fn exact() -> ResourceSelector {
        ResourceSelector::Exact(ResourceRef {
            namespace: String::from("payroll.record"),
            path: vec![String::from("r-1")],
            incarnation: 0,
        })
    }

    // XI-19, §8.17.12, OP-157 m.3 (w)
    #[test]
    fn hygiene_marks_unused_expiring_and_broad_and_changes_nothing() {
        let now = 400 * DAY_MS;
        let quiet = authority(exact(), 0, u64::MAX);
        let mark = |a: &CanonicalAuthority, issued: Option<u64>, used: (bool, bool)| {
            let s = GrantState {
                content: GrantContent {
                    basis: GrantBasis::Anchor(Id([1; 16])),
                    holder: SubjectSelector::Party(Id([2; 16])),
                    authority: a.clone(),
                    agency: BTreeSet::new(),
                    named: None,
                },
                ..sample()
            };
            marks(Id([3; 16]), &s, now, issued, used)
        };
        assert_eq!(mark(&quiet, Some(now - DAY_MS), (false, true)), None);
        let old = mark(&quiet, Some(now - 91 * DAY_MS), (false, true)).unwrap();
        assert!(old.unused && !old.expiring && !old.broad);
        assert_eq!(mark(&quiet, Some(now - 91 * DAY_MS), (true, true)), None);
        assert_eq!(
            mark(&quiet, Some(now - 91 * DAY_MS), (false, false)),
            None,
            "unproven is never marked"
        );
        let ending = authority(exact(), 0, now + 2 * DAY_MS);
        assert!(mark(&ending, Some(now), (false, true)).unwrap().expiring);
        let ended = authority(exact(), 0, now - 1);
        assert_eq!(mark(&ended, Some(now), (false, true)), None);
        let any = authority(
            ResourceSelector::Structural(Structural {
                namespace: String::from("payroll.record"),
                prefix: Vec::new(),
                kind: None,
                attrs: BTreeMap::new(),
            }),
            0,
            u64::MAX,
        );
        assert!(mark(&any, Some(now), (false, true)).unwrap().broad);
        let onward = authority(exact(), 1, u64::MAX);
        assert!(mark(&onward, Some(now), (false, true)).unwrap().broad);
    }

    fn sample() -> GrantState {
        GrantState {
            content: GrantContent {
                basis: GrantBasis::Anchor(Id([0; 16])),
                holder: SubjectSelector::Public,
                authority: authority(exact(), 0, u64::MAX),
                agency: BTreeSet::new(),
                named: None,
            },
            since: 1,
            revision: 0,
            ended: None,
        }
    }

    // IDP-39 (3), OP-157 m.3 (w)
    #[test]
    fn a_reviewer_sees_only_its_own_lineage() {
        let (root_anchor, a, b, x, y) = (
            Id([1; 16]),
            Id([2; 16]),
            Id([3; 16]),
            Id([4; 16]),
            Id([5; 16]),
        );
        let (ga, gb, gx, gy) = (Id([10; 16]), Id([11; 16]), Id([12; 16]), Id([13; 16]));
        let from = |grant, holder| {
            GrantBasis::Holding(HoldingRef {
                grant,
                holder,
                since: 1,
            })
        };
        let mut grants = BTreeMap::new();
        let with = |basis, holder| GrantState {
            content: GrantContent {
                basis,
                holder: SubjectSelector::Party(holder),
                ..sample().content
            },
            ..sample()
        };
        grants.insert(ga, with(GrantBasis::Anchor(root_anchor), a));
        grants.insert(gb, with(GrantBasis::Anchor(root_anchor), b));
        grants.insert(gx, with(from(ga, a), x));
        grants.insert(gy, with(from(gb, b), y));
        let none = BTreeSet::new();
        assert!(in_lineage(&grants, &none, &a, &gx));
        assert!(
            !in_lineage(&grants, &none, &a, &gy),
            "another manager's team"
        );
        assert!(
            !in_lineage(&grants, &none, &a, &ga),
            "the reviewer's own Grant"
        );
        let rooted = BTreeSet::from([root_anchor]);
        assert!(
            in_lineage(&grants, &rooted, &Id([9; 16]), &gy),
            "the root sees all"
        );
    }
}
