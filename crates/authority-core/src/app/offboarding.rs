//! Joiner, mover and leaver on the authority side (IDP-35, C13, TN-75, TN-109, INV-31, E6,
//! §8.17.9.6, OP-157 m.3 (v)). A read: it decides nothing and changes nothing.
//!
//! - A baseline Grant is a rule-shaped Grant whose holder is a predicate over the HR source's
//!   `hr_department` and `hr_title` Claims: a joiner is selected once the HR Claim lands, a mover
//!   leaves the old selection at once and enters the new one after the HR cooling.
//! - When a selection falls, the holder's episode ends (INV-31); a rejoin is a new episode and
//!   never revives what the old one carried.
//! - What offboarding a Party would touch is read channel by channel: Grants held by name,
//!   running Instances, rule-shaped holdings that still select it, its self-anchor with the
//!   Grants it gave, and the rule-shaped holdings that already ended. Nothing has a default.

use std::collections::BTreeSet;

use access_authority_sequencer::ports::DomainLog;
use access_kernel::meta::{GrantBasis, GrantState, PartyState, kind};
use access_kernel::model::{Conjunct, EqValue, Id, SubjectSelector};

use crate::CoreError;
use crate::app::Authority;
use crate::app::hub::Selection;
use crate::app::publishing::settle;
use crate::domain::{Snapshot, lineage_hops, read};
use crate::ports::{Binding, Reader, Salts};

/// The HR Claim class a department baseline selects on (IDP-35, OP-156 m.3 (q)).
pub const HR_DEPARTMENT: &str = "hr_department";

/// The HR Claim class a title baseline selects on.
pub const HR_TITLE: &str = "hr_title";

/// The holder of a baseline Grant (IDP-35 (2), C13): everyone whose HR record says department
/// `department` and, when named, title `title`; `None` when neither is named or one is empty.
#[must_use]
pub fn baseline_holder(department: Option<&str>, title: Option<&str>) -> Option<SubjectSelector> {
    let mut conjuncts = BTreeSet::new();
    for (class, value) in [(HR_DEPARTMENT, department), (HR_TITLE, title)] {
        let Some(v) = value else { continue };
        if v.trim().is_empty() {
            return None;
        }
        conjuncts.insert(Conjunct {
            claim_class: String::from(class),
            value: Some(EqValue::Text(String::from(v))),
        });
    }
    (!conjuncts.is_empty()).then_some(SubjectSelector::Pred(conjuncts))
}

/// A rule-shaped holding that still selects the Party (C13): retain, exclude or restrict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleHolding {
    /// The Grant.
    pub grant: Id,
    /// Its holder's conjuncts.
    pub conjuncts: BTreeSet<Conjunct>,
    /// The episode's first position.
    pub since: u64,
    /// Whether a statement the Grant requires is older than it allows (stale, never removed).
    pub stale: bool,
}

/// A rule-shaped holding whose episode already ended (INV-31): "E's Finance role ended (HR,
/// 6 Oct)". Shown, never chosen for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ended {
    /// The Grant.
    pub grant: Id,
    /// Its holder's conjuncts.
    pub conjuncts: BTreeSet<Conjunct>,
    /// The closing record's position, when a record closed it.
    pub pos: Option<u64>,
    /// When it closed, Unix ms, when known.
    pub at: Option<u64>,
    /// The issuer of the last statement that selected the Party.
    pub issuer: Option<Id>,
}

/// What offboarding `party` would touch now (§8.17.9.6, E6, OP-157 m.3 (v)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Channels {
    /// The Party's self-anchor.
    pub anchor: Option<Id>,
    /// The position of its departure, once it departed.
    pub departed: Option<u64>,
    /// Live Grants held by the Party by name: keep or revoke. HR's change never touches them.
    pub direct: Vec<Id>,
    /// Its live Instances: terminate.
    pub instances: Vec<Id>,
    /// Rule-shaped holdings that select it now.
    pub holdings: Vec<RuleHolding>,
    /// Live Grants on its self-anchor: the departure retires the anchor and revokes them; a
    /// handover keeps them under the new root.
    pub given: Vec<Id>,
    /// Live Grants derived from one of its holdings, with that holding's Grant: they end with
    /// the holding (cascade), or stay while a kept direct Grant carries them.
    pub derived: Vec<(Id, Id)>,
    /// Rule-shaped holdings whose episode ended.
    pub ended: Vec<Ended>,
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

fn grant_of_key(key: &[u8]) -> Option<Id> {
    use suiss_crypto::dcbor::{self, Limits, Value};
    match dcbor::decode(key, Limits::CEILING).ok()? {
        Value::Array(items) => access_kernel::codec::Canonical::from_value(items.get(1)?).ok(),
        _ => None,
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// What offboarding `party` would touch at `now`, channel by channel; `None` for a Party the
    /// domain does not know.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn offboarding(&self, party: &Id, now: u64) -> Result<Option<Channels>, CoreError> {
        let Some(p) = settle(&self.reader, |snap| {
            read::<PartyState>(snap, kind::PARTY, party)
        })
        .await?
        else {
            return Ok(None);
        };
        let mut out = Channels {
            anchor: Some(p.anchor),
            departed: p.ended.map(|e| e.at),
            instances: self.live_instances_of(party).await?,
            ..Channels::default()
        };
        let mut prefix = access_kernel::meta::key(kind::GRANT, &Id([0; 16]));
        prefix.truncate(prefix.len().saturating_sub(16));
        for (key, value, _) in self.scan(&prefix).await? {
            let (Some(grant), Some(_)) = (grant_of_key(&key), value) else {
                continue;
            };
            let Some(state) = settle(&self.reader, |snap| live(snap, &grant)).await? else {
                continue;
            };
            let c = &state.content;
            match &c.holder {
                SubjectSelector::Party(h) if h == party => out.direct.push(grant),
                SubjectSelector::Pred(conjuncts) => {
                    // C13, INV-31
                    match self.selection(&state, conjuncts, party, now).await? {
                        (Some(Selection::Current { since }), _) => {
                            out.holdings.push(RuleHolding {
                                grant,
                                conjuncts: conjuncts.clone(),
                                since,
                                stale: false,
                            });
                        }
                        (Some(Selection::Stale { since }), _) => {
                            out.holdings.push(RuleHolding {
                                grant,
                                conjuncts: conjuncts.clone(),
                                since,
                                stale: true,
                            });
                        }
                        (Some(Selection::Ended { pos, at }), said) => out.ended.push(Ended {
                            grant,
                            conjuncts: conjuncts.clone(),
                            pos,
                            at,
                            issuer: said.map(|s| s.issuer),
                        }),
                        (None, _) => {}
                    }
                }
                _ => {}
            }
            match c.basis {
                GrantBasis::Anchor(a) if a == p.anchor => out.given.push(grant),
                GrantBasis::Holding(h) if h.holder == *party => out.derived.push((grant, h.grant)),
                _ => {}
            }
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // IDP-35 (2), C13, OP-157 m.3 (v)
    #[test]
    fn a_baseline_selects_on_the_hr_department_and_title() {
        let Some(SubjectSelector::Pred(c)) = baseline_holder(Some("Finance"), None) else {
            panic!("a department baseline");
        };
        assert_eq!(c.len(), 1);
        let first = c.iter().next().unwrap();
        assert_eq!(first.claim_class, HR_DEPARTMENT);
        assert_eq!(first.value, Some(EqValue::Text(String::from("Finance"))));
        let Some(SubjectSelector::Pred(both)) = baseline_holder(Some("Finance"), Some("Analyst"))
        else {
            panic!("a department and title baseline");
        };
        assert_eq!(
            both.iter()
                .map(|c| c.claim_class.as_str())
                .collect::<Vec<_>>(),
            [HR_DEPARTMENT, HR_TITLE]
        );
        assert_eq!(baseline_holder(None, None), None, "everyone is no baseline");
        assert_eq!(baseline_holder(Some(" "), None), None);
        assert_eq!(baseline_holder(Some("Finance"), Some("")), None);
    }
}
