//! The group closure index and the derived index quotas (§9.7A.1, §9.7A.5, CMP-9, OP-158 m.3
//! (u)). Membership in Access is a Claim of a class under a `subject-selection` Acceptance; a
//! rule-shaped holder is a conjunction of classes. The index keeps, per class, the dense ordinals
//! of every Party a membership key ever named, as a roaring bitmap, so a Party outside the
//! intersection of a conjunction's bitmaps cannot be a member (Leopard's set intersection). It
//! only names candidates: the canonical episode decides (INV-33), and a stale or over-quota index
//! sends the question to the canonical state or refuses it, never to ALLOW (MD-8, G51).

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::codec::Canonical as _;
use access_kernel::model::Id;
use access_store::Pool;
use access_store::derived::{
    Batch, ClosureRow, GrantRow, KeyChange, MAX_CLASSES, advance_index, closure_extent, closure_of,
    cursor, ordinals_of,
};
use access_store::scope::DomainId;
use suiss_crypto::dcbor::Value;

use crate::CoreError;

pub mod bitmap;

pub use bitmap::Bitmap;

/// The enforced quotas (§9.7A.5, P46, EA).
pub mod quota {
    use std::time::Duration;

    /// Resolution depth: lineage hops an advisory answer follows (cycle guard).
    pub const DEPTH: usize = 25;
    /// Resolution width: conjuncts one rule-shaped holder intersects.
    pub const WIDTH: usize = 10;
    /// Advisory `check` deadline.
    pub const CHECK: Duration = Duration::from_millis(100);
    /// Search deadline, hard.
    pub const SEARCH: Duration = Duration::from_secs(1);
    /// Most results one search page returns.
    pub const SEARCH_RESULTS: u32 = 1_000;
    /// Most index tuples one ingest batch of the deriver applies.
    pub const TUPLES_PER_WRITE: usize = 1_000;
    /// Most claim classes one domain's closure index keeps.
    pub const TYPES_PER_STORE: u64 = access_store::derived::MAX_CLASSES;

    /// The stable code of every quota refusal (OP-158 m.3 (aa)).
    pub const EXCEEDED: &str = "index-quota-exceeded";
}

/// What one ingest batch of the deriver writes (CMP-9).
#[derive(Clone, Debug, Default)]
pub struct Pending {
    /// Grant rows by Grant; a later one replaces an earlier one.
    pub grants: BTreeMap<[u8; 16], GrantRow>,
    /// Key index changes, in order.
    pub keys: Vec<KeyChange>,
    /// Parties a membership key named, by class.
    pub members: BTreeMap<String, BTreeSet<[u8; 16]>>,
}

impl Pending {
    /// Index tuples it writes.
    #[must_use]
    pub fn tuples(&self) -> usize {
        self.grants
            .len()
            .saturating_add(self.keys.len())
            .saturating_add(self.members.values().map(BTreeSet::len).sum())
    }

    /// Whether it writes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tuples() == 0
    }

    /// Adds `other`, which comes later in the log.
    pub fn merge(&mut self, other: Self) {
        self.grants.extend(other.grants);
        self.keys.extend(other.keys);
        for (class, parties) in other.members {
            self.members.entry(class).or_default().extend(parties);
        }
    }

    /// Reads one effect key: a membership key `["member", class, subject, claim]` set to a
    /// Claim adds `subject` to `class`. Whether the key was one.
    pub fn member(&mut self, key: &[Value], value: Option<&Value>) -> bool {
        let [Value::Text(kind), Value::Text(class), subject, _] = key else {
            return false;
        };
        if kind != access_kernel::claim::MEMBER {
            return false;
        }
        if value.is_some()
            && let Ok(subject) = Id::from_value(subject)
        {
            self.members
                .entry(class.clone())
                .or_default()
                .insert(subject.0);
        }
        true
    }
}

/// Batches of the records `(at, pos, pending)` cut so none writes more than
/// [`quota::TUPLES_PER_WRITE`] tuples, except one record alone that writes more (a committed
/// record is never refused by its index). Each batch ends at the position of its last record.
#[must_use]
pub fn batches(records: Vec<(u64, Pending)>) -> Vec<(u64, Pending)> {
    let mut out: Vec<(u64, Pending)> = Vec::new();
    let mut current: Option<(u64, Pending)> = None;
    for (pos, one) in records {
        current = Some(match current.take() {
            Some((_, mut batch))
                if batch.tuples().saturating_add(one.tuples()) <= quota::TUPLES_PER_WRITE =>
            {
                batch.merge(one);
                (pos, batch)
            }
            Some(full) => {
                out.push(full);
                (pos, one)
            }
            None => (pos, one),
        });
    }
    out.extend(current);
    out
}

/// Applies `pending` to the index of `domain`, moving its cursor from `from` to `to`: new Party
/// ordinals, and each touched class's bitmap as it stands after the batch. A class past
/// [`MAX_CLASSES`] keeps no bitmap.
///
/// # Errors
/// [`CoreError::Store`]; `Stale` when another deriver moved the cursor first.
pub async fn apply(
    deriver: &Pool,
    domain: &DomainId,
    (from, to): (u64, u64),
    pending: &Pending,
) -> Result<(), CoreError> {
    let parties: Vec<[u8; 16]> = pending
        .members
        .values()
        .flatten()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut ordinals: BTreeMap<[u8; 16], u32> = if parties.is_empty() {
        BTreeMap::new()
    } else {
        ordinals_of(deriver, domain, &parties)
            .await?
            .into_iter()
            .collect()
    };
    let mut fresh = Vec::new();
    let mut closure = Vec::new();
    if !pending.members.is_empty() {
        let (mut classes, mut next) = closure_extent(deriver, domain).await?;
        for p in &parties {
            if !ordinals.contains_key(p) {
                ordinals.insert(*p, next);
                fresh.push((*p, next));
                next = next
                    .checked_add(1)
                    .ok_or(CoreError::Store(access_store::StoreError::Range))?;
            }
        }
        let names: Vec<String> = pending.members.keys().cloned().collect();
        let known: BTreeMap<String, ClosureRow> = closure_of(deriver, domain, &names)
            .await?
            .into_iter()
            .map(|r| (r.class.clone(), r))
            .collect();
        for (class, members) in &pending.members {
            let members_now = match known.get(class) {
                Some(row) => match &row.members {
                    None => None,
                    Some(bytes) => {
                        let mut b = Bitmap::from_bytes(bytes)
                            .map_err(|_| CoreError::Store(access_store::StoreError::Corrupt))?;
                        for p in members {
                            if let Some(o) = ordinals.get(p) {
                                b.insert(*o);
                            }
                        }
                        Some(b.to_bytes())
                    }
                },
                None if classes >= MAX_CLASSES => None,
                None => {
                    classes = classes.saturating_add(1);
                    let b: Bitmap = members
                        .iter()
                        .filter_map(|p| ordinals.get(p).copied())
                        .collect();
                    Some(b.to_bytes())
                }
            };
            closure.push(ClosureRow {
                class: class.clone(),
                members: members_now,
                pos: to,
            });
        }
    }
    let grants: Vec<GrantRow> = pending.grants.values().cloned().collect();
    advance_index(
        deriver,
        domain,
        (from, to),
        &Batch {
            grants: &grants,
            keys: &pending.keys,
            ordinals: &fresh,
            closure: &closure,
        },
    )
    .await?;
    Ok(())
}

/// What the closure index says about a Party and a conjunction of classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Candidate {
    /// The Party is in every class's bitmap: the canonical episode decides.
    Maybe,
    /// The Party is outside the intersection at the index's position: not a member.
    No,
    /// The index has not applied `head` yet; ask the canonical state (G51).
    Behind,
}

/// Whether `party` can be a member of every class in `classes` at `head`, from the index of
/// `domain` read over `pool`.
///
/// # Errors
/// `index-quota-exceeded` for more than [`quota::WIDTH`] classes or a class past
/// [`MAX_CLASSES`]; [`CoreError::Store`].
pub async fn candidate(
    pool: &Pool,
    domain: &DomainId,
    classes: &[String],
    party: &Id,
    head: u64,
) -> Result<Candidate, CoreError> {
    // §9.7A.5
    if classes.len() > quota::WIDTH {
        return Err(CoreError::Refused(quota::EXCEEDED));
    }
    // G51
    if cursor(pool, domain).await? < head {
        return Ok(Candidate::Behind);
    }
    let rows = closure_of(pool, domain, classes).await?;
    let Some(ordinal) = ordinals_of(pool, domain, &[party.0])
        .await?
        .first()
        .map(|(_, o)| *o)
    else {
        return Ok(Candidate::No);
    };
    for class in classes {
        let Some(row) = rows.iter().find(|r| &r.class == class) else {
            return Ok(Candidate::No);
        };
        let Some(bytes) = &row.members else {
            return Err(CoreError::Refused(quota::EXCEEDED));
        };
        let b = Bitmap::from_bytes(bytes)
            .map_err(|_| CoreError::Store(access_store::StoreError::Corrupt))?;
        if !b.contains(ordinal) {
            return Ok(Candidate::No);
        }
    }
    Ok(Candidate::Maybe)
}

/// The ordinals in every class of `classes` (Leopard's intersection), or `None` when the index
/// is behind `head` (G51).
///
/// # Errors
/// As [`candidate`].
pub async fn members(
    pool: &Pool,
    domain: &DomainId,
    classes: &[String],
    head: u64,
) -> Result<Option<Bitmap>, CoreError> {
    if classes.len() > quota::WIDTH {
        return Err(CoreError::Refused(quota::EXCEEDED));
    }
    if cursor(pool, domain).await? < head {
        return Ok(None);
    }
    let rows = closure_of(pool, domain, classes).await?;
    let mut out: Option<Bitmap> = None;
    for class in classes {
        let Some(row) = rows.iter().find(|r| &r.class == class) else {
            return Ok(Some(Bitmap::new()));
        };
        let Some(bytes) = &row.members else {
            return Err(CoreError::Refused(quota::EXCEEDED));
        };
        let b = Bitmap::from_bytes(bytes)
            .map_err(|_| CoreError::Store(access_store::StoreError::Corrupt))?;
        out = Some(match out {
            None => b,
            Some(o) => o.and(&b),
        });
    }
    Ok(out.or_else(|| Some(Bitmap::new())))
}

#[cfg(test)]
mod tests;
