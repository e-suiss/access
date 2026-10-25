//! Attenuation algebra: `⊑`, `∩`, `normalize` (INV-8, OP-107, OP-109).
//!
//! `None` from [`meet`] and friends is `⊥`, the value that covers nothing (OP-107 m.9).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::digest::Digest;
use crate::model::{
    ActionRef, ActionSet, AuthoritySet, Bound, CanonicalAuthority, PurposeRef, ResourceSelector,
    Structural, SubjectSelector, Window,
};

/// Catalog view the Kernel takes as input (OP-107 m.2, m.3, m.15).
#[derive(Clone, Debug, Default)]
pub struct Catalog {
    /// Actions of each pinned namespace catalog version.
    pub catalogs: BTreeMap<Digest, BTreeSet<ActionRef>>,
    /// Reserved actions: schema-declared ∪ domain-local.
    pub reserved: BTreeSet<ActionRef>,
    /// Declared purpose inclusion: purpose → purposes directly below it.
    pub purposes: BTreeMap<PurposeRef, BTreeSet<PurposeRef>>,
}

/// Input that is not a valid value of the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InputError {
    /// A window ends before it starts.
    #[error("window ends before it starts")]
    Window,
    /// An empty set where the model requires one element.
    #[error("empty set")]
    Empty,
    /// The declared purpose order has a cycle (OP-107 m.15).
    #[error("purpose order has a cycle")]
    PurposeCycle,
}

impl Catalog {
    fn below(&self, p: &PurposeRef) -> BTreeSet<PurposeRef> {
        let mut seen = BTreeSet::new();
        let mut stack: Vec<&PurposeRef> = alloc::vec![p];
        while let Some(x) = stack.pop() {
            if seen.insert(x.clone())
                && let Some(children) = self.purposes.get(x)
            {
                stack.extend(children.iter());
            }
        }
        seen
    }

    /// `a ≤ b` in the declared purpose order (reflexive, transitive).
    #[must_use]
    pub fn purpose_le(&self, a: &PurposeRef, b: &PurposeRef) -> bool {
        a == b || self.below(b).contains(a)
    }

    /// Rejects a purpose order with a cycle (OP-107 m.15).
    ///
    /// # Errors
    /// [`InputError::PurposeCycle`].
    pub fn check(&self) -> Result<(), InputError> {
        for (p, children) in &self.purposes {
            if children.iter().any(|c| self.below(c).contains(p)) {
                return Err(InputError::PurposeCycle);
            }
        }
        Ok(())
    }

    fn resolve(&self, namespace: &str, catalog: &Digest) -> BTreeSet<ActionRef> {
        self.catalogs
            .get(catalog)
            .map(|actions| {
                actions
                    .iter()
                    .filter(|a| under(&a.namespace, namespace) && !self.reserved.contains(*a))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every action an action set covers (OP-107 m.2).
    #[must_use]
    pub fn covered(&self, set: &ActionSet) -> BTreeSet<ActionRef> {
        let mut out = set.exact.clone();
        for (ns, cat) in &set.prefix {
            out.extend(self.resolve(ns, cat));
        }
        out
    }
}

fn under(namespace: &str, prefix: &str) -> bool {
    namespace == prefix
        || namespace
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('.'))
}

fn path_prefix(prefix: &[String], path: &[String]) -> bool {
    path.starts_with(prefix)
}

fn window_le(c: &Window, p: &Window) -> bool {
    p.from <= c.from && c.until <= p.until
}

fn window_meet(a: &Window, b: &Window) -> Option<Window> {
    let w = Window {
        from: a.from.max(b.from),
        until: a.until.min(b.until),
    };
    (w.from <= w.until).then_some(w)
}

fn le_opt_min(p: Option<i64>, c: Option<i64>) -> bool {
    match (p, c) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(p), Some(c)) => p <= c,
    }
}

fn le_opt_max(c: Option<i64>, p: Option<i64>) -> bool {
    match (c, p) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(c), Some(p)) => c <= p,
    }
}

fn max_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (x, None) | (None, x) => x,
    }
}

fn min_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (x, None) | (None, x) => x,
    }
}

/// `c ⊑ p` for resource selectors (OP-109 m.9).
#[must_use]
pub fn resource_le(c: &ResourceSelector, p: &ResourceSelector) -> bool {
    match (c, p) {
        (ResourceSelector::Exact(c), ResourceSelector::Exact(p)) => c == p,
        (ResourceSelector::Exact(c), ResourceSelector::Structural(p)) => {
            c.namespace == p.namespace
                && path_prefix(&p.prefix, &c.path)
                && p.kind.is_none()
                && p.attrs.is_empty()
        }
        (ResourceSelector::Structural(_), ResourceSelector::Exact(_)) => false,
        (ResourceSelector::Structural(c), ResourceSelector::Structural(p)) => {
            c.namespace == p.namespace
                && path_prefix(&p.prefix, &c.prefix)
                && (p.kind.is_none() || p.kind == c.kind)
                && p.attrs.iter().all(|(k, v)| c.attrs.get(k) == Some(v))
        }
    }
}

/// `a ∩ b` for resource selectors.
#[must_use]
pub fn resource_meet(
    left: &ResourceSelector,
    right: &ResourceSelector,
) -> Option<ResourceSelector> {
    match (left, right) {
        (ResourceSelector::Exact(_), _) => resource_le(left, right).then(|| left.clone()),
        (_, ResourceSelector::Exact(_)) => resource_le(right, left).then(|| right.clone()),
        (ResourceSelector::Structural(x), ResourceSelector::Structural(y)) => {
            if x.namespace != y.namespace {
                return None;
            }
            let prefix = if path_prefix(&x.prefix, &y.prefix) {
                y.prefix.clone()
            } else if path_prefix(&y.prefix, &x.prefix) {
                x.prefix.clone()
            } else {
                return None;
            };
            let kind = match (&x.kind, &y.kind) {
                (Some(a), Some(b)) if a != b => return None,
                (Some(k), _) | (None, Some(k)) => Some(k.clone()),
                (None, None) => None,
            };
            let mut attrs = x.attrs.clone();
            for (k, v) in &y.attrs {
                match attrs.get(k) {
                    Some(existing) if existing != v => return None,
                    _ => {
                        attrs.insert(k.clone(), v.clone());
                    }
                }
            }
            Some(ResourceSelector::Structural(Structural {
                namespace: x.namespace.clone(),
                prefix,
                kind,
                attrs,
            }))
        }
    }
}

/// `c ⊑ p` for subject selectors (OP-109 m.9).
#[must_use]
pub fn subject_le(c: &SubjectSelector, p: &SubjectSelector) -> bool {
    match (c, p) {
        (_, SubjectSelector::Public) => true,
        (SubjectSelector::Party(a), SubjectSelector::Party(b)) => a == b,
        (SubjectSelector::Pred(cc), SubjectSelector::Pred(pc)) => pc.is_subset(cc),
        (
            SubjectSelector::Foreign {
                domain: d1,
                class: k1,
            },
            SubjectSelector::Foreign {
                domain: d2,
                class: k2,
            },
        ) => d1 == d2 && k1 == k2,
        _ => false,
    }
}

/// `a ∩ b` for subject selectors.
#[must_use]
pub fn subject_meet(a: &SubjectSelector, b: &SubjectSelector) -> Option<SubjectSelector> {
    match (a, b) {
        (SubjectSelector::Public, x) | (x, SubjectSelector::Public) => Some(x.clone()),
        (SubjectSelector::Pred(x), SubjectSelector::Pred(y)) => {
            Some(SubjectSelector::Pred(x.union(y).cloned().collect()))
        }
        _ => (a == b).then(|| a.clone()),
    }
}

/// Maximal elements of a purpose set under the declared order.
#[must_use]
pub fn purpose_normalize(set: &BTreeSet<PurposeRef>, cat: &Catalog) -> BTreeSet<PurposeRef> {
    set.iter()
        .filter(|x| !set.iter().any(|y| y != *x && cat.purpose_le(x, y)))
        .cloned()
        .collect()
}

/// `c ⊑ p` for purpose sets.
#[must_use]
pub fn purpose_le(c: &BTreeSet<PurposeRef>, p: &BTreeSet<PurposeRef>, cat: &Catalog) -> bool {
    c.iter().all(|x| p.iter().any(|y| cat.purpose_le(x, y)))
}

/// `a ∩ b` for purpose sets: maximal common lower elements.
#[must_use]
pub fn purpose_meet(
    a: &BTreeSet<PurposeRef>,
    b: &BTreeSet<PurposeRef>,
    cat: &Catalog,
) -> Option<BTreeSet<PurposeRef>> {
    let mut universe: BTreeSet<PurposeRef> = a.union(b).cloned().collect();
    for x in a.iter().chain(b.iter()) {
        universe.extend(cat.below(x));
    }
    let common: BTreeSet<PurposeRef> = universe
        .into_iter()
        .filter(|x| {
            a.iter().any(|y| cat.purpose_le(x, y)) && b.iter().any(|y| cat.purpose_le(x, y))
        })
        .collect();
    let out = purpose_normalize(&common, cat);
    (!out.is_empty()).then_some(out)
}

/// Normal form of one bound; `Ok(None)` is `⊥`.
///
/// # Errors
/// Input outside the model ([`InputError`]).
pub fn bound_normalize(b: &Bound, cat: &Catalog) -> Result<Option<Bound>, InputError> {
    Ok(match b {
        Bound::Enum(s) if s.is_empty() => return Err(InputError::Empty),
        Bound::Purpose(s) if s.is_empty() => return Err(InputError::Empty),
        Bound::Subject(SubjectSelector::Pred(c)) if c.is_empty() => return Err(InputError::Empty),
        Bound::Interval(w) if w.from > w.until => return Err(InputError::Window),
        Bound::Range {
            min: Some(lo),
            max: Some(hi),
            ..
        } if lo > hi => None,
        Bound::Purpose(s) => Some(Bound::Purpose(purpose_normalize(s, cat))),
        other => Some(other.clone()),
    })
}

/// `c ⊑ p` for bounds; bounds of different types never compare.
#[must_use]
pub fn bound_le(c: &Bound, p: &Bound, cat: &Catalog) -> bool {
    match (c, p) {
        (Bound::Enum(c), Bound::Enum(p)) => c.is_subset(p),
        (Bound::Eq(c), Bound::Eq(p)) => c == p,
        (Bound::Flag(c), Bound::Flag(p)) => c == p,
        (
            Bound::Range {
                min: cmin,
                max: cmax,
                unit: cu,
            },
            Bound::Range {
                min: pmin,
                max: pmax,
                unit: pu,
            },
        ) => cu == pu && le_opt_min(*pmin, *cmin) && le_opt_max(*cmax, *pmax),
        (Bound::CountMax(c), Bound::CountMax(p)) => c <= p,
        (Bound::Interval(c), Bound::Interval(p)) => window_le(c, p),
        (Bound::Resource(c), Bound::Resource(p)) => resource_le(c, p),
        (Bound::Subject(c), Bound::Subject(p)) => subject_le(c, p),
        (Bound::Purpose(c), Bound::Purpose(p)) => purpose_le(c, p, cat),
        _ => false,
    }
}

/// `a ∩ b` for bounds; `None` is `⊥`.
#[must_use]
pub fn bound_meet(left: &Bound, right: &Bound, cat: &Catalog) -> Option<Bound> {
    match (left, right) {
        (Bound::Enum(x), Bound::Enum(y)) => {
            let s: BTreeSet<String> = x.intersection(y).cloned().collect();
            (!s.is_empty()).then_some(Bound::Enum(s))
        }
        (Bound::Eq(x), Bound::Eq(y)) => (x == y).then(|| left.clone()),
        (Bound::Flag(x), Bound::Flag(y)) => (x == y).then(|| left.clone()),
        (
            Bound::Range {
                min: amin,
                max: amax,
                unit: au,
            },
            Bound::Range {
                min: bmin,
                max: bmax,
                unit: bu,
            },
        ) => {
            if au != bu {
                return None;
            }
            let min = max_opt(*amin, *bmin);
            let max = min_opt(*amax, *bmax);
            match (min, max) {
                (Some(lo), Some(hi)) if lo > hi => None,
                _ => Some(Bound::Range {
                    min,
                    max,
                    unit: au.clone(),
                }),
            }
        }
        (Bound::CountMax(x), Bound::CountMax(y)) => Some(Bound::CountMax(*x.min(y))),
        (Bound::Interval(x), Bound::Interval(y)) => window_meet(x, y).map(Bound::Interval),
        (Bound::Resource(x), Bound::Resource(y)) => resource_meet(x, y).map(Bound::Resource),
        (Bound::Subject(x), Bound::Subject(y)) => subject_meet(x, y).map(Bound::Subject),
        (Bound::Purpose(x), Bound::Purpose(y)) => purpose_meet(x, y, cat).map(Bound::Purpose),
        _ => None,
    }
}

fn optional_le<T>(c: Option<&T>, p: Option<&T>, le: impl Fn(&T, &T) -> bool) -> bool {
    match (c, p) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(c), Some(p)) => le(c, p),
    }
}

struct Bottom;

fn optional_meet<T: Clone>(
    left: Option<&T>,
    right: Option<&T>,
    meet: impl Fn(&T, &T) -> Option<T>,
) -> Result<Option<T>, Bottom> {
    match (left, right) {
        (None, None) => Ok(None),
        (Some(x), None) | (None, Some(x)) => Ok(Some(x.clone())),
        (Some(x), Some(y)) => meet(x, y).map(Some).ok_or(Bottom),
    }
}

/// Normal form of an authority set; `Ok(None)` is `⊥`. A `Public` recipient or subject bound is written as absent (OP-109 m.10).
///
/// # Errors
/// Input outside the model ([`InputError`]).
pub fn normalize(a: &AuthoritySet, cat: &Catalog) -> Result<Option<AuthoritySet>, InputError> {
    if a.actions.exact.is_empty() && a.actions.prefix.is_empty() {
        return Ok(None);
    }
    let mut params = BTreeMap::new();
    for (k, b) in &a.params {
        match bound_normalize(b, cat)? {
            Some(Bound::Subject(SubjectSelector::Public)) => {}
            Some(n) => {
                params.insert(k.clone(), n);
            }
            None => return Ok(None),
        }
    }
    if let Some(SubjectSelector::Pred(c)) = &a.recipient
        && c.is_empty()
    {
        return Err(InputError::Empty);
    }
    let purpose = match &a.purpose {
        Some(p) if p.is_empty() => return Err(InputError::Empty),
        Some(p) => Some(purpose_normalize(p, cat)),
        None => None,
    };
    Ok(Some(AuthoritySet {
        actions: a.actions.clone(),
        resource: a.resource.clone(),
        params,
        recipient: a
            .recipient
            .clone()
            .filter(|r| *r != SubjectSelector::Public),
        purpose,
    }))
}

/// `c ⊑ p` for authority sets (OP-109 m.10).
#[must_use]
pub fn subsumes(c: &AuthoritySet, p: &AuthoritySet, cat: &Catalog) -> bool {
    cat.covered(&c.actions).is_subset(&cat.covered(&p.actions))
        && resource_le(&c.resource, &p.resource)
        && p.params.iter().all(|(k, pb)| {
            // OP-124 m.4
            matches!(pb, Bound::Subject(SubjectSelector::Public))
                || c.params.get(k).is_some_and(|cb| bound_le(cb, pb, cat))
        })
        && optional_le(
            c.recipient.as_ref(),
            p.recipient
                .as_ref()
                .filter(|r| **r != SubjectSelector::Public),
            subject_le,
        )
        && optional_le(c.purpose.as_ref(), p.purpose.as_ref(), |x, y| {
            purpose_le(x, y, cat)
        })
}

/// `a ∩ b` for authority sets; `None` is `⊥`.
#[must_use]
pub fn meet(a: &AuthoritySet, b: &AuthoritySet, cat: &Catalog) -> Option<AuthoritySet> {
    let exact: BTreeSet<ActionRef> = cat
        .covered(&a.actions)
        .intersection(&cat.covered(&b.actions))
        .cloned()
        .collect();
    if exact.is_empty() {
        return None;
    }
    let resource = resource_meet(&a.resource, &b.resource)?;
    let mut params = a.params.clone();
    for (k, vb) in &b.params {
        let merged = match params.get(k) {
            Some(va) => bound_meet(va, vb, cat)?,
            None => vb.clone(),
        };
        params.insert(k.clone(), merged);
    }
    let recipient = optional_meet(a.recipient.as_ref(), b.recipient.as_ref(), subject_meet).ok()?;
    let purpose = optional_meet(a.purpose.as_ref(), b.purpose.as_ref(), |x, y| {
        purpose_meet(x, y, cat)
    })
    .ok()?;
    Some(AuthoritySet {
        actions: ActionSet {
            exact,
            prefix: BTreeSet::new(),
        },
        resource,
        params,
        recipient,
        purpose,
    })
}

/// Child ⊆ Parent (§5.8, OP-109 m.11); a delegable grant never has a `Public` holder or holder class (OP-107 m.18).
#[must_use]
pub fn child_within_parent(
    c: &CanonicalAuthority,
    p: &CanonicalAuthority,
    holder: &SubjectSelector,
    cat: &Catalog,
) -> bool {
    let holder_ok = p
        .delegation
        .downstream_holder_class
        .as_ref()
        .is_none_or(|class| subject_le(holder, class));
    let class_ok = optional_le(
        c.delegation.downstream_holder_class.as_ref(),
        p.delegation.downstream_holder_class.as_ref(),
        subject_le,
    );
    let public = |s: Option<&SubjectSelector>| matches!(s, Some(SubjectSelector::Public));
    let no_wildcard = !public(p.delegation.downstream_holder_class.as_ref())
        && (c.delegation.depth == 0
            || (!public(Some(holder)) && !public(c.delegation.downstream_holder_class.as_ref())));
    no_wildcard
        && subsumes(&c.authority, &p.authority, cat)
        && window_le(&c.constraints.validity, &p.constraints.validity)
        && c.constraints
            .conditions
            .is_superset(&p.constraints.conditions)
        && p.delegation.depth > 0
        && c.delegation.depth < p.delegation.depth
        && holder_ok
        && class_ok
        && c.requirements.is_superset(&p.requirements)
}

#[cfg(test)]
mod tests;
