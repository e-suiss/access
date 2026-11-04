//! Litigation, regulator and law-enforcement holds (OP-74 m.3, OP-147 m.2, Ek C C.5 #5).

use alloc::vec::Vec;
use core::fmt;

use crate::class::Class;
use crate::decision::Record;
use crate::ids::{HoldId, SubjectId, TenantId};
use crate::time::Timestamp;

/// Who asked for the hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum HoldKind {
    /// Pending or reasonably foreseeable litigation.
    Litigation,
    /// A regulator request.
    Regulator,
    /// A law-enforcement request or preservation notice.
    LawEnforcement,
}

/// What a hold covers within its tenant.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum HoldScope {
    /// Every class of one subject.
    Subject(SubjectId),
    /// These classes, for every subject. An empty set is malformed and defers destruction.
    Classes(Vec<Class>),
    /// The whole tenant.
    Tenant,
}

/// A hold: while active it stops every destruction it covers, even past the legal period and
/// its cap (OP-74 m.3, Ek C C.5 #5).
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Hold {
    /// The hold.
    pub id: HoldId,
    /// The tenant it belongs to.
    pub tenant: TenantId,
    /// What it covers.
    pub scope: HoldScope,
    /// When it was placed.
    pub placed_at: Timestamp,
    /// When it ends; `None` until it is lifted.
    pub until: Option<Timestamp>,
    /// Who asked for it.
    pub kind: HoldKind,
    /// The hold serves a suspicious-activity report. Its existence, reason and scope are never
    /// shown to the requester (OP-74 m.4, Ek C C.1.1 (6)); `Debug` hides the scope.
    pub suspicious_activity: bool,
}

impl Hold {
    /// Whether the hold is in force at `now`. A hold whose placement time is still ahead of
    /// `now` already counts.
    #[must_use]
    pub fn is_active(&self, now: Timestamp) -> bool {
        self.until.is_none_or(|until| now < until)
    }

    /// Whether the hold's scope takes in `record`.
    #[must_use]
    pub fn covers(&self, record: &Record) -> bool {
        if self.tenant != record.tenant {
            return false;
        }
        match &self.scope {
            HoldScope::Subject(subject) => record.subject.as_ref() == Some(subject),
            HoldScope::Classes(classes) => classes.contains(&record.class),
            HoldScope::Tenant => true,
        }
    }

    pub(crate) fn is_malformed(&self) -> bool {
        matches!(&self.scope, HoldScope::Classes(classes) if classes.is_empty())
    }
}

impl fmt::Debug for Hold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Hold");
        s.field("id", &self.id).field("tenant", &self.tenant);
        if self.suspicious_activity {
            s.field("scope", &"<confidential>");
        } else {
            s.field("scope", &self.scope);
        }
        s.field("placed_at", &self.placed_at)
            .field("until", &self.until)
            .field("kind", &self.kind)
            .field("suspicious_activity", &self.suspicious_activity)
            .finish()
    }
}

#[cfg(test)]
mod tests;
