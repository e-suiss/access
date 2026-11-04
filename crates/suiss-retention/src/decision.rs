//! The destroy decision (OP-147 m.2, OP-73 m.4, OP-74 m.2–m.3).

use core::time::Duration;

use crate::class::Class;
use crate::hold::Hold;
use crate::ids::{HoldId, SubjectId, TenantId};
use crate::schedule::{Event, Length, Schedule};
use crate::time::Timestamp;

/// The oldest policy snapshot a product may destroy on (OP-147 m.2, PD). Older or missing, it
/// defers.
pub const SNAPSHOT_MAX_AGE: Duration = Duration::from_hours(24);

/// Whether an event has been recorded for a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum Occurrence {
    /// Recorded at this time. For [`Event::YearEnd`] it is the date whose year end counts.
    At(Timestamp),
    /// Known not to have happened yet.
    NotYet,
    /// The product cannot tell.
    Unknown,
}

/// The record whose key a product wants to destroy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Record {
    /// Its tenant.
    pub tenant: TenantId,
    /// Its class.
    pub class: Class,
    /// Its key person; `None` when the record belongs to no subject.
    pub subject: Option<SubjectId>,
    /// The schedule's start event.
    pub start: Occurrence,
    /// The event a [`Length::Until`] schedule waits for; unused otherwise.
    pub end: Occurrence,
}

/// The answer of [`may_destroy`]. It is a decision, not an error: only
/// [`Decision::Destroy`] lets the key go.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Decision {
    /// The period has run, nothing holds the record and the policy is fresh.
    Destroy,
    /// The record is still kept.
    Retain(Retain),
    /// The state is not known well enough to destroy; ask again later.
    Defer(Defer),
}

impl Decision {
    /// Whether the key may be destroyed.
    #[must_use]
    pub const fn is_destroy(&self) -> bool {
        matches!(self, Self::Destroy)
    }
}

/// Why a record is kept.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Retain {
    /// An active hold covers it (OP-74 m.3). Never shown to the requester (Ek C C.1.1 (6)).
    Held(HoldId),
    /// The start event has not happened, so the period has not begun (Ek C rule 4).
    AwaitingStart,
    /// The event a [`Length::Until`] schedule waits for has not happened.
    AwaitingEnd,
    /// The period runs until this time.
    Running {
        /// The earliest time the record may go.
        until: Timestamp,
    },
}

/// Why the decision waits.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Defer {
    /// The schedule is for another tenant or class than the record.
    Mismatch,
    /// No policy snapshot is at hand.
    NoSnapshot,
    /// The snapshot is [`SNAPSHOT_MAX_AGE`] old or older.
    StaleSnapshot,
    /// A hold of the record's tenant has an empty class set.
    MalformedHold(HoldId),
    /// It is not known whether the start event happened.
    UnknownStart,
    /// It is not known whether the awaited event happened.
    UnknownEnd,
    /// The cap ends before the period.
    InvalidSchedule,
    /// A date falls outside the representable range.
    OutOfRange,
}

/// Whether the key of `record` may be destroyed at trusted time `now` under `schedule`, the
/// tenant's `holds` and a policy snapshot `snapshot_age` old (OP-147 m.2). It returns
/// [`Decision::Destroy`] only when the period has run, no active hold covers the record and
/// the snapshot is younger than [`SNAPSHOT_MAX_AGE`]. Anything unknown defers; nothing is
/// destroyed early. A record under several schedules goes only when every one of them says
/// [`Decision::Destroy`] (Ek C rule 5).
pub fn may_destroy(
    schedule: &Schedule,
    record: &Record,
    holds: &[Hold],
    snapshot_age: Option<Duration>,
    now: Timestamp,
) -> Decision {
    if schedule.tenant != record.tenant || schedule.class != record.class {
        return Decision::Defer(Defer::Mismatch);
    }
    match snapshot_age {
        None => return Decision::Defer(Defer::NoSnapshot),
        Some(age) if age >= SNAPSHOT_MAX_AGE => return Decision::Defer(Defer::StaleSnapshot),
        Some(_) => {}
    }
    if let Some(hold) = holds
        .iter()
        .find(|h| h.tenant == record.tenant && h.is_malformed())
    {
        return Decision::Defer(Defer::MalformedHold(hold.id.clone()));
    }
    if let Some(hold) = holds.iter().find(|h| h.is_active(now) && h.covers(record)) {
        return Decision::Retain(Retain::Held(hold.id.clone()));
    }
    match timing(schedule, record) {
        Ok(Some(until)) if now >= until => Decision::Destroy,
        Ok(Some(until)) => Decision::Retain(Retain::Running { until }),
        Ok(None) => Decision::Retain(match schedule.length {
            Length::Until(_) => Retain::AwaitingEnd,
            Length::For(_) => Retain::AwaitingStart,
        }),
        Err(defer) => Decision::Defer(defer),
    }
}

/// The earliest time the record may go, or `None` while the awaited event has not happened.
fn timing(schedule: &Schedule, record: &Record) -> Result<Option<Timestamp>, Defer> {
    let start = match record.start {
        Occurrence::At(at) => Some(anchor(schedule.start, at)?),
        Occurrence::NotYet => None,
        Occurrence::Unknown => return Err(Defer::UnknownStart),
    };
    let cap = match (start, schedule.max) {
        (Some(start), Some(max)) => Some(start.checked_add(max).ok_or(Defer::OutOfRange)?),
        _ => None,
    };
    match schedule.length {
        Length::For(period) => {
            let Some(start) = start else {
                return Ok(None);
            };
            let end = start.checked_add(period).ok_or(Defer::OutOfRange)?;
            if cap.is_some_and(|cap| cap < end) {
                return Err(Defer::InvalidSchedule);
            }
            Ok(Some(end))
        }
        Length::Until(event) => match record.end {
            Occurrence::At(at) => {
                let end = anchor(event, at)?;
                Ok(Some(cap.map_or(end, |cap| cap.min(end))))
            }
            Occurrence::NotYet => Ok(cap),
            Occurrence::Unknown => Err(Defer::UnknownEnd),
        },
    }
}

fn anchor(event: Event, at: Timestamp) -> Result<Timestamp, Defer> {
    if event.at_year_end() {
        at.next_year_start().ok_or(Defer::OutOfRange)
    } else {
        Ok(at)
    }
}

#[cfg(test)]
mod tests;
