//! The legal retention schedule of a class for a tenant (OP-74 m.2, OP-147 m.2, Ek C).

use alloc::string::String;

use crate::class::Class;
use crate::ids::TenantId;

/// A calendar period. Months and years follow the UTC calendar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Period {
    /// Whole days of 24 hours.
    Days(u32),
    /// Calendar months.
    Months(u32),
    /// Calendar years.
    Years(u32),
}

/// How long a record is kept once its schedule starts (Ek C C.2, C.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Length {
    /// A fixed period counted from the start event.
    For(Period),
    /// Until the named event is recorded, such as the end of the tenant contract.
    Until(Event),
}

/// An event a schedule counts from or waits for (Ek C C.2 "başlangıç olayı").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Event {
    /// The record was written.
    Recorded,
    /// The transaction took place.
    Transaction,
    /// The last transaction of the relationship took place.
    LastTransaction,
    /// The account was closed.
    AccountClosed,
    /// The business relationship ended.
    RelationshipEnded,
    /// The contract ended.
    ContractEnded,
    /// The consent ended or was withdrawn.
    ConsentEnded,
    /// The data was last used.
    LastUse,
    /// The request was answered.
    Responded,
    /// The incident or breach occurred.
    Incident,
    /// The end of the calendar year of the given date; counting starts on 1 January after it.
    YearEnd,
    /// The tenant closed: the tenant contract ended.
    TenantClosed,
    /// The person deleted the item, the account closed or an erasure request was recorded,
    /// whichever came first.
    Removed,
    /// The Mandate or task the data serves ended.
    MandateEnded,
    /// The last model version the record is bound to was withdrawn.
    ModelWithdrawn,
}

impl Event {
    /// Whether the event is read as the end of the calendar year of the given date.
    #[must_use]
    pub const fn at_year_end(self) -> bool {
        matches!(self, Self::YearEnd)
    }
}

/// The legal basis of a schedule, as Ek C names it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct Basis(String);

impl Basis {
    /// Wraps a basis text such as `5549 m.8`.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The basis text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The version of the tenant's retention policy a schedule belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct PolicyVersion(u64);

impl PolicyVersion {
    /// Wraps a version number.
    #[must_use]
    pub const fn new(version: u64) -> Self {
        Self(version)
    }

    /// The version number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The legal retention of one class for one tenant (OP-74 m.2, OP-147 m.2). Access resolves it
/// from the tenant's region, sector template, flags and extensions (Ek C).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Schedule {
    /// The tenant.
    pub tenant: TenantId,
    /// The class.
    pub class: Class,
    /// The legal basis.
    pub basis: Basis,
    /// How long the record is kept.
    pub length: Length,
    /// The event the length counts from.
    pub start: Event,
    /// The longest the record may be kept, counted from the start event; a cap for legal
    /// retention only, never for a hold (Ek C C.5 #5).
    pub max: Option<Period>,
    /// The policy version.
    pub version: PolicyVersion,
}

const WORK_BASIS: &str = "Ek C C.3.6, C.5 #25";
const WORK_TRACE_DAYS: u32 = 400;

impl Schedule {
    /// The Ek C C.3.6 default for a Work class (POLICY DEFAULT, OP-147 m.5), or `None` for any
    /// other class. Work reads these until the Access snapshot carries the tenant's schedules.
    #[must_use]
    pub fn work_default(tenant: TenantId, class: Class, version: PolicyVersion) -> Option<Self> {
        let length = match class {
            Class::WorkRecord | Class::WorkEvidence => Length::Until(Event::TenantClosed),
            Class::WorkDraft => Length::Until(Event::Removed),
            Class::AgentTrace => Length::For(Period::Days(WORK_TRACE_DAYS)),
            _ => return None,
        };
        Some(Self {
            tenant,
            class,
            basis: Basis::new(WORK_BASIS),
            length,
            start: Event::Recorded,
            max: None,
            version,
        })
    }
}

#[cfg(test)]
mod tests;
