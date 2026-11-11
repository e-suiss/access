//! The Suiss One classes and what One data falls under them (OP-77, Ek C C.3.7, C.5 #26, #27).

use crate::class::Class;
use crate::ids::TenantId;
use crate::schedule::{Basis, Event, Length, Period, PolicyVersion, Schedule};

const ONE_BASIS: &str = "Ek C C.3.7, C.5 #26, #27";

/// Days an export package stays downloadable before it is crypto-shredded (PD, Ek C C.3.7).
pub const EXPORT_DOWNLOAD_DAYS: u32 = 7;

/// The longest raw observation is kept when the person turns keeping it on (PD, Ek C C.3.7).
pub const OBSERVATION_DAYS: u32 = 3;

/// Years the provider trace and the training lineage are kept (PD ⚠️, Ek C C.3.7).
pub const ONE_TRACE_YEARS: u32 = 3;

impl Class {
    /// Whether the class is user-keyed: its DEK is wrapped under the person's KEK on their
    /// devices and passkeys, and the operator cannot read it (E52, E66, Ek C C.3.7). Every One
    /// class is, except the content-free training lineage.
    #[must_use]
    pub const fn is_user_keyed(self) -> bool {
        matches!(
            self,
            Self::OneMemory
                | Self::OneModel
                | Self::OneObservation
                | Self::OneSensitive
                | Self::OneProviderTrace
                | Self::OneBrowserProfile
        )
    }

    /// Whether an account deletion crypto-shreds the class (Ek C C.3.7): every user-keyed One
    /// class; the training lineage stays, as the proof of withdrawal, for its own period.
    #[must_use]
    pub const fn shredded_with_account(self) -> bool {
        self.is_user_keyed()
    }

    /// How restrictive the class's rule is among the One classes, higher first; `None` outside
    /// them. An export package takes the rule of its most restrictive source (Ek C C.3.7).
    #[must_use]
    pub const fn one_restriction(self) -> Option<u8> {
        match self {
            Self::OneObservation => Some(6),
            Self::OneSensitive => Some(5),
            Self::OneBrowserProfile => Some(4),
            Self::OneMemory | Self::OneModel => Some(3),
            Self::OneProviderTrace => Some(2),
            Self::OneTrainingLineage => Some(1),
            _ => None,
        }
    }
}

/// One data that is not a class of its own (Ek C C.3.7 "Eşlemeler").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OneData {
    /// One's single-person task record, the content fields of the Executor's event history
    /// included (E62).
    TaskRecord,
    /// The body of an effect evidence (E64).
    EffectEvidence,
    /// A browser snapshot, a checkpoint of the agent browser (E63); it never outlives the profile.
    BrowserSnapshot,
    /// One's consent record (E60): not a One class but `audit`, counted from the end of the
    /// consent state it shows.
    ConsentRecord,
}

impl OneData {
    /// The class the data falls under.
    #[must_use]
    pub const fn class(self) -> Class {
        match self {
            Self::TaskRecord | Self::EffectEvidence => Class::OneMemory,
            Self::BrowserSnapshot => Class::OneBrowserProfile,
            Self::ConsentRecord => Class::Audit,
        }
    }

    /// The event the data's period counts from, where it differs from its class's.
    #[must_use]
    pub const fn start(self) -> Option<Event> {
        match self {
            Self::ConsentRecord => Some(Event::ConsentEnded),
            _ => None,
        }
    }
}

/// The class an export package of `sources` is kept under: its most restrictive One source.
/// `None` when no source is a One class. The package is downloadable for
/// [`EXPORT_DOWNLOAD_DAYS`] and then crypto-shredded.
#[must_use]
pub fn export_class(sources: &[Class]) -> Option<Class> {
    sources
        .iter()
        .copied()
        .filter_map(|c| c.one_restriction().map(|r| (r, c)))
        .max_by_key(|(r, _)| *r)
        .map(|(_, c)| c)
}

impl Schedule {
    /// The Ek C C.3.7 default for a One class (POLICY DEFAULT, OP-77), or `None` for any other
    /// class. No template extends these.
    #[must_use]
    pub fn one_default(tenant: TenantId, class: Class, version: PolicyVersion) -> Option<Self> {
        let (length, start, max) = match class {
            Class::OneMemory | Class::OneModel | Class::OneSensitive => {
                (Length::Until(Event::Removed), Event::Recorded, None)
            }
            Class::OneObservation => (
                Length::For(Period::Days(OBSERVATION_DAYS)),
                Event::Recorded,
                Some(Period::Days(OBSERVATION_DAYS)),
            ),
            Class::OneProviderTrace => (
                Length::For(Period::Years(ONE_TRACE_YEARS)),
                Event::Transaction,
                None,
            ),
            Class::OneBrowserProfile => (Length::Until(Event::MandateEnded), Event::Recorded, None),
            Class::OneTrainingLineage => (
                Length::For(Period::Years(ONE_TRACE_YEARS)),
                Event::ModelWithdrawn,
                None,
            ),
            _ => return None,
        };
        Some(Self {
            tenant,
            class,
            basis: Basis::new(ONE_BASIS),
            length,
            start,
            max,
            version,
        })
    }
}

#[cfg(test)]
mod tests;
