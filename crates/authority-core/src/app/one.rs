//! What One's cloud key permission reads of the head (OP-156 m.3 (w), E59, E46): whether the
//! Mandate a permission is bound to is live now and still covers the work it serves. A read: it
//! decides nothing and changes nothing.

use access_authority_sequencer::ports::DomainLog;
use access_kernel::meta::{MandateState, kind};
use access_kernel::model::Id;

use crate::CoreError;
use crate::app::Authority;
use crate::domain::read;
use crate::ports::{Binding, Reader, Salts};

/// Where a Mandate stands for one action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MandateStanding {
    /// Live and covering the action until the given Unix ms.
    Covers(u64),
    /// Revoked, past its window, or narrowed so it no longer covers the action.
    Ended,
    /// The head holds no such Mandate.
    Unknown,
}

/// Where `m` stands at `now` for the action `name` of `namespace` (E59 (3)).
#[must_use]
pub fn standing(m: &MandateState, namespace: &str, name: &str, now: u64) -> MandateStanding {
    let w = m.envelope.constraints.validity;
    let actions = &m.envelope.authority.actions;
    let covers = actions
        .exact
        .iter()
        .any(|a| a.namespace == namespace && a.name == name)
        || actions.prefix.iter().any(|(n, _)| n == namespace);
    if m.ended.is_none() && covers && w.from <= now && now < w.until {
        MandateStanding::Covers(w.until)
    } else {
        MandateStanding::Ended
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// Where the Mandate `mandate` stands at `now` for the action `name` of `namespace`.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn mandate_standing(
        &self,
        mandate: &Id,
        (namespace, name): (&str, &str),
        now: u64,
    ) -> Result<MandateStanding, CoreError> {
        let state = self
            .settled(|snap| read::<MandateState>(snap, kind::MANDATE, mandate))
            .await?;
        Ok(state.map_or(MandateStanding::Unknown, |m| {
            standing(&m, namespace, name, now)
        }))
    }
}
