//! Event order on the receiving side (OP-22, OP-156 m.3 (j), §17.3.5). Access does not promise
//! an order: every event, webhook and SET carries `access_position = {pos, idx}`, a monotone
//! version field of its source (one domain for authority events, the issuer for identity
//! events). An event is a signal to re-read, never authority: a receiver that sees an event
//! older than, or the same as, the last position it applied re-queries the subject instead of
//! applying the event ("when in doubt, re-query").
//!
//! ```
//! use access_sdk::ordering::{AccessPosition, should_requery};
//!
//! let applied = AccessPosition { pos: 12, idx: 1 };
//! assert!(!should_requery(Some(applied), AccessPosition { pos: 13, idx: 0 }));
//! assert!(should_requery(Some(applied), AccessPosition { pos: 12, idx: 0 }));
//! ```

/// The `access_position` member: the record position and the event's index there.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccessPosition {
    /// The record position.
    pub pos: u64,
    /// The event's index within the record.
    pub idx: u64,
}

/// The member name in an event body and in a SET's claims.
pub const FIELD: &str = "access_position";

/// Whether a receiver whose last applied position (of the same source) is `last` must
/// re-query instead of applying the event at `incoming`: always without a known position, and
/// whenever `incoming` is not past `last`. Positions of one source only grow, so an event at or
/// before `last` arrived out of order or twice.
#[must_use]
pub fn should_requery(last: Option<AccessPosition>, incoming: AccessPosition) -> bool {
    last.is_none_or(|l| incoming <= l)
}

/// What a receiver keeps per source: the newest position it applied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Applied(Option<AccessPosition>);

/// What to do with one event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// It is newer than anything applied: re-read the subject and apply it.
    Apply,
    /// It arrived out of order or twice: re-query the subject's current state.
    Requery,
}

impl Applied {
    /// The newest position applied, if any.
    #[must_use]
    pub const fn last(&self) -> Option<AccessPosition> {
        self.0
    }

    /// Decides what to do with an event at `incoming` and, when it is newer, records it.
    pub fn observe(&mut self, incoming: AccessPosition) -> Next {
        if self.0.is_some_and(|l| incoming <= l) {
            return Next::Requery;
        }
        let first = self.0.is_none();
        self.0 = Some(incoming);
        if first { Next::Requery } else { Next::Apply }
    }
}

#[cfg(test)]
mod tests;
