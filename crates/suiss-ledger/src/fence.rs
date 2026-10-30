//! Durability fence and outbox cursor (TI-6, OP-130 m.1, Work OP-3): nothing that depends on a
//! record leaves before the record is durable.

/// Position of one outbox event: the record it derives from and its index there.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cursor {
    /// Record position.
    pub pos: u64,
    /// Event index within the record.
    pub idx: u32,
}

/// The highest position known to be durable. It only moves forward, and only on a commit the
/// driver reports as durable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fence {
    durable: Option<u64>,
}

/// A durable position below the current one was reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("durable position went back")]
pub struct FenceError;

impl Fence {
    /// A fence that starts at a position already durable in storage.
    #[must_use]
    pub const fn at(durable: u64) -> Self {
        Self {
            durable: Some(durable),
        }
    }

    /// The highest durable position, if any.
    #[must_use]
    pub const fn durable(&self) -> Option<u64> {
        self.durable
    }

    /// Records that every position up to `pos` is durable.
    ///
    /// # Errors
    /// [`FenceError`] when `pos` is below the current durable position.
    pub fn advance(&mut self, pos: u64) -> Result<(), FenceError> {
        if self.durable.is_some_and(|d| pos < d) {
            return Err(FenceError);
        }
        self.durable = Some(pos);
        Ok(())
    }

    /// Whether an event of the record at `pos` may leave.
    #[must_use]
    pub fn allows(&self, pos: u64) -> bool {
        self.durable.is_some_and(|d| pos <= d)
    }

    /// The events of `pending`, in order, that may leave after `after`: those past the cursor
    /// up to the first one the fence holds back.
    #[must_use]
    pub fn releasable<'a>(&self, after: Option<Cursor>, pending: &'a [Cursor]) -> &'a [Cursor] {
        let start = pending
            .iter()
            .position(|c| after.is_none_or(|a| *c > a))
            .unwrap_or(pending.len());
        let rest = pending.get(start..).unwrap_or_default();
        let end = rest
            .iter()
            .position(|c| !self.allows(c.pos))
            .unwrap_or(rest.len());
        rest.get(..end).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
