//! Checkpoints of a log and the order they go out in: built from the head, mirrored to the
//! declared replica, then sent to witnesses (OP-86, T21, TI-13, OP-140 m.5).

use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::note::{Checkpoint, NoteError};

use crate::sequencer::Head;

/// The `tlog-checkpoint` of the log at `head`. `extensions` are the product's extra lines,
/// e.g. Access's `recorded_at` and spec-version digest (§16.4.4 m.18).
///
/// # Errors
/// [`NoteError`] for an origin or extension line the checkpoint format does not allow, or
/// [`NoteError::Checkpoint`] when the size overflows.
pub fn of_head(
    origin: &str,
    head: &Head,
    extensions: Vec<String>,
) -> Result<Checkpoint, NoteError> {
    let size = head.pos.checked_add(1).ok_or(NoteError::Checkpoint)?;
    if head.frontier.size() != size {
        return Err(NoteError::Checkpoint);
    }
    let cp = Checkpoint {
        origin: String::from(origin),
        size,
        root: head.frontier.root(),
        extensions,
    };
    cp.to_body()?;
    Ok(cp)
}

/// Why a step of the publication order is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OrderError {
    /// A size below one already reported.
    #[error("size went back")]
    Backwards,
    /// A witness request for a checkpoint the replica does not hold yet (TI-13).
    #[error("not mirrored yet")]
    NotMirrored,
    /// A size that no built checkpoint has.
    #[error("unknown checkpoint")]
    Unknown,
}

/// Where publication stands: the latest checkpoint built, how far the replica has mirrored,
/// and the largest checkpoint a witness has cosigned. Sizes only grow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Publication {
    built: u64,
    mirrored: u64,
    witnessed: u64,
}

fn forward(slot: &mut u64, size: u64) -> Result<(), OrderError> {
    if size < *slot {
        return Err(OrderError::Backwards);
    }
    *slot = size;
    Ok(())
}

impl Publication {
    /// Resumes from stored sizes.
    ///
    /// # Errors
    /// [`OrderError`] when the stored sizes break the order.
    pub const fn resume(built: u64, mirrored: u64, witnessed: u64) -> Result<Self, OrderError> {
        if witnessed > mirrored || witnessed > built {
            return Err(OrderError::NotMirrored);
        }
        Ok(Self {
            built,
            mirrored,
            witnessed,
        })
    }

    /// A checkpoint of `size` was built and signed by the log.
    ///
    /// # Errors
    /// [`OrderError::Backwards`].
    pub fn built(&mut self, size: u64) -> Result<(), OrderError> {
        forward(&mut self.built, size)
    }

    /// The replica acknowledged every record up to `size`.
    ///
    /// # Errors
    /// [`OrderError::Backwards`].
    pub fn mirrored(&mut self, size: u64) -> Result<(), OrderError> {
        forward(&mut self.mirrored, size)
    }

    /// Whether the checkpoint of `size` may be sent to witnesses now: it was built and the
    /// replica already holds it (mirror before witness).
    ///
    /// # Errors
    /// [`OrderError::Unknown`] or [`OrderError::NotMirrored`].
    pub const fn may_witness(&self, size: u64) -> Result<(), OrderError> {
        if size == 0 || size > self.built {
            return Err(OrderError::Unknown);
        }
        if size > self.mirrored {
            return Err(OrderError::NotMirrored);
        }
        Ok(())
    }

    /// A witness cosigned the checkpoint of `size`.
    ///
    /// # Errors
    /// [`OrderError`] when it could not have been sent.
    pub fn witnessed(&mut self, size: u64) -> Result<(), OrderError> {
        self.may_witness(size)?;
        forward(&mut self.witnessed, size)
    }

    /// The largest cosigned size.
    #[must_use]
    pub const fn witnessed_size(&self) -> u64 {
        self.witnessed
    }
}

#[cfg(test)]
mod tests;
