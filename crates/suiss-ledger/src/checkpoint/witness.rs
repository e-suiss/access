//! The witness's side of the checkpoint protocol (§16.6 witness protocol, CMP-6, T17,
//! OP-158 m.3 (d)): a witness keeps, per log, the last checkpoint it cosigned and cosigns a
//! newer one only when a consistency proof from that base verifies; after a handover or
//! recovery the old binding is fenced at the size the record fixed (U11). Two checkpoints of
//! one log with the same size and different roots are equivocation (U9, HL-7).

use suiss_crypto::digest::{ProofError, verify_consistency};
use suiss_crypto::note::Checkpoint;

use crate::Hash;

/// Why a witness does not cosign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The request names another base size than the witness holds; the log retries with it
    /// (C2SP tlog-witness `409`).
    #[error("base is at size {0}")]
    Conflict(u64),
    /// The consistency proof from the base does not verify.
    #[error("inconsistent: {0}")]
    Inconsistent(ProofError),
    /// The checkpoint is older than the base.
    #[error("older than the base")]
    Backwards,
    /// The same size as the base with another root: the log equivocated.
    #[error("same size, another root")]
    Equivocation,
    /// The signing binding is fenced below this size (U11).
    #[error("fenced at size {0}")]
    Fenced(u64),
}

/// A witness's view of one log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogState {
    base: Option<(u64, Hash)>,
    fence: Option<u64>,
}

impl LogState {
    /// Resumes from the stored base and fence.
    #[must_use]
    pub const fn resume(base: Option<(u64, Hash)>, fence: Option<u64>) -> Self {
        Self { base, fence }
    }

    /// The last cosigned size and root.
    #[must_use]
    pub const fn base(&self) -> Option<(u64, Hash)> {
        self.base
    }

    /// The size above which the current binding may not be cosigned.
    #[must_use]
    pub const fn fence(&self) -> Option<u64> {
        self.fence
    }

    /// The size the request must name as `old`.
    #[must_use]
    pub const fn size(&self) -> u64 {
        match self.base {
            Some((s, _)) => s,
            None => 0,
        }
    }

    /// Whether `cp`, with `proof` from base size `old`, may be cosigned.
    ///
    /// # Errors
    /// [`Refusal`].
    pub fn check(&self, old: u64, proof: &[Hash], cp: &Checkpoint) -> Result<(), Refusal> {
        if let Some(max) = self.fence
            && cp.size > max
        {
            return Err(Refusal::Fenced(max));
        }
        let size = self.size();
        if old != size {
            return Err(Refusal::Conflict(size));
        }
        let Some((base, root)) = self.base else {
            return Ok(());
        };
        if cp.size < base {
            return Err(Refusal::Backwards);
        }
        if cp.size == base && cp.root != root {
            return Err(Refusal::Equivocation);
        }
        verify_consistency(base, cp.size, &root, &cp.root, proof).map_err(Refusal::Inconsistent)
    }

    /// The witness cosigned `cp`: it becomes the base.
    ///
    /// # Errors
    /// [`Refusal`] as [`LogState::check`] with an empty proof would for a smaller size.
    pub fn cosigned(&mut self, cp: &Checkpoint) -> Result<(), Refusal> {
        if self.base.is_some_and(|(s, _)| cp.size < s) {
            return Err(Refusal::Backwards);
        }
        self.base = Some((cp.size, cp.root));
        Ok(())
    }

    /// The current binding may sign nothing larger than `max` (U11): the record that moved
    /// the binding fixed `max` (`h + 1` after a handover, `N` after a recovery).
    pub fn fence_at(&mut self, max: u64) {
        self.fence = Some(self.fence.map_or(max, |f| f.min(max)));
    }

    /// A new binding was learned; it starts unfenced from the current base.
    pub const fn rebind(&mut self) {
        self.fence = None;
    }
}

/// Whether two checkpoints of one log contradict each other: same origin and size, other
/// root (U9, HL-7, §9.16).
#[must_use]
pub fn equivocates(a: &Checkpoint, b: &Checkpoint) -> bool {
    a.origin == b.origin && a.size == b.size && a.root != b.root
}

/// Most proof lines an `add-checkpoint` request carries (RFC 9162 bound for 2^63 leaves).
pub const MAX_PROOF: usize = 63;

/// Why an `add-checkpoint` body is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed add-checkpoint request")]
pub struct WireError;

/// The C2SP `tlog-witness` `add-checkpoint` body: `old <size>`, one base64 proof hash per
/// line, an empty line, then the signed checkpoint note.
#[must_use]
pub fn add_checkpoint(old: u64, proof: &[Hash], note: &str) -> alloc::string::String {
    let mut out = alloc::format!("old {old}\n");
    for h in proof {
        out.push_str(&suiss_crypto::note::base64_encode(h));
        out.push('\n');
    }
    out.push('\n');
    out.push_str(note);
    out
}

/// Splits an `add-checkpoint` body into the base size, the proof and the note.
///
/// # Errors
/// [`WireError`].
pub fn parse_add_checkpoint(body: &str) -> Result<(u64, alloc::vec::Vec<Hash>, &str), WireError> {
    let (head, note) = body.split_once("\n\n").ok_or(WireError)?;
    let mut lines = head.split('\n');
    let old = lines
        .next()
        .and_then(|l| l.strip_prefix("old "))
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        .filter(|n| *n == "0" || !n.starts_with('0'))
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or(WireError)?;
    let mut proof = alloc::vec::Vec::new();
    for l in lines {
        if proof.len() == MAX_PROOF {
            return Err(WireError);
        }
        let h: Hash = suiss_crypto::note::base64_decode(l)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(WireError)?;
        proof.push(h);
    }
    Ok((old, proof, note))
}
