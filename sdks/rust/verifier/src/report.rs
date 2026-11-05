//! Producing Offline Exercise Reports (§9.12.2, L2-RPT-1 to L2-RPT-3, SEC14): each local use
//! of one projection is chained as it happens, and a report is cut when the verifier
//! reconnects. The next report continues the chain from the head the last one ended with.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use access_kernel::claim::body::{Class, body_digest};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::model::{Id, TrustedTime, Window};
use access_kernel::report::{self, Entry, LocalOutcome, Report, ReportError, SliceAmount, Summary};

/// A cut report: the body, its canonical bytes and the value of the `offline_exercise_report`
/// Claim that carries it (L2-CLB-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CutReport {
    /// The report.
    pub report: Report,
    /// Its canonical bytes, the Claim body.
    pub body: Vec<u8>,
    /// The Claim's `value`.
    pub value: [u8; 32],
}

/// The chain of one projection at one verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportBuilder {
    verifier_profile: Digest,
    verifier_instance: Option<Id>,
    exercise: Digest,
    contract: Digest,
    profile_version: u64,
    previous: Option<Digest>,
    first_seq: u64,
    head: Digest,
    seq: u64,
    entries: Vec<Entry>,
}

impl ReportBuilder {
    /// A new chain for a projection, from its seed (L2-RPT-2).
    ///
    /// # Errors
    /// [`ReportError::Malformed`].
    pub fn start(
        verifier_profile: Digest,
        verifier_instance: Option<Id>,
        exercise: Digest,
        contract: Digest,
        profile_version: u64,
    ) -> Result<Self, ReportError> {
        let head = report::seed(&exercise, &contract)?;
        Ok(Self {
            verifier_profile,
            verifier_instance,
            exercise,
            contract,
            profile_version,
            previous: None,
            first_seq: 0,
            head,
            seq: 0,
            entries: Vec::new(),
        })
    }

    /// Continues a chain after the report `previous` summarises (L2-RPT-2).
    #[must_use]
    pub fn resume(
        verifier_profile: Digest,
        verifier_instance: Option<Id>,
        exercise: Digest,
        contract: Digest,
        profile_version: u64,
        previous: &Summary,
    ) -> Self {
        Self {
            verifier_profile,
            verifier_instance,
            exercise,
            contract,
            profile_version,
            previous: Some(previous.head),
            first_seq: previous.next_seq,
            head: previous.head,
            seq: previous.next_seq,
            entries: Vec::new(),
        }
    }

    /// The projection's `ExerciseID`.
    #[must_use]
    pub const fn exercise(&self) -> &Digest {
        &self.exercise
    }

    /// The current chain head.
    #[must_use]
    pub const fn head(&self) -> &Digest {
        &self.head
    }

    /// The sequence number the next entry gets.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.seq
    }

    /// Entries not yet reported.
    #[must_use]
    pub fn pending(&self) -> &[Entry] {
        &self.entries
    }

    /// Chains one local use and returns its sequence number. Only an `allow` draws, and
    /// entries keep their time order (L2-RPT-3).
    ///
    /// # Errors
    /// [`ReportError::Entry`] or [`ReportError::Period`]; nothing is chained.
    pub fn record(&mut self, entry: Entry) -> Result<u64, ReportError> {
        if entry.outcome == LocalOutcome::Deny && !entry.drawn.is_empty()
            || entry.drawn.iter().any(|d| d.amount == 0)
        {
            return Err(ReportError::Entry);
        }
        if self.entries.last().is_some_and(|l| l.time > entry.time) {
            return Err(ReportError::Period);
        }
        let seq = self.seq;
        let next = seq.checked_add(1).ok_or(ReportError::Chain)?;
        self.head = report::link(&self.head, seq, &entry)?;
        self.seq = next;
        self.entries.push(entry);
        Ok(seq)
    }

    /// Cuts a report of the pending entries over the period up to `now`, with what remains of
    /// the slice, and continues the chain after it (§9.12.2). The report is checked with the
    /// Kernel's own rule before it is returned.
    ///
    /// # Errors
    /// [`ReportError`]; the builder is unchanged.
    pub fn cut(
        &mut self,
        now: TrustedTime,
        slice_unused: BTreeSet<SliceAmount>,
    ) -> Result<CutReport, ReportError> {
        let from = self.entries.first().map_or(now, |e| e.time.min(now));
        let until = self.entries.last().map_or(now, |e| e.time.max(now));
        let report = Report {
            verifier_profile: self.verifier_profile,
            verifier_instance: self.verifier_instance,
            exercise: self.exercise,
            contract: self.contract,
            period: Window { from, until },
            previous: self.previous,
            first_seq: self.first_seq,
            entries: self.entries.clone(),
            head: self.head,
            slice_unused,
            profile_version: self.profile_version,
        };
        let summary = report::verify(&report)?;
        let value = report.to_value();
        let body = report.to_bytes().map_err(|_| ReportError::Malformed)?;
        let claim = body_digest(Class::OfflineExerciseReport, &value)
            .map_err(|_| ReportError::Malformed)?;
        self.previous = Some(summary.head);
        self.first_seq = summary.next_seq;
        self.entries.clear();
        Ok(CutReport {
            report,
            body,
            value: claim,
        })
    }
}
