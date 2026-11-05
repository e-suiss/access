//! Offline Exercise Reports (§9.12.2, L2-RPT-1 to L2-RPT-3): what an offline verifier sends
//! when it reconnects, and the hash chain that makes a hidden or reordered entry detectable.
//! A report is a Claim; it never changes authority state or what remains of a budget (E5,
//! PI-22).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::codec::{Canonical, Fields, ModelError, map, set_of, set_value, uint};
use crate::digest::Digest;
use crate::model::{Id, Window};
use crate::validity::{word, word_of};

/// Digest context of a chain link (L2-RPT-2).
pub const CHAIN_CONTEXT: &str = "access/report-chain/v1";

/// The verifier's local outcome for one use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LocalOutcome {
    /// Allowed locally.
    Allow,
    /// Denied locally.
    Deny,
}

const OUTCOMES: [(&str, LocalOutcome); 2] =
    [("allow", LocalOutcome::Allow), ("deny", LocalOutcome::Deny)];

/// An amount against one budget term of the contract's offline slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SliceAmount {
    /// The budget term.
    pub budget_term: Digest,
    /// The amount.
    pub amount: u64,
}

/// One local use (§9.12.2 `entries[]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The intent digest.
    pub intent: Digest,
    /// Digest of the authority-relevant parameters.
    pub params: Option<Digest>,
    /// Verifier-local time.
    pub time: u64,
    /// Clock evidence.
    pub clock_evidence: Option<Digest>,
    /// The local outcome.
    pub outcome: LocalOutcome,
    /// What the use drew from the slice; only an `allow` draws.
    pub drawn: BTreeSet<SliceAmount>,
    /// The holder's proof of possession.
    pub holder_proof: Option<Digest>,
}

/// An Offline Exercise Report body (§9.12.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// Digest of the verifier's profile.
    pub verifier_profile: Digest,
    /// The verifier's Instance, if it has one.
    pub verifier_instance: Option<Id>,
    /// The `projection.issue` `ExerciseID`.
    pub exercise: Digest,
    /// Digest of the contract.
    pub contract: Digest,
    /// Local time span covered.
    pub period: Window,
    /// Head of the previous report for this projection.
    pub previous: Option<Digest>,
    /// Sequence number of the first entry.
    pub first_seq: u64,
    /// Entries in sequence order.
    pub entries: Vec<Entry>,
    /// Chain head after the last entry.
    pub head: Digest,
    /// Unused slice.
    pub slice_unused: BTreeSet<SliceAmount>,
    /// Profile version applied.
    pub profile_version: u64,
}

impl Canonical for SliceAmount {
    fn to_value(&self) -> Value {
        map([
            ("budget_term", Some(self.budget_term.to_value())),
            ("amount", Some(Value::Unsigned(self.amount))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let s = Self {
            budget_term: Digest::from_value(f.req("budget_term")?).ok_or(ModelError::Shape)?,
            amount: uint(f.req("amount")?)?,
        };
        f.done()?;
        Ok(s)
    }
}

fn opt_digest(f: &mut Fields<'_>, key: &str) -> Result<Option<Digest>, ModelError> {
    f.opt(key)
        .map(|v| Digest::from_value(v).ok_or(ModelError::Shape))
        .transpose()
}

fn amounts(s: &BTreeSet<SliceAmount>) -> Option<Value> {
    (!s.is_empty()).then(|| set_value(s.iter().map(Canonical::to_value)))
}

impl Canonical for Entry {
    fn to_value(&self) -> Value {
        map([
            ("intent", Some(self.intent.to_value())),
            ("params", self.params.as_ref().map(Canonical::to_value)),
            ("time", Some(Value::Unsigned(self.time))),
            (
                "clock_evidence",
                self.clock_evidence.as_ref().map(Canonical::to_value),
            ),
            ("outcome", Some(word_of(self.outcome, &OUTCOMES))),
            ("drawn", amounts(&self.drawn)),
            (
                "holder_proof",
                self.holder_proof.as_ref().map(Canonical::to_value),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let e = Self {
            intent: Digest::from_value(f.req("intent")?).ok_or(ModelError::Shape)?,
            params: opt_digest(&mut f, "params")?,
            time: uint(f.req("time")?)?,
            clock_evidence: opt_digest(&mut f, "clock_evidence")?,
            outcome: word(f.req("outcome")?, &OUTCOMES)?,
            drawn: f
                .opt("drawn")
                .map(|d| set_of(d, true, SliceAmount::from_value))
                .transpose()?
                .unwrap_or_default(),
            holder_proof: opt_digest(&mut f, "holder_proof")?,
        };
        f.done()?;
        if e.drawn.iter().any(|d| d.amount == 0) {
            return Err(ModelError::Range);
        }
        Ok(e)
    }
}

impl Canonical for Report {
    fn to_value(&self) -> Value {
        map([
            (
                "verifier",
                Some(map([
                    ("profile", Some(self.verifier_profile.to_value())),
                    (
                        "instance",
                        self.verifier_instance.as_ref().map(Canonical::to_value),
                    ),
                ])),
            ),
            (
                "projection",
                Some(map([
                    ("exercise", Some(self.exercise.to_value())),
                    ("contract", Some(self.contract.to_value())),
                ])),
            ),
            ("period", Some(self.period.to_value())),
            ("previous", self.previous.as_ref().map(Canonical::to_value)),
            ("first_seq", Some(Value::Unsigned(self.first_seq))),
            (
                "entries",
                Some(Value::Array(
                    self.entries.iter().map(Canonical::to_value).collect(),
                )),
            ),
            ("head", Some(self.head.to_value())),
            ("slice_unused", amounts(&self.slice_unused)),
            (
                "profile_version",
                Some(Value::Unsigned(self.profile_version)),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let mut vf = Fields::of(f.req("verifier")?)?;
        let verifier_profile = Digest::from_value(vf.req("profile")?).ok_or(ModelError::Shape)?;
        let verifier_instance = vf.opt("instance").map(Id::from_value).transpose()?;
        vf.done()?;
        let mut pf = Fields::of(f.req("projection")?)?;
        let exercise = Digest::from_value(pf.req("exercise")?).ok_or(ModelError::Shape)?;
        let contract = Digest::from_value(pf.req("contract")?).ok_or(ModelError::Shape)?;
        pf.done()?;
        let Value::Array(items) = f.req("entries")? else {
            return Err(ModelError::Shape);
        };
        let r = Self {
            verifier_profile,
            verifier_instance,
            exercise,
            contract,
            period: Window::from_value(f.req("period")?)?,
            previous: opt_digest(&mut f, "previous")?,
            first_seq: uint(f.req("first_seq")?)?,
            entries: items
                .iter()
                .map(Entry::from_value)
                .collect::<Result<_, _>>()?,
            head: Digest::from_value(f.req("head")?).ok_or(ModelError::Shape)?,
            slice_unused: f
                .opt("slice_unused")
                .map(|d| set_of(d, true, SliceAmount::from_value))
                .transpose()?
                .unwrap_or_default(),
            profile_version: uint(f.req("profile_version")?)?,
        };
        f.done()?;
        Ok(r)
    }
}

/// Why a report is refused (L2-RPT-3). Each is a protocol error; the report is not recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReportError {
    /// Not a report body.
    #[error("report-malformed")]
    Malformed,
    /// `previous` is present exactly when `first_seq` is not 0.
    #[error("report-start")]
    Start,
    /// An entry lies outside the period.
    #[error("report-period")]
    Period,
    /// A `deny` entry draws from the slice, or a total overflows.
    #[error("report-entry")]
    Entry,
    /// The chain does not lead to `head`.
    #[error("report-chain")]
    Chain,
}

impl ReportError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "report-malformed",
            Self::Start => "report-start",
            Self::Period => "report-period",
            Self::Entry => "report-entry",
            Self::Chain => "report-chain",
        }
    }
}

fn chain_digest(v: &Value) -> Result<Digest, ReportError> {
    let bytes = dcbor::encode(v, Limits::CEILING).map_err(|_| ReportError::Malformed)?;
    Ok(Digest(context_digest(CHAIN_CONTEXT, &bytes).0))
}

/// The start of a projection's chain: the digest of `[exercise, contract]` (L2-RPT-2).
///
/// # Errors
/// [`ReportError::Malformed`] when it cannot be encoded.
pub fn seed(exercise: &Digest, contract: &Digest) -> Result<Digest, ReportError> {
    chain_digest(&Value::Array(alloc::vec![
        exercise.to_value(),
        contract.to_value()
    ]))
}

/// The link after `previous` for the entry numbered `seq`: the digest of `[previous, seq,
/// entry]` (L2-RPT-2).
///
/// # Errors
/// [`ReportError::Malformed`] when it cannot be encoded.
pub fn link(previous: &Digest, seq: u64, entry: &Entry) -> Result<Digest, ReportError> {
    chain_digest(&Value::Array(alloc::vec![
        previous.to_value(),
        Value::Unsigned(seq),
        entry.to_value()
    ]))
}

/// What a verified report says about its chain and its draws.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// The chain head; the next report names it in `previous`.
    pub head: Digest,
    /// The sequence number the next report starts at.
    pub next_seq: u64,
    /// The total drawn per budget term by the `allow` entries.
    pub drawn: BTreeMap<Digest, u64>,
}

/// Checks a report body (L2-RPT-3): `previous` is present exactly when `first_seq` is not 0,
/// every entry lies in the period, only `allow` entries draw, and the chain from `previous` (or
/// the projection's seed) through every entry leads to `head`.
///
/// # Errors
/// [`ReportError`].
pub fn verify(report: &Report) -> Result<Summary, ReportError> {
    if report.previous.is_some() != (report.first_seq != 0) {
        return Err(ReportError::Start);
    }
    let mut head = match report.previous {
        Some(p) => p,
        None => seed(&report.exercise, &report.contract)?,
    };
    let mut seq = report.first_seq;
    let mut drawn: BTreeMap<Digest, u64> = BTreeMap::new();
    for e in &report.entries {
        if e.time < report.period.from || e.time > report.period.until {
            return Err(ReportError::Period);
        }
        if e.outcome == LocalOutcome::Deny && !e.drawn.is_empty() {
            return Err(ReportError::Entry);
        }
        for d in &e.drawn {
            let total = drawn.entry(d.budget_term).or_insert(0);
            *total = total.checked_add(d.amount).ok_or(ReportError::Entry)?;
        }
        head = link(&head, seq, e)?;
        seq = seq.checked_add(1).ok_or(ReportError::Chain)?;
    }
    if head != report.head {
        return Err(ReportError::Chain);
    }
    Ok(Summary {
        head,
        next_seq: seq,
        drawn,
    })
}

/// Decodes and checks a report body (L2-RPT-1, L2-RPT-3).
///
/// # Errors
/// [`ReportError`].
pub fn verify_bytes(body: &[u8]) -> Result<(Report, Summary), ReportError> {
    let report = Report::from_bytes(body).map_err(|_| ReportError::Malformed)?;
    let summary = verify(&report)?;
    Ok((report, summary))
}

/// Whether `report` continues the chain a previous report of the projection ended with
/// (L2-RPT-2): it names that head and starts at the next sequence number. A report that does
/// not continue leaves a gap the reconciliation view shows.
#[must_use]
pub fn continues(previous: &Summary, report: &Report) -> bool {
    report.previous == Some(previous.head) && report.first_seq == previous.next_seq
}

#[cfg(test)]
mod tests;
