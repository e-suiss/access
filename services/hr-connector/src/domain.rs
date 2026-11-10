//! What a connector sends (OP-156 m.3 (q)): one HR record per person in the line format of
//! Access's HR batch API, and the batches it pushes. Sans-I/O.

pub mod vendor;

use std::fmt::Write as _;

use serde::Serialize;

/// Most records one batch carries; Access takes at most 10 000.
pub const BATCH_RECORDS: usize = 1000;

/// Largest batch body, in bytes, kept under Access's request limits.
pub const BATCH_BYTES: usize = 192 * 1024;

/// One record as Access's HR batch API reads it: dates are `YYYY-MM-DD`.
#[derive(Clone, Default, PartialEq, Eq, Serialize)]
pub struct Record {
    /// The HR system's id of the person.
    pub employee_id: String,
    /// The person's work e-mail address.
    pub email: String,
    /// Department.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// Job title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The manager's employee id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,
    /// The start date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_date: Option<String>,
    /// The end date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date: Option<String>,
    /// The employment status as the HR system names it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub employment_status: Option<String>,
}

impl core::fmt::Debug for Record {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Record")
            .field("start_date", &self.start_date)
            .field("end_date", &self.end_date)
            .finish_non_exhaustive()
    }
}

/// One batch: its JSONL text, its SHA-256 and its record count, what `idp.hr.import` names.
#[derive(Clone, PartialEq, Eq)]
pub struct Batch {
    /// The JSONL text.
    pub content: String,
    /// Its record count.
    pub records: u32,
}

impl core::fmt::Debug for Batch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Batch")
            .field("records", &self.records)
            .finish_non_exhaustive()
    }
}

impl Batch {
    /// The SHA-256 of the content.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        suiss_crypto::digest::sha256(self.content.as_bytes())
    }
}

/// `records` as batches of at most [`BATCH_RECORDS`] records and [`BATCH_BYTES`] bytes, each
/// person once (the first record of an employee id wins).
#[must_use]
pub fn batches(records: &[Record]) -> Vec<Batch> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    let mut current = String::new();
    let mut count = 0_u32;
    for r in records {
        if !seen.insert(r.employee_id.as_str()) {
            continue;
        }
        let Ok(line) = serde_json::to_string(r) else {
            continue;
        };
        let full = usize::try_from(count).is_ok_and(|c| c >= BATCH_RECORDS)
            || current.len().saturating_add(line.len()).saturating_add(1) > BATCH_BYTES;
        if full && count > 0 {
            out.push(Batch {
                content: core::mem::take(&mut current),
                records: count,
            });
            count = 0;
        }
        let _ = writeln!(current, "{line}");
        count = count.saturating_add(1);
    }
    if count > 0 {
        out.push(Batch {
            content: current,
            records: count,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    // OP-156 m.3 (q)
    #[test]
    fn batches_stay_within_the_limits_and_name_each_person_once() {
        let people: Vec<Record> = (0..2500)
            .map(|i| Record {
                employee_id: format!("E{}", i % 2400),
                email: format!("p{i}@acme.example"),
                ..Record::default()
            })
            .collect();
        let b = batches(&people);
        assert_eq!(b.iter().map(|b| b.records).sum::<u32>(), 2400);
        assert!(
            b.iter()
                .all(|b| b.records <= 1000 && b.content.len() <= BATCH_BYTES)
        );
        assert_eq!(b[0].content.lines().count(), 1000);
        assert_eq!(batches(&[]), Vec::new());
    }
}
