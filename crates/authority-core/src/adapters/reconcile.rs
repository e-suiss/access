//! Offline reconciliation, the authority side (§7.9.4.1, §9.12.2, L2-RPT-2, L2-RPT-3, SEC14):
//! an admitted `offline_exercise_report` Claim is bound to the projection it names, checked
//! against the chain the last report ended with and against the issued contract, and what it
//! came to is recorded as derived state. A report changes no counter and no authority: the slice
//! was drawn when the projection was issued, and an unused slice comes back only through a
//! grounded `consumption.release` (E5, PI-22, INV-21).

use std::collections::BTreeMap;

use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::model::Id;
use access_kernel::report::{self, LocalOutcome, Report, Summary};
use access_kernel::validity::ValidityContract;
use access_kernel::validity::ceiling::report_deadline;
use access_store::Pool;
use access_store::offline::{
    ContractRow, ReconciliationRow, ReportRow, contract_of, last_report, reports,
};
use access_store::scope::DomainId;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;
use crate::app::Reported;

/// What a report came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reconciled {
    /// The projection.
    pub exercise: Digest,
    /// The report names the contract this domain issued for the projection.
    pub bound: bool,
    /// The report continues the last recorded head (L2-RPT-2); a report whose own chain does
    /// not verify is recorded as discontinuous and does not count as a report.
    pub continuous: bool,
    /// The report arrived after `horizon + 24 h` (SEC14).
    pub late: bool,
    /// Entries inside the contract.
    pub in_contract: u32,
    /// Entries outside it.
    pub out_of_contract: u32,
}

/// The slice terms of a recorded contract with their amounts, and its issuance and horizon.
fn issued(c: &ContractRow) -> Option<(BTreeMap<Digest, u64>, u64, u64)> {
    let vc = ValidityContract::from_bytes(&c.contract).ok()?;
    let slice = vc
        .offline_slice
        .iter()
        .map(|s| (s.budget_term, s.amount))
        .collect();
    Some((slice, c.iat_ms, c.horizon_ms))
}

/// Whether the entry at `time`, drawing `drawn` on top of `used`, lies inside the contract: in
/// the window, and only drawing from the slice, within it (§9.12.2).
fn within(
    (slice, iat, horizon): &(BTreeMap<Digest, u64>, u64, u64),
    used: &mut BTreeMap<Digest, u64>,
    entry: &report::Entry,
) -> bool {
    if entry.time < *iat || entry.time > *horizon {
        return false;
    }
    if entry.outcome == LocalOutcome::Deny {
        return true;
    }
    let mut ok = true;
    for d in &entry.drawn {
        let total = used.entry(d.budget_term).or_insert(0);
        *total = total.saturating_add(d.amount);
        if slice
            .get(&d.budget_term)
            .is_none_or(|amount| *total > *amount)
        {
            ok = false;
        }
    }
    ok
}

fn unused_bytes(report: &Report) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(
            report
                .slice_unused
                .iter()
                .map(access_kernel::codec::Canonical::to_value)
                .collect(),
        ),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

/// Whether `body` reads as an Offline Exercise Report.
pub(super) fn is_report(body: &[u8]) -> bool {
    Report::from_bytes(body).is_ok()
}

/// Reconciles the report `body` of Claim `claim` before its record commits (§7.9.4.1, SI-7,
/// §16.5.1): binds it to its projection, checks the chain and derives the in-contract and
/// out-of-contract entries. The rows are written in the commit of the Claim record, at its
/// position, once it is admitted: the report row only for a report whose chain verifies, the
/// reconciliation row for every one.
///
/// # Errors
/// [`CoreError::Store`]; a body that is not a report is [`CoreError::Protocol`].
pub(super) async fn prepare(
    app: &Pool,
    domain: Digest,
    claim: Id,
    body: &[u8],
    now: u64,
) -> Result<Reported, CoreError> {
    let id = DomainId::from_bytes(domain.0);
    let (report, summary) = match report::verify_bytes(body) {
        Ok(v) => v,
        Err(e) => {
            let r = Report::from_bytes(body).map_err(|_| CoreError::Protocol(e.code()))?;
            let out = Reconciled {
                exercise: r.exercise,
                bound: false,
                continuous: false,
                late: false,
                in_contract: 0,
                out_of_contract: u32::try_from(r.entries.len()).unwrap_or(u32::MAX),
            };
            return Ok(Reported {
                report: None,
                reconciliation: reconciliation(claim, &r, &out),
                verifiers: Vec::new(),
            });
        }
    };
    let contract = contract_of(app, &id, &report.exercise.0).await?;
    let terms = contract.as_ref().and_then(issued);
    let bound = contract
        .as_ref()
        .is_some_and(|c| c.contract_digest == report.contract.0);
    // L2-RPT-2
    let previous = last_report(app, &id, &report.exercise.0).await?;
    let continuous = match &previous {
        Some(p) => report::continues(
            &Summary {
                head: Digest(p.head),
                next_seq: p.next_seq,
                drawn: BTreeMap::new(),
            },
            &report,
        ),
        None => report.previous.is_none() && report.first_seq == 0,
    };
    let mut used: BTreeMap<Digest, u64> = BTreeMap::new();
    for earlier in reports(app, &id, &report.exercise.0).await? {
        if let Ok((_, s)) = report::verify_bytes(&earlier.body) {
            for (term, amount) in s.drawn {
                let total = used.entry(term).or_insert(0);
                *total = total.saturating_add(amount);
            }
        }
    }
    let (mut inside, mut outside) = (0_u32, 0_u32);
    for e in &report.entries {
        let ok = match (bound, &terms) {
            (true, Some(t)) => within(t, &mut used, e),
            _ => false,
        };
        if ok {
            inside = inside.saturating_add(1);
        } else {
            outside = outside.saturating_add(1);
        }
    }
    let late = terms
        .as_ref()
        .is_some_and(|(_, _, horizon)| now > report_deadline(*horizon));
    let out = Reconciled {
        exercise: report.exercise,
        bound,
        continuous,
        late,
        in_contract: inside,
        out_of_contract: outside,
    };
    let chained = report.previous.is_none() == (report.first_seq == 0)
        && summary.next_seq >= report.first_seq
        && report.period.until >= report.period.from;
    let row = chained.then(|| ReportRow {
        pos: 0,
        claim: claim.0,
        exercise: report.exercise.0,
        previous: report.previous.map(|p| p.0),
        first_seq: report.first_seq,
        next_seq: summary.next_seq,
        head: summary.head.0,
        period_from_ms: report.period.from,
        period_until_ms: report.period.until,
        body: body.to_vec(),
    });
    Ok(Reported {
        report: row,
        reconciliation: reconciliation(claim, &report, &out),
        verifiers: contract.map(|c| c.audiences).unwrap_or_default(),
    })
}

fn reconciliation(claim: Id, report: &Report, out: &Reconciled) -> ReconciliationRow {
    ReconciliationRow {
        pos: 0,
        claim: claim.0,
        exercise: report.exercise.0,
        bound: out.bound,
        continuous: out.continuous,
        late: out.late,
        in_contract: out.in_contract,
        out_of_contract: out.out_of_contract,
        slice_unused: unused_bytes(report),
    }
}
