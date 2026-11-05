//! Running the cases against an adapter and judging each one.

use std::fmt::Write as _;
use std::future::Future;
use std::time::Duration;

use serde::Serialize;

use crate::case::{Case, Expect};
use crate::protocol::{CaseMessage, CaseResult, Outcome};
use crate::upstream::{Upstream, UpstreamError};
use crate::verdict::{Verdict, judge};

/// Why an adapter exchange failed.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// The adapter broke the protocol.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The adapter process is gone or its pipes failed.
    #[error("adapter: {0}")]
    Io(String),
}

/// A PEP under test.
pub trait Adapter {
    /// Sends one case and waits up to `wait` for its result; `Ok(None)` when none came.
    fn exchange(
        &mut self,
        msg: &CaseMessage,
        wait: Duration,
    ) -> impl Future<Output = Result<Option<CaseResult>, AdapterError>>;
}

/// One judged case.
#[derive(Clone, Debug, Serialize)]
pub struct CaseReport {
    /// Case ID.
    pub id: String,
    /// Rule IDs.
    pub rules: Vec<String>,
    /// Expected effect.
    pub expect: Expect,
    /// What the PEP answered.
    pub outcome: Option<Outcome>,
    /// The PEP's own explanation.
    pub detail: Option<String>,
    /// Effects the resource received.
    pub effects: u32,
    /// The judgement.
    #[serde(flatten)]
    pub verdict: Verdict,
}

/// Why a run stopped.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// A message could not be built.
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
    /// The adapter failed.
    #[error(transparent)]
    Adapter(#[from] AdapterError),
}

/// Runs every case in order. The adapter gets `deadline_ms` for upstream calls and the
/// runner waits `deadline_ms + grace` for each result.
///
/// # Errors
/// [`RunError`] when the adapter breaks the protocol.
pub async fn run(
    upstream: &Upstream,
    cases: &[Case],
    adapter: &mut impl Adapter,
    deadline_ms: u64,
    grace: Duration,
) -> Result<Vec<CaseReport>, RunError> {
    let mut out = Vec::with_capacity(cases.len());
    let wait = Duration::from_millis(deadline_ms).saturating_add(grace);
    for case in cases {
        let msg = upstream.message(case, deadline_ms)?;
        let result = adapter.exchange(&msg, wait).await?;
        if let Some(r) = &result
            && r.case != case.id
        {
            return Err(AdapterError::Protocol(format!(
                "result for {} while {} runs",
                r.case, case.id
            ))
            .into());
        }
        let outcome = result.as_ref().map(|r| r.outcome);
        let effects = upstream.effects(&case.id);
        out.push(CaseReport {
            id: case.id.clone(),
            rules: case.rules.clone(),
            expect: case.expect,
            outcome,
            detail: result.and_then(|r| r.detail),
            effects,
            verdict: judge(case.expect, outcome, effects),
        });
    }
    Ok(out)
}

/// The report as text, one line per case and a summary.
#[must_use]
pub fn render(name: &str, reports: &[CaseReport]) -> String {
    let mut out = format!("PEP conformance: {name}\n");
    for r in reports {
        let (mark, why) = match &r.verdict {
            Verdict::Pass => ("pass     ", String::new()),
            Verdict::Leak { reason } => ("LEAK     ", format!(": {reason}")),
            Verdict::Fail { reason } => ("FAIL     ", format!(": {reason}")),
        };
        let _ = writeln!(out, "{mark} {}{why}", r.id);
    }
    let passed = reports.iter().filter(|r| r.verdict.passed()).count();
    let open = reports
        .iter()
        .filter(|r| matches!(r.verdict, Verdict::Leak { .. }))
        .count();
    let _ = writeln!(
        out,
        "{passed}/{} passed, {open} leaked an effect",
        reports.len()
    );
    out
}
