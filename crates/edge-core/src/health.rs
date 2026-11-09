//! The health and metrics layer (§10.6, OP-47, OP-67): per-call counters labelled only by call
//! and outcome, never by tenant, realm or subject, in the Prometheus text format; and the
//! lockdown state for `/healthz`.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use access_internal_api::edge::Call;

/// The outcome of one edge call or parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Answered.
    Ok,
    /// Refused by access-server or a parser limit.
    Refused,
    /// No answer, or the parser worker failed.
    Failed,
}

const OUTCOMES: [(Outcome, &str); 3] = [
    (Outcome::Ok, "ok"),
    (Outcome::Refused, "refused"),
    (Outcome::Failed, "failed"),
];

/// Counters of one gateway process.
#[derive(Debug, Default)]
pub struct Health {
    calls: [[AtomicU64; 3]; 7],
    parses: [AtomicU64; 3],
}

fn slot(o: Outcome) -> usize {
    match o {
        Outcome::Ok => 0,
        Outcome::Refused => 1,
        Outcome::Failed => 2,
    }
}

fn call_slot(c: Call) -> usize {
    Call::all().iter().position(|x| *x == c).unwrap_or(0)
}

impl Health {
    /// Counts one edge call.
    pub fn call(&self, c: Call, o: Outcome) {
        if let Some(n) = self.calls.get(call_slot(c)).and_then(|r| r.get(slot(o))) {
            n.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Counts one parse.
    pub fn parse(&self, o: Outcome) {
        if let Some(n) = self.parses.get(slot(o)) {
            n.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The counters in the Prometheus text format; labels are `call` and `outcome` only (OP-47).
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from("# TYPE access_edge_calls_total counter\n");
        for c in Call::all() {
            for (o, name) in OUTCOMES {
                let n = self
                    .calls
                    .get(call_slot(c))
                    .and_then(|r| r.get(slot(o)))
                    .map_or(0, |n| n.load(Ordering::Relaxed));
                let _ = writeln!(
                    out,
                    "access_edge_calls_total{{call=\"{}\",outcome=\"{name}\"}} {n}",
                    c.name()
                );
            }
        }
        out.push_str("# TYPE access_edge_parses_total counter\n");
        for (o, name) in OUTCOMES {
            let n = self
                .parses
                .get(slot(o))
                .map_or(0, |n| n.load(Ordering::Relaxed));
            let _ = writeln!(out, "access_edge_parses_total{{outcome=\"{name}\"}} {n}");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-47
    #[test]
    fn metrics_carry_no_tenant_or_realm_label() {
        let h = Health::default();
        h.call(Call::IssueClaim, Outcome::Refused);
        h.parse(Outcome::Failed);
        let text = h.render();
        assert!(
            text.contains("access_edge_calls_total{call=\"issue_claim\",outcome=\"refused\"} 1")
        );
        assert!(text.contains("access_edge_parses_total{outcome=\"failed\"} 1"));
        for forbidden in ["tenant=", "realm=", "subject=", "domain="] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }
}
