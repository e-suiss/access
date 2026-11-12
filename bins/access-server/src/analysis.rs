//! The control-plane SMT analysis of restriction policy changes (OP-105, OP-157 m.3 (n)): the
//! pinned cvc5 the operator names in `[policy] analyzer`, run in the solver sandbox. It may only
//! raise a structurally narrowing `policy.set` to expansion; the Kernel's structural rule stays
//! binding.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use access_authority_core::ports::{Comparing, NoAnalysis, PolicyAnalysis, PolicyRelation};
use restriction_analysis::sibling::{Client, Relation, SocketError};
use restriction_analysis::{Change, Cvc5, Limits, Timeouts};

use crate::config::Config;

/// Time limits on the commit path: one solver query and the whole comparison (OP-157 m.3 (n),
/// PD). A limit hit is no answer, which raises the change.
pub(crate) const TIMEOUTS: Timeouts = Timeouts {
    query: Duration::from_secs(10),
    total: Duration::from_secs(30),
};

/// The pinned cvc5 behind the analysis port.
pub(crate) struct Smt(Arc<Cvc5>);

impl Smt {
    /// The solver at `path`, bound to this platform's pin and confined to the solver profile.
    ///
    /// # Errors
    /// No cvc5 is pinned for this platform, or the pin is unreadable.
    pub(crate) fn pinned(path: &Path) -> Result<Self, restriction_analysis::AnalysisError> {
        Ok(Self(Arc::new(Cvc5::pinned(path, TIMEOUTS, confine)?)))
    }
}

// OP-115 m.6
fn confine(command: &mut std::process::Command, solver: &Path) -> std::io::Result<()> {
    suiss_sandbox::Lockdown::new(
        suiss_sandbox::Profile::Solver,
        suiss_sandbox::LandlockAbi::REQUIRED,
    )
    .allow_execute(solver)
    .confine(command)
    .map_err(std::io::Error::other)
}

/// The port's answer for the analysis's: every failure is no answer, never equivalence.
pub(crate) const fn relation(change: &Change) -> PolicyRelation {
    match change {
        Change::Equivalent => PolicyRelation::Equivalent,
        Change::Narrowing => PolicyRelation::Narrowing,
        Change::Widening(_) => PolicyRelation::Widening,
        Change::Incomparable(_) => PolicyRelation::Incomparable,
        Change::MayError(_) => PolicyRelation::MayError,
        Change::Unknown(_) => PolicyRelation::Unknown,
    }
}

impl PolicyAnalysis for Smt {
    fn compare<'a>(&'a self, schema: &'a str, old: &'a str, new: &'a str) -> Comparing<'a> {
        let cvc5 = self.0.clone();
        let (schema, old, new) = (schema.to_owned(), old.to_owned(), new.to_owned());
        Box::pin(async move {
            let ran = tokio::task::spawn_blocking(move || {
                restriction_analysis::compare(&cvc5, &schema, &old, &new, Limits::default())
            })
            .await;
            ran.map_or(PolicyRelation::Unknown, |c| relation(&c))
        })
    }
}

/// How long the server waits for the sibling solver beyond its own total limit.
const SIBLING_GRACE: Duration = Duration::from_secs(5);

/// The `access-policy-solver` sibling process behind the analysis port (OP-157 m.8 (a),
/// OP-159 m.3 (aa)). The server starts no process; an unreachable, unsafe or slow socket is no
/// answer, which raises the change (OP-157 m.8 (b)).
pub(crate) struct Sibling(Client);

impl Sibling {
    /// The solver at `socket`, which must be owned by `owner` (by default its directory's owner).
    ///
    /// # Errors
    /// The socket exists but its owner or mode, or its directory, is not safe.
    pub(crate) fn new(socket: &Path, owner: Option<u32>) -> Result<Self, String> {
        let wait = TIMEOUTS.total.saturating_add(SIBLING_GRACE);
        let client = Client::new(socket.to_path_buf(), owner, wait);
        match client.check() {
            Ok(()) | Err(SocketError::Missing(_)) => Ok(Self(client)),
            Err(e) => Err(e.to_string()),
        }
    }
}

impl PolicyAnalysis for Sibling {
    fn compare<'a>(&'a self, schema: &'a str, old: &'a str, new: &'a str) -> Comparing<'a> {
        let client = self.0.clone();
        let (schema, old, new) = (schema.to_owned(), old.to_owned(), new.to_owned());
        Box::pin(async move {
            let wait = TIMEOUTS.total.saturating_add(SIBLING_GRACE);
            let ran = tokio::time::timeout(
                wait,
                tokio::task::spawn_blocking(move || client.compare(&schema, &old, &new)),
            )
            .await;
            let relation = match ran {
                Ok(Ok(r)) => r,
                _ => Relation::Unknown,
            };
            if relation == Relation::Unknown {
                tracing::warn!(
                    event = "policy.analyzer.unavailable",
                    reason = "sibling",
                    "the policy solver gave no answer; the change is raised"
                );
            }
            sibling_relation(relation)
        })
    }
}

/// The port's answer for the sibling's.
pub(crate) const fn sibling_relation(r: Relation) -> PolicyRelation {
    match r {
        Relation::Equivalent => PolicyRelation::Equivalent,
        Relation::Narrowing => PolicyRelation::Narrowing,
        Relation::Widening => PolicyRelation::Widening,
        Relation::Incomparable => PolicyRelation::Incomparable,
        Relation::MayError => PolicyRelation::MayError,
        Relation::Unknown => PolicyRelation::Unknown,
    }
}

/// The analysis the configuration names: the sibling solver, the pinned solver, or none.
///
/// # Errors
/// Both `[policy] analyzer` and `solver` are set; `analyzer` is set but no cvc5 is pinned for
/// this platform or the pin is unreadable; or the solver socket is not safe. The server does not
/// start rather than run without the analysis it was told to use.
pub(crate) fn configured(config: &Config) -> Result<Arc<dyn PolicyAnalysis>, String> {
    match (&config.policy.analyzer, &config.policy.solver) {
        (Some(_), Some(_)) => Err("policy.analyzer and policy.solver are exclusive".to_owned()),
        (None, Some(socket)) => Sibling::new(socket, config.policy.solver_owner)
            .map(|s| Arc::new(s) as Arc<dyn PolicyAnalysis>)
            .map_err(|e| format!("policy.solver: {e}")),
        (None, None) => Ok(Arc::new(NoAnalysis)),
        (Some(path), None) => Smt::pinned(path)
            .map(|s| Arc::new(s) as Arc<dyn PolicyAnalysis>)
            .map_err(|e| format!("policy.analyzer {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests;
