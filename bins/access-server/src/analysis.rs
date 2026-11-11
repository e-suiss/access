//! The control-plane SMT analysis of restriction policy changes (OP-105, OP-157 m.3 (n)): the
//! pinned cvc5 the operator names in `[policy] analyzer`, run in the solver sandbox. It may only
//! raise a structurally narrowing `policy.set` to expansion; the Kernel's structural rule stays
//! binding.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use access_authority_core::ports::{Comparing, NoAnalysis, PolicyAnalysis, PolicyRelation};
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

/// The analysis the configuration names: the pinned solver, or none.
///
/// # Errors
/// `[policy] analyzer` is set but no cvc5 is pinned for this platform or the pin is unreadable;
/// the server does not start rather than run without the analysis it was told to use.
pub(crate) fn configured(config: &Config) -> Result<Arc<dyn PolicyAnalysis>, String> {
    match &config.policy.analyzer {
        None => Ok(Arc::new(NoAnalysis)),
        Some(path) => Smt::pinned(path)
            .map(|s| Arc::new(s) as Arc<dyn PolicyAnalysis>)
            .map_err(|e| format!("policy.analyzer {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests;
