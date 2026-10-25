//! Control-plane SMT analysis of Access Restriction Profile changes (OP-105): Cedar `SymCC` with a
//! pinned cvc5 running as a separate process. Never on the request path and never in the Kernel.

mod pin;
mod solver;

use std::collections::{BTreeMap, BTreeSet};

use cedar_policy::{Policy, PolicySet, RequestEnv, Schema};
use cedar_policy_symcc::solver::LocalSolver;
use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicy, CompiledPolicySet, Env};
use suiss_restriction::{Engine, PolicyView};

pub use solver::{Confine, Cvc5, Timeouts};
pub use suiss_restriction::{CompileError, Limits};

/// The result of comparing an old and a new policy set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every request gets the same outcome under both sets.
    Equivalent,
    /// Every request is at least as restricted under the new set, and some request is more.
    Narrowing,
    /// Some request is less restricted under the new set.
    Widening(Widening),
    /// A policy of one of the sets can raise an evaluation error (OP-104 m.5).
    MayError(MayError),
}

/// Where the new set is weaker than the old one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Widening {
    /// The request environment, `None` for a syntactic finding.
    pub env: Option<RequestEnvironment>,
    /// What got weaker.
    pub reason: WideningReason,
    /// A request showing it, when the solver gave one.
    pub counterexample: Option<Counterexample>,
}

/// What got weaker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WideningReason {
    /// A request the old set denied is not denied by the new set.
    Deny,
    /// A request for which the old set required `reference` is neither denied nor requires it.
    Require {
        /// The `@require` reference.
        reference: String,
    },
    /// The `@require` reference of policy `id` changed (OP-104 m.6).
    RequireChanged {
        /// The policy `@id`.
        id: String,
        /// Old reference.
        old: String,
        /// New reference.
        new: String,
    },
}

/// Which input set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The set in force.
    Old,
    /// The proposed set.
    New,
}

/// A policy that can raise an evaluation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MayError {
    /// Which set it belongs to.
    pub side: Side,
    /// Its `@id`.
    pub id: String,
    /// The request environment.
    pub env: RequestEnvironment,
    /// A request that makes it error, when the solver gave one.
    pub counterexample: Option<Counterexample>,
}

/// One action / principal type / resource type combination of the schema.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestEnvironment {
    /// Principal entity type.
    pub principal: String,
    /// Action entity uid.
    pub action: String,
    /// Resource entity type.
    pub resource: String,
}

/// A concrete request synthesised by the solver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counterexample {
    /// The request, in Cedar's display form.
    pub request: String,
    /// The entity store, as Cedar entity JSON.
    pub entities: String,
}

/// Why no verdict was reached. Every variant is fail-closed: the change must not be applied.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AnalysisError {
    /// The old set does not compile under the restriction rules.
    #[error("old policy set rejected: {0}")]
    Old(CompileError),
    /// The new set does not compile under the restriction rules.
    #[error("new policy set rejected: {0}")]
    New(CompileError),
    /// `SymCC` could not compile a set or the engine state was inconsistent.
    #[error("symbolic compilation failed")]
    Symbolic,
    /// `supply-chain/cvc5.toml` is unreadable.
    #[error("bad cvc5 pin")]
    Pin,
    /// No cvc5 is pinned for this platform.
    #[error("no cvc5 pinned for this platform")]
    UnsupportedPlatform,
    /// The configured cvc5 cannot be read or started.
    #[error("cvc5 unavailable")]
    SolverUnavailable,
    /// The solver sandbox could not be prepared (OP-115 m.6).
    #[error("solver sandbox unavailable")]
    Sandbox,
    /// The configured cvc5 does not match the pin (OP-105).
    #[error("cvc5 does not match the pinned sha256")]
    PinMismatch,
    /// The solver failed or exited.
    #[error("solver failed")]
    Solver,
    /// The solver answered `unknown`.
    #[error("solver returned unknown")]
    Unknown,
    /// A time limit was hit.
    #[error("solver timed out")]
    Timeout,
    /// A counterexample could not be decoded.
    #[error("counterexample could not be decoded")]
    Counterexample,
}

impl From<cedar_policy_symcc::err::Error> for AnalysisError {
    fn from(e: cedar_policy_symcc::err::Error) -> Self {
        use cedar_policy_symcc::err::Error as E;
        match e {
            E::SolverUnknown => Self::Unknown,
            E::SolverError(_) => Self::Solver,
            E::DecodeModel(_) | E::ConcretizeError(_) | E::ModelInvalid { .. } => {
                Self::Counterexample
            }
            _ => Self::Symbolic,
        }
    }
}

/// Compares two forbid-only sets compiled with the same schema under the `suiss-restriction`
/// rules (OP-104, OP-105). Blocks the calling thread; the solver runs on a private runtime.
///
/// # Errors
/// [`AnalysisError`]; no error means a verdict was proved.
pub fn analyze(
    cvc5: &Cvc5,
    schema: &str,
    old: &str,
    new: &str,
    limits: Limits,
) -> Result<Verdict, AnalysisError> {
    let old = Engine::compile(schema, old, limits).map_err(AnalysisError::Old)?;
    let new = Engine::compile(schema, new, limits).map_err(AnalysisError::New)?;
    let (old, new) = (Set::of(&old)?, Set::of(&new)?);
    // OP-104 m.6
    if let Some(w) = require_changed(&old, &new) {
        return Ok(Verdict::Widening(w));
    }
    on_private_runtime(cvc5, async |cvc5| run(cvc5, &old, &new).await)
}

/// Runs `f` on a fresh single-threaded runtime in its own thread, so the caller's runtime (if
/// any) is never entered or blocked from inside.
fn on_private_runtime<F>(cvc5: &Cvc5, f: F) -> Result<Verdict, AnalysisError>
where
    F: AsyncFnOnce(&Cvc5) -> Result<Verdict, AnalysisError> + Send,
{
    let total = cvc5.timeouts().total;
    std::thread::scope(|s| {
        std::thread::Builder::new()
            .name("restriction-smt".into())
            .spawn_scoped(s, move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| AnalysisError::Solver)?;
                rt.block_on(async move {
                    tokio::time::timeout(total, f(cvc5))
                        .await
                        .map_err(|_| AnalysisError::Timeout)?
                })
            })
            .map_err(|_| AnalysisError::Solver)?
            .join()
            .map_err(|_| AnalysisError::Solver)?
    })
}

struct Set<'a> {
    schema: &'a Schema,
    base: &'a Policy,
    policies: Vec<PolicyView<'a>>,
}

impl<'a> Set<'a> {
    fn of(engine: &'a Engine) -> Result<Self, AnalysisError> {
        Ok(Self {
            schema: engine.schema(),
            base: engine.base_permit().ok_or(AnalysisError::Symbolic)?,
            policies: engine.policies().ok_or(AnalysisError::Symbolic)?,
        })
    }

    fn refs(&self) -> BTreeSet<&'a str> {
        self.policies.iter().filter_map(|p| p.require).collect()
    }

    fn with(&self, keep: impl Fn(&PolicyView<'_>) -> bool) -> Result<PolicySet, AnalysisError> {
        let mut set = PolicySet::new();
        set.add(self.base.clone())
            .map_err(|_| AnalysisError::Symbolic)?;
        for p in self.policies.iter().filter(|p| keep(p)) {
            set.add(p.policy.clone())
                .map_err(|_| AnalysisError::Symbolic)?;
        }
        Ok(set)
    }

    fn deny(&self, env: &RequestEnv) -> Result<CompiledPolicySet, AnalysisError> {
        compile(&self.with(|p| p.require.is_none())?, env, self.schema)
    }

    fn require(&self, env: &RequestEnv, r: &str) -> Result<CompiledPolicySet, AnalysisError> {
        compile(&self.with(|p| p.require == Some(r))?, env, self.schema)
    }

    fn deny_or_require(
        &self,
        env: &RequestEnv,
        r: &str,
    ) -> Result<CompiledPolicySet, AnalysisError> {
        compile(
            &self.with(|p| p.require.is_none_or(|x| x == r))?,
            env,
            self.schema,
        )
    }
}

fn compile(
    set: &PolicySet,
    env: &RequestEnv,
    schema: &Schema,
) -> Result<CompiledPolicySet, AnalysisError> {
    Ok(CompiledPolicySet::compile(set, env, schema)?)
}

fn require_changed(old: &Set<'_>, new: &Set<'_>) -> Option<Widening> {
    let before: BTreeMap<&str, &str> = old
        .policies
        .iter()
        .filter_map(|p| p.require.map(|r| (p.id, r)))
        .collect();
    new.policies.iter().find_map(|p| {
        let (now, was) = (p.require?, *before.get(p.id)?);
        (now != was).then(|| Widening {
            env: None,
            reason: WideningReason::RequireChanged {
                id: p.id.to_owned(),
                old: was.to_owned(),
                new: now.to_owned(),
            },
            counterexample: None,
        })
    })
}

fn environment(env: &RequestEnv) -> RequestEnvironment {
    RequestEnvironment {
        principal: env.principal().to_string(),
        action: env.action().to_string(),
        resource: env.resource().to_string(),
    }
}

fn counterexample(env: &Env) -> Result<Counterexample, AnalysisError> {
    let entities = env
        .entities
        .to_json_value()
        .map_err(|_| AnalysisError::Counterexample)?;
    Ok(Counterexample {
        request: env.request.to_string(),
        entities: entities.to_string(),
    })
}

struct Solver<'c> {
    compiler: CedarSymCompiler<LocalSolver>,
    cvc5: &'c Cvc5,
}

impl Solver<'_> {
    async fn query<T>(
        &mut self,
        f: impl AsyncFnOnce(&mut CedarSymCompiler<LocalSolver>) -> cedar_policy_symcc::err::Result<T>,
    ) -> Result<T, AnalysisError> {
        let limit = self.cvc5.timeouts().query;
        Ok(tokio::time::timeout(limit, f(&mut self.compiler))
            .await
            .map_err(|_| AnalysisError::Timeout)??)
    }

    // OP-104 m.5
    async fn may_error(
        &mut self,
        side: Side,
        set: &Set<'_>,
        env: &RequestEnv,
    ) -> Result<Option<MayError>, AnalysisError> {
        for p in &set.policies {
            let compiled = CompiledPolicy::compile(p.policy, env, set.schema)?;
            let cex = self
                .query(async |c| {
                    c.check_never_errors_with_counterexample_opt(&compiled)
                        .await
                })
                .await?;
            if let Some(cex) = cex {
                return Ok(Some(MayError {
                    side,
                    id: p.id.to_owned(),
                    env: environment(env),
                    counterexample: Some(counterexample(&cex)?),
                }));
            }
        }
        Ok(None)
    }

    async fn implies(
        &mut self,
        weaker: &CompiledPolicySet,
        stronger: &CompiledPolicySet,
    ) -> Result<Option<Env>, AnalysisError> {
        self.query(async |c| {
            c.check_implies_with_counterexample_opt(weaker, stronger)
                .await
        })
        .await
    }

    /// `to` restricts every request at least as much as `from` (spike C1 and C2[r]).
    async fn restricts(
        &mut self,
        from: &Set<'_>,
        to: &Set<'_>,
        env: &RequestEnv,
    ) -> Result<Option<Widening>, AnalysisError> {
        let widening = |reason, cex: &Env| -> Result<Widening, AnalysisError> {
            Ok(Widening {
                env: Some(environment(env)),
                reason,
                counterexample: Some(counterexample(cex)?),
            })
        };
        if let Some(cex) = self.implies(&to.deny(env)?, &from.deny(env)?).await? {
            return Ok(Some(widening(WideningReason::Deny, &cex)?));
        }
        for r in from.refs() {
            let cex = self
                .implies(&to.deny_or_require(env, r)?, &from.require(env, r)?)
                .await?;
            if let Some(cex) = cex {
                let reason = WideningReason::Require {
                    reference: r.to_owned(),
                };
                return Ok(Some(widening(reason, &cex)?));
            }
        }
        Ok(None)
    }
}

async fn run(cvc5: &Cvc5, old: &Set<'_>, new: &Set<'_>) -> Result<Verdict, AnalysisError> {
    let compiler = CedarSymCompiler::new(cvc5.spawn()?)?;
    let mut solver = Solver { compiler, cvc5 };
    let envs: Vec<RequestEnv> = new.schema.request_envs().collect();
    for env in &envs {
        for (side, set) in [(Side::New, new), (Side::Old, old)] {
            if let Some(e) = solver.may_error(side, set, env).await? {
                return Ok(Verdict::MayError(e));
            }
        }
        if let Some(w) = solver.restricts(old, new, env).await? {
            return Ok(Verdict::Widening(w));
        }
    }
    for env in &envs {
        if solver.restricts(new, old, env).await?.is_some() {
            return Ok(Verdict::Narrowing);
        }
    }
    Ok(Verdict::Equivalent)
}

#[cfg(test)]
mod tests;
