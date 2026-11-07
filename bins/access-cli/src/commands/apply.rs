//! `access-cli apply`: the `GitOps` reconciler (§12.5.3, TN-122…TN-124). It acts as its own agent
//! Instance (the key it is given) under its own Grant (the `--basis`); every change is one
//! Exercise through the management API, in plan order, stopping at the first failure. Reserved
//! changes (CT3) are never applied: they are written as proposals for a quorum (TN-122, E11). A
//! plan with a conflict applies nothing (fail closed).
//!
//! `--release <kind>/<key>` is the emergency escape (TN-124): it is not an "unmanage" switch.
//! It writes the resource's retire, a CT1 restriction Exercise, as a proposal and says so; once
//! retired, the reconciler reports the resource as retired and never brings it back.

use std::path::PathBuf;

use access_kernel::json::b64url_encode;
use clap::Args;
use serde_json::Value;

use super::diff::{desired, render};
use super::{Connect, failed, load_key, note, out, runtime};
use crate::api::{self, Method};
use crate::client::{Client, ClientError, Env, System};
use crate::exit::{self, Code};
use crate::gitops::{self, PlanOptions, Step};
use crate::http::{Https, Transport};
use crate::yaml;

/// `apply` arguments.
#[derive(Debug, Args)]
pub(crate) struct ApplyArgs {
    #[command(flatten)]
    pub(crate) connect: Connect,
    /// The desired configuration (YAML).
    #[arg(long, value_name = "PATH", required_unless_present = "release")]
    pub(crate) file: Option<PathBuf>,
    /// Retire runtime resources the document does not name (CT1).
    #[arg(long)]
    pub(crate) prune: bool,
    /// Where to write proposals (reserved changes, releases); standard output when absent.
    #[arg(long, value_name = "PATH")]
    pub(crate) proposals: Option<PathBuf>,
    /// Emergency escape for `<kind>/<key>`: propose its retire as a CT1 restriction Exercise.
    #[arg(long, value_name = "KIND/KEY", conflicts_with_all = ["file", "prune"])]
    pub(crate) release: Option<String>,
}

/// What a reconciliation did.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    /// Applied changes: what, Exercise id, position.
    pub(crate) applied: Vec<(String, String, String)>,
    /// Proposals, not applied.
    pub(crate) proposals: Vec<Value>,
    /// The plan, rendered.
    pub(crate) plan: String,
    /// Conflicts; when present nothing was applied.
    pub(crate) conflicts: usize,
}

/// Why a reconciliation stopped.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ApplyError {
    /// The document cannot be planned.
    #[error(transparent)]
    Doc(#[from] gitops::DocError),
    /// A read or a write failed; the outcome holds what was applied before it.
    #[error("{source} (after {applied} applied change(s))")]
    Client {
        /// The failure.
        source: ClientError,
        /// Changes applied before it.
        applied: usize,
        /// The outcome so far.
        outcome: Box<Outcome>,
    },
}

const RESERVED: &str = "reserved change (CT3): the reconciler's Grant holds no reserved action; a quorum signs it (TN-122, E11)";
const RELEASE: &str =
    "emergency escape (TN-124): a restriction Exercise; the reconciler never undoes it";

/// Plans and applies `doc` for `realm`.
pub(crate) async fn reconcile<T: Transport, E: Env>(
    client: &Client<'_, T, E>,
    realm: &str,
    doc: &Value,
    prune: bool,
    managed_by: Option<String>,
) -> Result<Outcome, ApplyError> {
    let live = runtime(client, realm)
        .await
        .map_err(|source| ApplyError::Client {
            source,
            applied: 0,
            outcome: Box::default(),
        })?;
    let steps = gitops::plan(
        api::contract(),
        realm,
        doc,
        &live,
        &PlanOptions { prune, managed_by },
    )?;
    let mut outcome = Outcome {
        plan: render(&steps),
        conflicts: steps
            .iter()
            .filter(|s| matches!(s, Step::Conflict { .. }))
            .count(),
        ..Outcome::default()
    };
    for step in &steps {
        if step.reserved() {
            outcome
                .proposals
                .push(gitops::proposal(step, "CT3", RESERVED));
        }
    }
    if outcome.conflicts > 0 {
        return Ok(outcome);
    }
    for step in steps.iter().filter(|s| !s.reserved()) {
        let Step::Write {
            operation,
            key,
            body,
            if_match,
            exists,
            what,
        } = step
        else {
            continue;
        };
        let fail = |source, outcome: Outcome| ApplyError::Client {
            source,
            applied: outcome.applied.len(),
            outcome: Box::new(outcome),
        };
        let Some(op) = api::contract().operation(operation) else {
            return Err(fail(ClientError::Unexpected("operation"), outcome));
        };
        // OP-65: an update names the version it replaces; read it just before writing
        let tag = if *exists && matches!(op.method, Method::Put) && op.keyed() && if_match.is_none()
        {
            match client
                .read(Method::Get, &op.url_path(realm, key.as_deref()), None)
                .await
            {
                Ok(r) if r.status == 200 => r.header("etag").map(String::from),
                Ok(_) => None,
                Err(e) => return Err(fail(e, outcome)),
            }
        } else {
            if_match.clone()
        };
        match client.write(op, key.as_deref(), body, tag.as_deref()).await {
            Ok(w) => outcome
                .applied
                .push((what.clone(), w.exercise_id, w.position)),
            Err(e) => return Err(fail(e, outcome)),
        }
    }
    Ok(outcome)
}

fn emit_proposals(proposals: &[Value], path: Option<&PathBuf>) -> Code {
    if proposals.is_empty() {
        return exit::OK;
    }
    let text = yaml::to_string(
        &Value::Array(proposals.to_vec()),
        Some("Proposals from access-cli apply: not applied; each needs its own Exercise."),
    );
    match path {
        Some(p) => match std::fs::write(p, text) {
            Ok(()) => {
                note(&format!(
                    "access-cli: {} proposal(s) written to {}",
                    proposals.len(),
                    p.display()
                ));
                exit::OK
            }
            Err(e) => {
                note(&format!("access-cli: {}: {e}", p.display()));
                exit::FAILED
            }
        },
        None => out(&text),
    }
}

/// Runs `apply`.
pub(crate) async fn run(args: ApplyArgs) -> Code {
    if let Some(target) = &args.release {
        let step = match gitops::release(target) {
            Ok(s) => s,
            Err(e) => {
                note(&format!("access-cli: {e}"));
                return exit::USAGE;
            }
        };
        note(&format!(
            "access-cli: proposed the restriction Exercise (CT1) retiring {target}; nothing was applied. Once it commits, apply reports {target} as retired and does not undo it."
        ));
        return emit_proposals(
            &[gitops::proposal(&step, "CT1", RELEASE)],
            args.proposals.as_ref(),
        );
    }
    let Some(file) = &args.file else {
        return exit::USAGE;
    };
    let doc = match desired(file) {
        Ok(d) => d,
        Err(c) => return c,
    };
    let target = match args.connect.target() {
        Ok(t) => t,
        Err(e) => {
            note(&format!("access-cli: {e}"));
            return exit::USAGE;
        }
    };
    let instance = match load_key(&args.connect) {
        Ok(k) => k,
        Err(c) => return c,
    };
    let https = match Https::new(&args.connect.ca) {
        Ok(h) => h,
        Err(e) => {
            note(&format!("access-cli: {e}"));
            return exit::CONFIG;
        }
    };
    let client = Client::new(&https, &instance, &target, &System);
    let managed_by = Some(b64url_encode(instance.kid()));
    match reconcile(&client, &target.realm, &doc, args.prune, managed_by).await {
        Ok(o) => report(&o, args.proposals.as_ref()),
        Err(ApplyError::Client {
            source, outcome, ..
        }) => {
            let _ = report(&outcome, args.proposals.as_ref());
            failed(&source)
        }
        Err(e) => {
            note(&format!("access-cli: {e}"));
            exit::CONFIG
        }
    }
}

fn report(o: &Outcome, proposals: Option<&PathBuf>) -> Code {
    note(o.plan.trim_end());
    for (what, exercise, position) in &o.applied {
        note(&format!(
            "access-cli: applied {what}: Exercise {exercise} at position {position}"
        ));
    }
    let code = emit_proposals(&o.proposals, proposals);
    if o.conflicts > 0 {
        note("access-cli: the plan has conflicts; nothing was applied");
        return exit::FAILED;
    }
    code
}
