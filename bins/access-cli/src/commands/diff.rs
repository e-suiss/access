//! `access-cli diff`: the plan from the runtime state to a desired document, without writing
//! (drift is a read, §12.5.3). Only the members the document sets are compared, so an unset
//! member is never drift (TN-123 item 4). Exit 0: in sync; 7: changes; 5: conflicts.

use std::path::{Path, PathBuf};

use clap::Args;
use serde_json::Value;

use super::{Connect, failed, load_key, note, out, runtime};
use crate::api;
use crate::client::{Client, System};
use crate::exit::{self, Code};
use crate::gitops::{self, PlanOptions, Step};
use crate::http::Https;
use crate::yaml;

/// `diff` arguments.
#[derive(Debug, Args)]
pub(crate) struct DiffArgs {
    #[command(flatten)]
    pub(crate) connect: Connect,
    /// The desired configuration (YAML, as `export` writes it).
    #[arg(long, value_name = "PATH")]
    pub(crate) file: PathBuf,
    /// Also plan to retire runtime resources the document does not name.
    #[arg(long)]
    pub(crate) prune: bool,
}

/// Reads the desired document.
pub(crate) fn desired(path: &Path) -> Result<Value, Code> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        note(&format!("access-cli: {}: {e}", path.display()));
        exit::CONFIG
    })?;
    yaml::from_str(&text).map_err(|e| {
        note(&format!("access-cli: {}: {e}", path.display()));
        exit::CONFIG
    })
}

/// One line per step: `+`/`~`/`-` writes, `!` reserved (proposal only), `x` conflicts, `?`
/// resources the document does not name.
pub(crate) fn render(steps: &[Step]) -> String {
    let mut text = String::new();
    for s in steps {
        let line = match s {
            Step::Write {
                what, operation, ..
            } if s.reserved() => {
                format!("! {what} [{operation}: reserved, proposal only]")
            }
            Step::Write {
                what, operation, ..
            } => {
                let sign = if operation.starts_with("retire") {
                    '-'
                } else if what.starts_with("create") {
                    '+'
                } else {
                    '~'
                };
                format!("{sign} {what} [{operation}]")
            }
            Step::Conflict { at, reason } => format!("x {at}: {reason}"),
            Step::Unmanaged { at } => format!("? {at}: not in the document; left as it is"),
        };
        text.push_str(&line);
        text.push('\n');
    }
    text
}

/// The exit code of a plan: conflicts first, then changes.
pub(crate) fn verdict(steps: &[Step]) -> Code {
    if steps.iter().any(|s| matches!(s, Step::Conflict { .. })) {
        exit::FAILED
    } else if steps.iter().any(|s| matches!(s, Step::Write { .. })) {
        exit::DIFFERS
    } else {
        exit::OK
    }
}

/// Runs `diff`.
pub(crate) async fn run(args: DiffArgs) -> Code {
    let doc = match desired(&args.file) {
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
    let live = match runtime(&client, &target.realm).await {
        Ok(r) => r,
        Err(e) => return failed(&e),
    };
    let steps = match gitops::plan(
        api::contract(),
        &target.realm,
        &doc,
        &live,
        &PlanOptions {
            prune: args.prune,
            managed_by: None,
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            note(&format!("access-cli: {e}"));
            return exit::CONFIG;
        }
    };
    let code = out(&render(&steps));
    if code == exit::OK {
        verdict(&steps)
    } else {
        code
    }
}
