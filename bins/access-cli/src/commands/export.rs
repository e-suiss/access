//! `access-cli export`: the realm's configuration as deterministic YAML (TN-123 item 1):
//! resources sorted by natural key, keys sorted, server-generated members and retired
//! resources left out unless `--with-generated`, secrets only as `secret://` references.

use std::path::PathBuf;

use clap::Args;

use super::{Connect, failed, load_key, note, out, runtime};
use crate::api;
use crate::client::{Client, System};
use crate::exit::{self, Code};
use crate::gitops::{self, ExportOptions};
use crate::http::Https;
use crate::yaml;

/// `export` arguments.
#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    #[command(flatten)]
    pub(crate) connect: Connect,
    /// Keep server-generated members (`readOnly` in the contract) and retired resources.
    #[arg(long)]
    pub(crate) with_generated: bool,
    /// Write to this file instead of standard output.
    #[arg(long, value_name = "PATH")]
    pub(crate) output: Option<PathBuf>,
}

/// The header comment of an exported document.
pub(crate) const HEADER: &str = "Access realm configuration (access-cli export).\n\
Only the members you keep are managed; removing a member leaves it as it is (TN-123).\n\
Secrets appear only as secret:// references.";

/// Runs `export`.
pub(crate) async fn run(args: ExportArgs) -> Code {
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
    let doc = match gitops::export(
        api::contract(),
        &target.realm,
        &live,
        ExportOptions {
            generated: args.with_generated,
        },
    ) {
        Ok(d) => d,
        Err(e) => {
            note(&format!("access-cli: {e}"));
            return exit::FAILED;
        }
    };
    let text = yaml::to_string(&doc, Some(HEADER));
    match args.output {
        Some(path) => match std::fs::write(&path, text) {
            Ok(()) => exit::OK,
            Err(e) => {
                note(&format!("access-cli: {}: {e}", path.display()));
                exit::FAILED
            }
        },
        None => out(&text),
    }
}
