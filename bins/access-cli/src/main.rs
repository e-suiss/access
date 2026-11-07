//! `access-cli`: the Access command line (OP-151 m.3 (h)). Each subcommand lives in its own
//! module under `commands/`; this file only parses the command line and maps the outcome to an
//! exit code ([`exit`]). Secrets never come from arguments or the environment: arguments name
//! files, and the configuration names credential files (OP-129 m.3). There is no bearer token
//! option: the management commands act with an Instance key (TN-130).

mod api;
mod client;
mod commands;
mod config;
mod exit;
mod gitops;
mod http;
mod keys;
mod yaml;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// The Access command line.
#[derive(Debug, Parser)]
#[command(name = "access-cli", version, about, disable_help_subcommand = true)]
struct Cli {
    /// The configuration file: the server's `access.toml` or one with its `[database]` section.
    #[arg(
        long,
        value_name = "PATH",
        default_value = "access.toml",
        global = true
    )]
    config: PathBuf,
    /// `tracing` filter directives for the log on standard error.
    #[arg(long, value_name = "FILTER", default_value = "info", global = true)]
    log: String,
    #[command(subcommand)]
    command: Command,
}

/// What to do.
#[derive(Debug, Subcommand)]
enum Command {
    /// Applies the schema migrations as the migration role and prints what it applied
    /// (OP-55, OP-138).
    Migrate(commands::migrate::Args),
    /// Reads and writes realm-admin resources; every write is one Exercise signed with the
    /// Instance key (TN-110).
    Admin(commands::admin::AdminArgs),
    /// Writes the realm's configuration as deterministic YAML (TN-123).
    Export(commands::export::ExportArgs),
    /// Shows the plan from the runtime state to a desired document (TN-123).
    Diff(commands::diff::DiffArgs),
    /// Reconciles the realm to a desired document, one Exercise per change; reserved changes
    /// and emergency releases are only proposed (TN-122, TN-124).
    Apply(commands::apply::ApplyArgs),
    /// Re-evaluates a recorded decision with the Kernel (INV-21).
    Replay(commands::replay::ReplayArgs),
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let usage = e.use_stderr();
            let _ = e.print();
            return if usage {
                exit::USAGE.into()
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    if access_telemetry::init_with_writer(&cli.log, std::io::stderr).is_err() {
        return exit::CONFIG.into();
    }
    let code = match cli.command {
        Command::Migrate(args) => commands::migrate::run(&cli.config, &args),
        Command::Replay(args) => commands::replay::run(&args),
        command => {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return exit::FAILED.into();
            };
            rt.block_on(async move {
                match command {
                    Command::Admin(a) => Box::pin(commands::admin::run(a)).await,
                    Command::Export(a) => Box::pin(commands::export::run(a)).await,
                    Command::Diff(a) => Box::pin(commands::diff::run(a)).await,
                    Command::Apply(a) => Box::pin(commands::apply::run(a)).await,
                    Command::Migrate(a) => commands::migrate::run(&cli.config, &a),
                    Command::Replay(a) => commands::replay::run(&a),
                }
            })
        }
    };
    code.into()
}

#[cfg(test)]
mod tests;
