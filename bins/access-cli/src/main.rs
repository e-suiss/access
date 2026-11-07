//! `access-cli`: the Access command line (OP-151 m.3 (h)). Each subcommand lives in its own
//! module under `commands/`; this file only parses the command line and maps the outcome to an
//! exit code ([`exit`]). Secrets never come from arguments or the environment: arguments name
//! files, and the configuration names credential files (OP-129 m.3).

mod commands;
mod config;
mod exit;

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
    };
    code.into()
}

#[cfg(test)]
mod tests;
