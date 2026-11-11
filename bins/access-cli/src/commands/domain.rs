//! `access-cli domain`: the domain-scope steps a root takes when its domain leaves its provider
//! (§9.15, §16.6).

pub(crate) mod recover;

use clap::{Args, Subcommand};

use crate::exit::Code;

/// `domain` arguments.
#[derive(Debug, Args)]
pub(crate) struct DomainArgs {
    #[command(subcommand)]
    pub(crate) command: DomainCommand,
}

/// The `domain` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum DomainCommand {
    /// Plans a forced recovery from the witnesses and the recovery-side records, and with
    /// `--discover` lists the revocations the lost suffix may hold (§13.6, §16.6 FR-0…FR-6).
    Recover(recover::RecoverArgs),
}

/// Runs `domain`.
pub(crate) async fn run(args: DomainArgs) -> Code {
    match args.command {
        DomainCommand::Recover(a) => recover::run(&a).await,
    }
}
