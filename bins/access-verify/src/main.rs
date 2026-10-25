//! Reference Verifier (CMP-17, TI-17): verifies Access artefacts offline with the open Kernel.
//! It reads files, never the network or the system clock; time comes from `--now` and `--iat`.

mod args;
mod commands;

use std::fmt::Write as _;
use std::io::Write as _;
use std::process::ExitCode;

use args::{Options, Usage};
use commands::{COMMANDS, Outcome};

const NAME: &str = "access-verify";

fn usage() -> String {
    let mut out = format!(
        "usage: {NAME} <command> [--option value]...\n\nPrints `accept` and its outputs, or `reject: <reason>`. Exit status: 0 accept, 1 reject, 2 usage or I/O error.\n\ncommands:\n"
    );
    for c in COMMANDS {
        let _ = writeln!(out, "  {:<12} {}", c.name, c.summary);
        let options: Vec<String> = c.options.iter().map(|o| format!("--{o}")).collect();
        let _ = writeln!(out, "  {:<12} {}", "", options.join(" "));
    }
    out
}

fn render(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Accept(outputs) => {
            let mut out = String::from("accept\n");
            for (name, value) in outputs {
                let _ = writeln!(out, "{name}: {value}");
            }
            out
        }
        Outcome::Reject(reason) => format!("reject: {reason}\n"),
    }
}

fn run(args: &[String]) -> Result<Outcome, Usage> {
    let Some((name, rest)) = args.split_first() else {
        return Err(Usage(usage()));
    };
    let command = COMMANDS
        .iter()
        .find(|c| c.name == name)
        .ok_or_else(|| Usage(format!("unknown command {name}\n\n{}", usage())))?;
    (command.run)(&Options::parse(rest, command.options)?)
}

fn emit(mut sink: impl std::io::Write, text: &str) -> bool {
    sink.write_all(text.as_bytes())
        .and_then(|()| sink.flush())
        .is_ok()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(
        args.first().map(String::as_str),
        Some("help" | "--help" | "-h")
    ) {
        return if emit(std::io::stdout().lock(), &usage()) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    match run(&args) {
        Ok(outcome) => {
            let code = match outcome {
                Outcome::Accept(_) => ExitCode::SUCCESS,
                Outcome::Reject(_) => ExitCode::FAILURE,
            };
            if emit(std::io::stdout().lock(), &render(&outcome)) {
                code
            } else {
                ExitCode::from(2)
            }
        }
        Err(Usage(message)) => {
            let _ = std::io::stderr()
                .lock()
                .write_all(format!("{NAME}: {}\n", message.trim_end()).as_bytes());
            ExitCode::from(2)
        }
    }
}
