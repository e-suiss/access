//! Restriction analysis solver (OP-157 m.8 (a), OP-159 m.3 (aa)).
//!
//! The binary runs the pinned cvc5 under its own sandbox and answers `restriction-analysis`
//! requests from the server over a Unix socket whose owner and mode it checks at start. The
//! server keeps its seccomp profile; an unreachable or slow solver raises the classification.
//!
//! ```text
//! access-policy-solver serve <config>
//! ```

use std::io::Write as _;
use std::process::ExitCode;

/// The usage text.
const USAGE: &str = "usage:\naccess-policy-solver serve <config>\n";

fn main() -> ExitCode {
    let help = std::env::args_os()
        .nth(1)
        .is_some_and(|a| a == "--help" || a == "-h");
    if help {
        let _ = std::io::stdout().write_all(USAGE.as_bytes());
        return ExitCode::SUCCESS;
    }
    let _ = std::io::stderr()
        .write_all(b"access-policy-solver: not built yet (OP-159 m.4 (a), lane J6)\n");
    let _ = std::io::stderr().write_all(USAGE.as_bytes());
    ExitCode::from(2)
}
