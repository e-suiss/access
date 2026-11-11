//! Load harness (OP-32, OP-61, OP-72, OP-158 m.3 (z)).
//!
//! The binary drives commit (CT1/CT2), check, search, login, refresh, introspection and revocation
//! fan-out against a running `access-server` and prints JSON with the environment (CPU, cores,
//! PostgreSQL version, sync standby count) and the git version. An unmeasured figure is never
//! published.
//!
//! ```text
//! access-load run <scenario> <target>
//! access-load list
//! ```

use std::io::Write as _;
use std::process::ExitCode;

/// The usage text.
const USAGE: &str = "usage:\naccess-load run <scenario> <target>\naccess-load list\n";

fn main() -> ExitCode {
    let help = std::env::args_os()
        .nth(1)
        .is_some_and(|a| a == "--help" || a == "-h");
    if help {
        let _ = std::io::stdout().write_all(USAGE.as_bytes());
        return ExitCode::SUCCESS;
    }
    let _ = std::io::stderr().write_all(b"access-load: not built yet (OP-158 m.4 (a), lane W10)\n");
    let _ = std::io::stderr().write_all(USAGE.as_bytes());
    ExitCode::from(2)
}
