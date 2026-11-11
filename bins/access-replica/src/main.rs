//! Replica agent (§16.6.1, T21, CMP-21, TI-13, OP-158 m.3 (f), (h)).
//!
//! The binary follows `GET /v1/domains/{domain}/mirror`, checks size, root and consistency with
//! `suiss_ledger::replica::Follower`, appends records to local files and answers a signed
//! `replica_ack {size, root}`. Its reads are advisory only and never a source of ALLOW (P43).
//! `apply-redactions` applies DEK destruction to the local copy (U22); `--replay` is the sampling
//! replay agent (G32).
//!
//! ```text
//! access-replica follow <config>
//! access-replica apply-redactions <config>
//! access-replica --replay <config>
//! ```

use std::io::Write as _;
use std::process::ExitCode;

/// The usage text.
const USAGE: &str = "usage:\naccess-replica follow <config>\naccess-replica apply-redactions <config>\naccess-replica --replay <config>\n";

fn main() -> ExitCode {
    let help = std::env::args_os()
        .nth(1)
        .is_some_and(|a| a == "--help" || a == "-h");
    if help {
        let _ = std::io::stdout().write_all(USAGE.as_bytes());
        return ExitCode::SUCCESS;
    }
    let _ =
        std::io::stderr().write_all(b"access-replica: not built yet (OP-158 m.4 (a), lane W3)\n");
    let _ = std::io::stderr().write_all(USAGE.as_bytes());
    ExitCode::from(2)
}
