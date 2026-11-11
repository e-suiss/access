//! Witness conformance profile (§16.6, U9, U11, HL-7, OP-158 m.3 (d)).
//!
//! The binary keeps, per domain, the last cosigned (size, root) in an append-only, hash-chained local file;
//! cosigns a checkpoint only when its consistency proof from that base verifies and the signing key
//! is the current binding's operational key; learns a new binding from the inclusion proof of a
//! `domain_handover` or `domain_recover` record and fences the old one. `monitor` pulls every
//! declared witness's latest cosigns and keeps two roots for one size as signed equivocation
//! evidence. It never connects to an Access store.
//!
//! ```text
//! access-witness serve <config>
//! access-witness monitor <config>
//! ```

use std::io::Write as _;
use std::process::ExitCode;

/// The usage text.
const USAGE: &str = "usage:\naccess-witness serve <config>\naccess-witness monitor <config>\n";

fn main() -> ExitCode {
    let help = std::env::args_os()
        .nth(1)
        .is_some_and(|a| a == "--help" || a == "-h");
    if help {
        let _ = std::io::stdout().write_all(USAGE.as_bytes());
        return ExitCode::SUCCESS;
    }
    let _ =
        std::io::stderr().write_all(b"access-witness: not built yet (OP-158 m.4 (a), lane W2)\n");
    let _ = std::io::stderr().write_all(USAGE.as_bytes());
    ExitCode::from(2)
}
