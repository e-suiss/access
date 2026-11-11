//! Load harness (OP-32, OP-61, OP-72, OP-158 m.3 (z)).
//!
//! The binary drives commit (CT1/CT2), check, search, login, refresh, introspection and revocation
//! fan-out against a running `access-server` and prints JSON with the environment (CPU, cores,
//! PostgreSQL version, sync standby count) and the git version. An unmeasured figure is never
//! published.
//!
//! The load is open: request `i` is due at `start + i / rate` whether or not earlier ones have
//! answered, and its latency is counted from when it was due, so a slow server cannot hide its
//! queue (no coordinated omission). The bodies come from a requests file, one JSON object per
//! line (`{"method", "path", "headers", "body"}`), used in turn; signed bodies (AIS, assertions)
//! are made by the caller. The transport is HTTP/1.1 on TCP; a TLS cell is measured behind its
//! terminator.
//!
//! ```text
//! access-load run <scenario> <target> --requests <file> [--rate <per s>] [--seconds <n>]
//!     [--connections <n>] [--out <file>]
//! access-load list
//! ```

use std::io::Write as _;
use std::process::ExitCode;

mod environment;
mod http;
mod run;
mod scenario;
mod stats;

/// The usage text.
const USAGE: &str = "usage:\naccess-load run <scenario> <target> --requests <file> [--rate <per s>] [--seconds <n>] [--connections <n>] [--out <file>]\naccess-load list\n";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--help" | "-h") => {
            let _ = std::io::stdout().write_all(USAGE.as_bytes());
            ExitCode::SUCCESS
        }
        Some("list") => {
            let mut out = String::new();
            for s in scenario::ALL {
                out.push_str(s.name);
                out.push('\t');
                out.push_str(s.summary);
                out.push('\n');
            }
            let _ = std::io::stdout().write_all(out.as_bytes());
            ExitCode::SUCCESS
        }
        Some("run") => match run::Options::parse(args.get(1..).unwrap_or_default()) {
            Ok(options) => match run::main(&options) {
                Ok(report) => {
                    let text = report.to_string();
                    let _ = std::io::stdout().write_all(text.as_bytes());
                    let _ = std::io::stdout().write_all(b"\n");
                    if let Some(path) = &options.out
                        && std::fs::write(path, text.as_bytes()).is_err()
                    {
                        let _ = std::io::stderr().write_all(b"access-load: cannot write --out\n");
                        return ExitCode::FAILURE;
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    let _ = std::io::stderr().write_all(format!("access-load: {e}\n").as_bytes());
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                let _ = std::io::stderr().write_all(format!("access-load: {e}\n").as_bytes());
                let _ = std::io::stderr().write_all(USAGE.as_bytes());
                ExitCode::from(2)
            }
        },
        _ => {
            let _ = std::io::stderr().write_all(USAGE.as_bytes());
            ExitCode::from(2)
        }
    }
}
