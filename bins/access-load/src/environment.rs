//! The environment a measurement ran in (OP-61): no figure is published without it.

use std::process::Command;

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// The CPU model, from `/proc/cpuinfo` or `sysctl`.
fn cpu() -> Option<String> {
    if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
        return info
            .lines()
            .find_map(|l| l.strip_prefix("model name"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_owned());
    }
    run("sysctl", &["-n", "machdep.cpu.brand_string"])
}

/// What is known of the machine and the deployment measured. The PostgreSQL version and the
/// synchronous standby count are the deployment's and come from `ACCESS_LOAD_PG_VERSION` and
/// `ACCESS_LOAD_SYNC_STANDBYS`; the git version from `GITHUB_SHA` or `git`.
#[must_use]
pub(crate) fn capture() -> serde_json::Value {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    serde_json::json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "cpu": cpu(),
        "cores": std::thread::available_parallelism().ok().map(std::num::NonZero::get),
        "pg_version": var("ACCESS_LOAD_PG_VERSION"),
        "sync_standbys": var("ACCESS_LOAD_SYNC_STANDBYS").and_then(|v| v.parse::<u32>().ok()),
        "host": var("ACCESS_LOAD_HOST"),
        "git": var("GITHUB_SHA").or_else(|| run("git", &["rev-parse", "HEAD"])),
        "harness": env!("CARGO_PKG_VERSION"),
    })
}
