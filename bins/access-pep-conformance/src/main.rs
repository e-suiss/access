//! `access-pep-conformance --sut <command>`: runs the PEP fault cases against an adapter
//! (OP-150 m.1 (a), CMP-17, X21). Exit status 0 when every case passes, 1 otherwise, 2 when
//! the run itself fails.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a developer CLI; it reports to the terminal"
)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use access_pep_conformance::case::load;
use access_pep_conformance::fixture::Fixture;
use access_pep_conformance::run::{render, run};
use access_pep_conformance::sut::Subprocess;
use access_pep_conformance::upstream::Upstream;

struct Args {
    sut: String,
    cases: PathBuf,
    deadline_ms: u64,
    grace_ms: u64,
    json: Option<PathBuf>,
}

const USAGE: &str = "usage: access-pep-conformance --sut <command> [--cases <dir>] [--deadline-ms <n>] [--grace-ms <n>] [--json <file>]";

fn args() -> Result<Args, String> {
    let mut out = Args {
        sut: String::new(),
        cases: PathBuf::from("conformance/pep/cases"),
        deadline_ms: 500,
        grace_ms: 2_000,
        json: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--sut" => out.sut = value()?,
            "--cases" => out.cases = PathBuf::from(value()?),
            "--deadline-ms" => out.deadline_ms = value()?.parse().map_err(|e| format!("{e}"))?,
            "--grace-ms" => out.grace_ms = value()?.parse().map_err(|e| format!("{e}"))?,
            "--json" => out.json = Some(PathBuf::from(value()?)),
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    if out.sut.is_empty() {
        return Err(String::from("--sut is required"));
    }
    Ok(out)
}

async fn conformance(args: Args) -> Result<bool, String> {
    let cases = load(&args.cases).map_err(|e| e.to_string())?;
    let fixture = Fixture::load().map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let upstream = Arc::new(
        Upstream::new(&format!("http://{addr}"), &cases, fixture).map_err(|e| e.to_string())?,
    );
    let app = Arc::clone(&upstream).router();
    tokio::spawn(async move { axum::serve(listener, app).await });
    let mut sut = Subprocess::start(&args.sut, Duration::from_secs(10))
        .await
        .map_err(|e| e.to_string())?;
    let reports = run(
        &upstream,
        &cases,
        &mut sut,
        args.deadline_ms,
        Duration::from_millis(args.grace_ms),
    )
    .await;
    let name = sut.name().to_owned();
    sut.stop();
    let reports = reports.map_err(|e| e.to_string())?;
    print!("{}", render(&name, &reports));
    if let Some(path) = args.json {
        let text = serde_json::to_string_pretty(&reports).map_err(|e| e.to_string())?;
        std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(reports.iter().all(|r| r.verdict.passed()))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = match args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match conformance(args).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("pep-conformance: {e}");
            ExitCode::from(2)
        }
    }
}
