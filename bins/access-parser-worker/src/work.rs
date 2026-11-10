//! One disposable worker (U43, OP-155 m.3 (c)): `RLIMIT_AS` 256 MiB, at most 2 s of CPU per
//! request, `Profile::ParserWorker` (no socket call, no file, no key), and a panic is an abort of
//! this process only. It reads request frames from its standard input and writes replies to its
//! standard output, both ends of the supervisor's socket pair.

use std::io::Write as _;
use std::process::ExitCode;

use access_edge_core::ipc::{Op, Reply, Request};
use access_edge_core::pool::{MAX_REQUESTS, read_frame};
use suiss_sandbox::{LandlockAbi, Lockdown, Profile};

use crate::{parse, saml, supervisor, trusted_list};

/// Address space of one worker.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "Linux limits only")
)]
pub(crate) const MEMORY: u64 = 256 * 1024 * 1024;

/// CPU seconds one request may use.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "Linux limits only")
)]
pub(crate) const CPU_SECONDS: u64 = 2;

/// The hard CPU limit: every request's budget, never raised.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "Linux limits only")
)]
const CPU_HARD: u64 = CPU_SECONDS * (MAX_REQUESTS as u64 + 1) + 1;

#[cfg(target_os = "linux")]
fn limits() -> Result<(), String> {
    use rustix::process::{Resource, Rlimit, setrlimit};
    setrlimit(
        Resource::As,
        Rlimit {
            current: Some(MEMORY),
            maximum: Some(MEMORY),
        },
    )
    .map_err(|e| e.to_string())?;
    setrlimit(
        Resource::Cpu,
        Rlimit {
            current: Some(CPU_SECONDS),
            maximum: Some(CPU_HARD),
        },
    )
    .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
fn limits() -> Result<(), String> {
    Err(String::from(
        "resource limits are not supported on this operating system",
    ))
}

/// Gives the next request [`CPU_SECONDS`] from now; past it the kernel stops the worker.
#[cfg(target_os = "linux")]
fn cpu_budget() -> Result<(), String> {
    use rustix::process::{Resource, Rlimit, setrlimit};
    use rustix::time::{ClockId, clock_gettime};
    let used = u64::try_from(clock_gettime(ClockId::ProcessCPUTime).tv_sec).unwrap_or(CPU_HARD);
    let current = used.saturating_add(CPU_SECONDS).min(CPU_HARD);
    setrlimit(
        Resource::Cpu,
        Rlimit {
            current: Some(current),
            maximum: Some(CPU_HARD),
        },
    )
    .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
fn cpu_budget() -> Result<(), String> {
    limits()
}

/// The answer to one request.
pub(crate) fn handle(r: Request) -> Reply {
    let checked = match r.op {
        Op::XmlCheck => parse::xml(&r.input).map(|s| (s, r.input)),
        Op::XmlInflate => parse::inflate(&r.input),
        Op::DerCheck => parse::der(&r.input).map(|s| (s, r.input)),
        Op::Abort => abort(),
        Op::TlRead => trusted_list::read(&r.input),
        Op::SamlRequest => saml::request(&r.input),
        Op::SamlRedirect => saml::redirect(&r.input),
    };
    match checked {
        Ok((summary, output)) => Reply::Ok { summary, output },
        Err(code) => Reply::Refused(String::from(code)),
    }
}

/// U43 test hook: a worker built with debug assertions aborts as a memory corruption would;
/// a release worker refuses the operation.
#[cfg(debug_assertions)]
fn abort() -> Result<(access_edge_core::ipc::Summary, Vec<u8>), &'static str> {
    std::process::abort()
}

#[cfg(not(debug_assertions))]
fn abort() -> Result<(access_edge_core::ipc::Summary, Vec<u8>), &'static str> {
    Err("op-refused")
}

/// The worker's main loop; ends at the end of its input.
pub(crate) fn run() -> ExitCode {
    // U43
    std::panic::set_hook(Box::new(|_| std::process::abort()));
    if let Err(error) = limits() {
        supervisor::log(&format!("worker limits refused: {error}"));
        return ExitCode::FAILURE;
    }
    // SA-22, OP-90
    let locked = match Lockdown::new(Profile::ParserWorker, LandlockAbi::REQUIRED).apply() {
        Ok(locked) => locked,
        Err(error) => {
            supervisor::log(&format!("worker lockdown failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    if locked.narrow().is_err() {
        return ExitCode::FAILURE;
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        let frame = match read_frame(&mut input) {
            Ok(Some(frame)) => frame,
            Ok(None) => return ExitCode::SUCCESS,
            Err(_) => return ExitCode::FAILURE,
        };
        if cpu_budget().is_err() {
            return ExitCode::FAILURE;
        }
        let reply = Request::decode(&frame)
            .map_or_else(|_| Reply::Refused(String::from("frame-malformed")), handle);
        let Ok(out) = reply.encode() else {
            return ExitCode::FAILURE;
        };
        if output
            .write_all(&out)
            .and_then(|()| output.flush())
            .is_err()
        {
            return ExitCode::FAILURE;
        }
    }
}
