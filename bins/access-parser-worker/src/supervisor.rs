//! The supervisor (OP-155 m.3 (c)): it binds its Unix socket, locks itself down with
//! `Profile::ParserSupervisor`, starts the worker pool and answers gateways on the socket. Only callers whose user id
//! is configured are answered (UDS peer credentials, as for the signers).
//!
//! Configuration, from the environment:
//! - `ACCESS_PARSER_SOCKET`: the socket path (required);
//! - `ACCESS_PARSER_CALLERS`: comma-separated user ids of the gateways (required);
//! - `ACCESS_PARSER_WORKERS`: workers kept running, 1 to 64 (default 4);
//! - `ACCESS_PARSER_LOADER`: colon-separated directories the workers' dynamic loader reads
//!   (default `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, `/etc/ld.so.cache`, those that exist);
//! - `ACCESS_PARSER_RUN_AS`: `uid:gid` to switch to when started as root (SA-22).

use std::io::Write as _;
use std::num::NonZeroUsize;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use access_edge_core::pool::{Pool, PoolConfig, read_frame};
use suiss_sandbox::{LandlockAbi, Lockdown, Profile, RunAs};

/// Most gateway connections served at once.
pub(crate) const MAX_CONNECTIONS: usize = 64;

/// Longest a gateway connection may stay idle.
pub(crate) const IDLE: Duration = Duration::from_secs(30);

const LOADER: [&str; 5] = [
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/etc/ld.so.cache",
];

/// One line on standard error; the supervisor carries no telemetry stack (OP-155 m.3 (c)).
pub(crate) fn log(message: &str) {
    #[allow(
        clippy::print_stderr,
        reason = "the worker binary logs to standard error only"
    )]
    {
        eprintln!("access-parser-worker: {message}");
    }
}

struct Config {
    socket: PathBuf,
    callers: Vec<u32>,
    workers: NonZeroUsize,
    loader: Vec<PathBuf>,
    run_as: Option<RunAs>,
}

fn config() -> Result<Config, String> {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let socket =
        PathBuf::from(var("ACCESS_PARSER_SOCKET").ok_or("ACCESS_PARSER_SOCKET is required")?);
    let callers = var("ACCESS_PARSER_CALLERS")
        .ok_or("ACCESS_PARSER_CALLERS is required")?
        .split(',')
        .map(|u| {
            u.trim()
                .parse::<u32>()
                .map_err(|_| "ACCESS_PARSER_CALLERS: not a user id")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let workers = match var("ACCESS_PARSER_WORKERS") {
        None => NonZeroUsize::MIN.saturating_add(3),
        Some(n) => n
            .parse::<NonZeroUsize>()
            .ok()
            .filter(|n| n.get() <= 64)
            .ok_or("ACCESS_PARSER_WORKERS: 1 to 64")?,
    };
    let loader = var("ACCESS_PARSER_LOADER").map_or_else(
        || LOADER.iter().map(PathBuf::from).collect(),
        |v| v.split(':').map(PathBuf::from).collect::<Vec<_>>(),
    );
    let run_as = var("ACCESS_PARSER_RUN_AS")
        .map(|v| {
            let (u, g) = v.split_once(':').ok_or("ACCESS_PARSER_RUN_AS: uid:gid")?;
            let (u, g) = (u.parse::<u32>(), g.parse::<u32>());
            match (u, g) {
                (Ok(u), Ok(g)) => RunAs::new(u, g).map_err(|_| "ACCESS_PARSER_RUN_AS: not root"),
                _ => Err("ACCESS_PARSER_RUN_AS: uid:gid"),
            }
        })
        .transpose()?;
    Ok(Config {
        socket,
        callers,
        workers,
        loader: loader.into_iter().filter(|p| p.exists()).collect(),
        run_as,
    })
}

#[cfg(target_os = "linux")]
fn admitted(s: &UnixStream, callers: &[u32]) -> bool {
    rustix::net::sockopt::socket_peercred(s).is_ok_and(|c| callers.contains(&c.uid.as_raw()))
}

#[cfg(not(target_os = "linux"))]
fn admitted(_: &UnixStream, _: &[u32]) -> bool {
    false
}

fn answer(mut s: UnixStream, pool: &Pool) {
    if s.set_read_timeout(Some(IDLE)).is_err() {
        return;
    }
    let Ok(mut input) = s.try_clone() else {
        return;
    };
    while let Ok(Some(frame)) = read_frame(&mut input) {
        let Ok(out) = pool.call(&frame).encode() else {
            return;
        };
        if s.write_all(&out).is_err() {
            return;
        }
    }
}

/// Runs the supervisor until its socket fails.
pub(crate) fn run() -> ExitCode {
    let config = match config() {
        Ok(c) => c,
        Err(error) => {
            log(&format!("invalid configuration: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let Ok(exe) = std::env::current_exe() else {
        log("cannot name its own executable");
        return ExitCode::FAILURE;
    };
    let _ = std::fs::remove_file(&config.socket);
    let listener = match UnixListener::bind(&config.socket) {
        Ok(l) => l,
        Err(error) => {
            log(&format!("cannot bind the socket: {error}"));
            return ExitCode::FAILURE;
        }
    };
    // SA-22, OP-90, OP-155 m.3 (c)
    let mut lockdown = Lockdown::new(Profile::ParserSupervisor, LandlockAbi::REQUIRED)
        .allow_execute(&exe)
        .allow_read("/proc");
    for dir in &config.loader {
        lockdown = lockdown.allow_execute(dir);
    }
    if let Some(run_as) = config.run_as {
        lockdown = lockdown.run_as(run_as);
    }
    let locked = match lockdown.apply() {
        Ok(locked) => locked,
        Err(error) => {
            log(&format!(
                "runtime lockdown failed; refusing to start (OP-90): {error}"
            ));
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = locked.narrow() {
        log(&format!(
            "seccomp phase 2 failed; refusing to continue: {error}"
        ));
        return ExitCode::FAILURE;
    }
    let pool = match Pool::start(PoolConfig {
        size: config.workers,
        ..PoolConfig::new(exe)
    }) {
        Ok(pool) => Arc::new(pool),
        Err(error) => {
            log(&format!("cannot start the workers: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let live = Arc::new(AtomicUsize::new(0));
    let callers = Arc::new(config.callers);
    for conn in listener.incoming() {
        let Ok(s) = conn else { continue };
        if !admitted(&s, &callers) || live.load(Ordering::Acquire) >= MAX_CONNECTIONS {
            continue;
        }
        live.fetch_add(1, Ordering::AcqRel);
        let (pool, live) = (Arc::clone(&pool), Arc::clone(&live));
        let spawned = std::thread::Builder::new()
            .name(String::from("gateway"))
            .spawn(move || {
                answer(s, &pool);
                live.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            log("cannot start a connection thread");
        }
    }
    ExitCode::FAILURE
}
