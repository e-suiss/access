//! Restriction analysis solver (OP-157 m.8 (a), OP-159 m.3 (aa)).
//!
//! The binary runs the pinned cvc5 under its own sandbox and answers `restriction-analysis`
//! requests from the server over a Unix socket whose owner and mode it checks at start. The
//! server keeps its seccomp profile; an unreachable or slow solver raises the classification.
//!
//! ```text
//! access-policy-solver serve <config>
//! ```
//!
//! The configuration names the socket and the cvc5 executable, one `key = "value"` per line:
//!
//! ```text
//! socket = "/run/access-solver/solver.sock"
//! cvc5 = "/opt/cvc5/bin/cvc5"
//! mode = "0660"
//! ```

use std::io::Write as _;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use restriction_analysis::sibling::{Relation, check_socket, read_request};
use restriction_analysis::{Cvc5, Limits, Timeouts};

/// The usage text.
const USAGE: &str = "usage:\naccess-policy-solver serve <config>\n";

/// Time limits of one comparison (OP-157 m.3 (n)); the server waits a little longer.
const TIMEOUTS: Timeouts = Timeouts {
    query: Duration::from_secs(10),
    total: Duration::from_secs(30),
};

/// How long a client may take to send its request.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Comparisons running at once; a request beyond them is answered `Unknown`.
const MAX_RUNNING: usize = 4;

/// The configuration file.
#[derive(Debug, PartialEq, Eq)]
struct Config {
    socket: PathBuf,
    cvc5: PathBuf,
    mode: u32,
}

fn parse(text: &str) -> Result<Config, String> {
    let (mut socket, mut cvc5, mut mode) = (None, None, 0o600);
    for (n, line) in text
        .lines()
        .enumerate()
        .map(|(n, l)| (n.saturating_add(1), l.trim()))
    {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("line {n}: expected key = \"value\""))?;
        let v = v
            .trim()
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .ok_or_else(|| format!("line {n}: the value is not a quoted string"))?;
        match k.trim() {
            "socket" => socket = Some(PathBuf::from(v)),
            "cvc5" => cvc5 = Some(PathBuf::from(v)),
            "mode" => {
                mode = match v {
                    "0600" => 0o600,
                    "0660" => 0o660,
                    _ => return Err(format!("line {n}: mode is 0600 or 0660")),
                };
            }
            other => return Err(format!("line {n}: unknown key {other:?}")),
        }
    }
    Ok(Config {
        socket: socket.ok_or("no socket")?,
        cvc5: cvc5.ok_or("no cvc5")?,
        mode,
    })
}

// OP-115 m.6
fn confine(command: &mut std::process::Command, solver: &Path) -> std::io::Result<()> {
    suiss_sandbox::Lockdown::new(
        suiss_sandbox::Profile::Solver,
        suiss_sandbox::LandlockAbi::REQUIRED,
    )
    .allow_execute(solver)
    .confine(command)
    .map_err(std::io::Error::other)
}

/// Binds the socket with `mode` and checks it and its directory (OP-159 m.3 (aa)).
fn bind(config: &Config) -> Result<UnixListener, String> {
    let path = &config.socket;
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if !m.file_type().is_socket() {
            return Err(format!("{}: exists and is not a socket", path.display()));
        }
        std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(config.mode))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    check_socket(path, None).map_err(|e| e.to_string())?;
    Ok(listener)
}

fn answer(cvc5: &Cvc5, mut stream: UnixStream, running: &AtomicUsize) {
    let relation = if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err() {
        Relation::Unknown
    } else {
        match read_request(&mut stream) {
            Some((schema, old, new)) if running.load(Ordering::Acquire) <= MAX_RUNNING => {
                Relation::of_change(&restriction_analysis::compare(
                    cvc5,
                    &schema,
                    &old,
                    &new,
                    Limits::default(),
                ))
            }
            _ => Relation::Unknown,
        }
    };
    let _ = stream.write_all(&[relation.code()]);
}

fn serve(config: &Config) -> Result<(), String> {
    let cvc5 = Arc::new(Cvc5::pinned(&config.cvc5, TIMEOUTS, confine).map_err(|e| e.to_string())?);
    let listener = bind(config)?;
    let running = Arc::new(AtomicUsize::new(0));
    let _ = std::io::stderr().write_all(
        format!(
            "access-policy-solver: listening on {}\n",
            config.socket.display()
        )
        .as_bytes(),
    );
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let (task_cvc5, task_running) = (cvc5.clone(), running.clone());
        running.fetch_add(1, Ordering::AcqRel);
        let spawned = std::thread::Builder::new()
            .name("solver-request".into())
            .spawn(move || {
                answer(&task_cvc5, stream, &task_running);
                task_running.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            running.fetch_sub(1, Ordering::AcqRel);
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [h] if h == "--help" || h == "-h" => {
            let _ = std::io::stdout().write_all(USAGE.as_bytes());
            ExitCode::SUCCESS
        }
        [cmd, path] if cmd == "serve" => {
            let run = std::fs::read_to_string(path)
                .map_err(|e| format!("{}: {e}", Path::new(path).display()))
                .and_then(|t| parse(&t))
                .and_then(|c| serve(&c));
            match run {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    let _ = std::io::stderr()
                        .write_all(format!("access-policy-solver: {e}\n").as_bytes());
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            let _ = std::io::stderr().write_all(USAGE.as_bytes());
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-159 m.3 (aa)
    #[test]
    fn the_configuration_names_the_socket_the_solver_and_a_closed_mode() {
        let c = parse("# x\nsocket = \"/run/s.sock\"\ncvc5 = \"/opt/cvc5\"\n").unwrap();
        assert_eq!(
            c,
            Config {
                socket: "/run/s.sock".into(),
                cvc5: "/opt/cvc5".into(),
                mode: 0o600
            }
        );
        assert_eq!(
            parse("socket = \"/s\"\ncvc5 = \"/c\"\nmode = \"0660\"\n")
                .unwrap()
                .mode,
            0o660
        );
        assert!(parse("socket = \"/s\"\ncvc5 = \"/c\"\nmode = \"0666\"\n").is_err());
        assert!(parse("socket = \"/s\"\n").is_err());
        assert!(parse("socket = /s\ncvc5 = \"/c\"\n").is_err());
        assert!(parse("socket = \"/s\"\ncvc5 = \"/c\"\nkey = \"secret\"\n").is_err());
    }
}
