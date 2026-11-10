//! `access-proxy`: renders `access-proxy.toml` for an engine, and in the packaged images starts
//! the engine on what it rendered (OP-156 m.3 (m)). It serves nothing itself (Ek B 5369).
//!
//! ```text
//! access-proxy check  [--config FILE]
//! access-proxy render --engine envoy|caddy|traefik [--config FILE] [--out FILE]
//! access-proxy run    --engine envoy|caddy [--config FILE] [--dir DIR]
//! ```
//!
//! `--config` defaults to `/etc/access-proxy/access-proxy.toml`, `--dir` to `/run/access-proxy`;
//! `render` writes to standard output unless `--out` names a file.

use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use access_proxy::config::Config;
use access_proxy::render::{Target, render};

const CONFIG: &str = "/etc/access-proxy/access-proxy.toml";
const DIR: &str = "/run/access-proxy";

struct Args {
    command: String,
    engine: Option<Target>,
    config: PathBuf,
    out: Option<PathBuf>,
    dir: PathBuf,
}

fn args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let command = it
        .next()
        .ok_or_else(|| String::from("a command is needed: check, render or run"))?;
    let mut a = Args {
        command,
        engine: None,
        config: PathBuf::from(CONFIG),
        out: None,
        dir: PathBuf::from(DIR),
    };
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--engine" => {
                a.engine =
                    Some(Target::parse(&value).ok_or_else(|| format!("unknown engine {value}"))?);
            }
            "--config" => a.config = PathBuf::from(value),
            "--out" => a.out = Some(PathBuf::from(value)),
            "--dir" => a.dir = PathBuf::from(value),
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(a)
}

fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Config::parse(&text).map_err(|e| e.to_string())
}

fn engine_command(target: Target, file: &Path) -> Result<Command, String> {
    match target {
        Target::Envoy => {
            let mut c = Command::new("envoy");
            c.arg("--config-path")
                .arg(file)
                .args(["--log-level", "info", "--disable-hot-restart"]);
            Ok(c)
        }
        Target::Caddy => {
            let mut c = Command::new("caddy");
            c.arg("run")
                .arg("--config")
                .arg(file)
                .args(["--adapter", "caddyfile"]);
            Ok(c)
        }
        Target::Traefik => Err(String::from("traefik is rendered only; it is not packaged")),
    }
}

fn run() -> Result<(), String> {
    let a = args()?;
    let config = load(&a.config)?;
    match a.command.as_str() {
        "check" => Ok(()),
        "render" => {
            let target = a
                .engine
                .ok_or_else(|| String::from("render needs --engine"))?;
            let text = render(&config, target).map_err(|e| e.to_string())?;
            match a.out {
                Some(p) => std::fs::write(&p, text).map_err(|e| format!("{}: {e}", p.display())),
                None => std::io::stdout()
                    .write_all(text.as_bytes())
                    .map_err(|e| e.to_string()),
            }
        }
        "run" => {
            let target = a.engine.ok_or_else(|| String::from("run needs --engine"))?;
            let text = render(&config, target).map_err(|e| e.to_string())?;
            let file = a.dir.join(target.file());
            std::fs::write(&file, text).map_err(|e| format!("{}: {e}", file.display()))?;
            let err = engine_command(target, &file)?.exec();
            Err(format!("{}: {err}", target.word()))
        }
        other => Err(format!("unknown command {other}")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "access-proxy: {e}");
            ExitCode::from(2)
        }
    }
}
