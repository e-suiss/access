//! Access witness (§16.6 witness protocol, CMP-6, T17, OP-158 m.3 (d)): an open process any
//! operator runs for a domain. It cosigns a checkpoint only after a consistency proof from the
//! last one it cosigned and only under the domain's current binding, keeps its own
//! hash-chained state files, and answers gossip so monitors can compare what every witness
//! saw (U9, HL-7). It never connects to the Access store.
//!
//! ```text
//! access-witness keygen <key file> <name>   new Ed25519 key (mode 0600); prints the vkey
//! access-witness vkey <key file> <name>     prints the vkey of an existing key
//! access-witness serve <config file>        serves; prints `listening <addr>`
//! access-witness monitor <domain> <url> <vkey> [<url> <vkey>]…
//!                                           compares the witnesses' latest cosigned checkpoints
//! ```
//!
//! Exit status: 0 ok, 1 failure, 2 usage, 3 equivocation found.

mod config;
mod http;
mod monitor;
mod serve;
mod state;
mod verify;

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use suiss_crypto::cose::PublicKey;
use suiss_crypto::note::Verifier;
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer as _, SoftSigner};

const USAGE: &str = "usage: access-witness keygen <key file> <name> | vkey <key file> <name> | serve <config file> | monitor <domain> <url> <vkey> [<url> <vkey>]...\n";

fn out(text: &str) -> bool {
    let mut o = std::io::stdout().lock();
    o.write_all(text.as_bytes())
        .and_then(|()| o.flush())
        .is_ok()
}

fn err(text: &str) {
    let _ = std::io::stderr()
        .lock()
        .write_all(format!("access-witness: {}\n", text.trim_end()).as_bytes());
}

fn vkey_of(signer: &SoftSigner, name: &str) -> Result<String, String> {
    let PublicKey::Ed25519(k) = signer.public_key() else {
        return Err("not an Ed25519 key".into());
    };
    Verifier::cosigner(name, k)
        .map(|v| v.to_vkey())
        .map_err(|e| format!("name: {e}"))
}

/// Reads the operator's key file (never an argument or environment value).
fn load(path: &Path) -> Result<SoftSigner, String> {
    let doc = Secret::new(std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?);
    SoftSigner::ed25519_from_pkcs8(&doc).map_err(|e| format!("{}: {e}", path.display()))
}

fn keygen(path: &Path, name: &str) -> Result<String, String> {
    let (signer, doc) = SoftSigner::generate_ed25519().map_err(|e| e.to_string())?;
    let vkey = vkey_of(&signer, name)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(doc.expose())
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(format!("vkey {vkey}\n"))
}

async fn serve(path: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let config = config::parse(&text)?;
    std::fs::create_dir_all(&config.state)
        .map_err(|e| format!("{}: {e}", config.state.display()))?;
    let signer = load(&config.key)?;
    let vkey = vkey_of(&signer, &config.name)?;
    let listen = config.listen;
    let witness = Arc::new(serve::Witness::open(config, signer, vkey)?);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| format!("{listen}: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    if !out(&format!("listening {addr}\n")) {
        return Err("stdout closed".into());
    }
    axum::serve(listener, serve::router(witness))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| e.to_string())
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["keygen", key, name] => {
            let line = keygen(Path::new(key), name)?;
            Ok(if out(&line) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        ["vkey", key, name] => {
            let line = format!("vkey {}\n", vkey_of(&load(Path::new(key))?, name)?);
            Ok(if out(&line) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        ["serve", config] => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(serve(Path::new(config)))?;
            Ok(ExitCode::SUCCESS)
        }
        ["monitor", domain, pairs @ ..] if !pairs.is_empty() && pairs.len() % 2 == 0 => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let report = rt.block_on(monitor::run(domain, pairs))?;
            let code = match report.status {
                monitor::Status::Consistent => ExitCode::SUCCESS,
                monitor::Status::Unreachable => ExitCode::FAILURE,
                monitor::Status::Equivocation => ExitCode::from(3),
            };
            Ok(if out(&report.text) {
                code
            } else {
                ExitCode::FAILURE
            })
        }
        _ => {
            let _ = out(USAGE);
            Ok(ExitCode::from(2))
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            err(&e);
            ExitCode::FAILURE
        }
    }
}
