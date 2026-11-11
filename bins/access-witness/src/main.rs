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
//! access-witness monitor <config file>     compares the witnesses' latest cosigned heads
//! access-witness fence <config file> <domain> <size>
//!                                           while stopped: cosign nothing above <size> under
//!                                           the binding it last cosigned (U11)
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

const USAGE: &str = "usage:\naccess-witness serve <config>\naccess-witness monitor <config>\naccess-witness keygen <key file> <name>\naccess-witness vkey <key file> <name>\naccess-witness fence <config> <domain> <size>\n";

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

/// Fences the binding `domain` was last cosigned under at `size` (U11): run while the witness
/// is stopped; it reads the fence from its chain when it starts.
fn fence(path: &Path, domain: &str, size: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let config = config::parse(&text)?;
    let d = access_kernel::json::b64url_decode(domain)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(access_kernel::digest::Digest)
        .ok_or("domain: not a base64url DomainID")?;
    let size: u64 = size.parse().map_err(|_| "size: not a number")?;
    if !config.logs.contains_key(&config::origin(&d)) {
        return Err("domain: not a log of this witness".into());
    }
    let mut chain = state::Chain::open(&config.state, &d)?;
    let binding = chain.latest.as_ref().map_or([0; 32], |e| e.binding);
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|t| u64::try_from(t.as_millis()).ok())
        .unwrap_or_default();
    chain.fence(binding, size, at)?;
    Ok(format!("fenced {size}\n"))
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
        ["monitor", config] => {
            let text = std::fs::read_to_string(config).map_err(|e| format!("{config}: {e}"))?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|d| u64::try_from(d.as_millis()).ok())
                .unwrap_or_default();
            let report = rt.block_on(monitor::run(&text, now))?;
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
        ["fence", config, domain, size] => {
            let line = fence(Path::new(config), domain, size)?;
            Ok(if out(&line) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        ["--help" | "-h" | "help"] => Ok(if out(USAGE) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }),
        _ => {
            let _ = std::io::stderr().lock().write_all(USAGE.as_bytes());
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
