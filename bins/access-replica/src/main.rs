//! Replica agent (§16.6.1, T21, CMP-21, TI-13, OP-158 m.3 (f)): an open process the domain's
//! replica operator runs outside the provider. It follows the domain's Replica Mirror, checks
//! every record against the tree it rebuilds and every checkpoint against the domain's binding
//! keys, keeps its own append-only copy and answers a signed `replica_ack {size, root}` only
//! once the copy is on disk. Its reads are advisory only and never a source of ALLOW (P43).
//! `apply-redactions` applies a redaction to the local copy (U22); redaction at the source does
//! not reach a copy by itself (N-11).
//!
//! ```text
//! access-replica keygen <key file>              new Ed25519 ack key (mode 0600); prints it
//! access-replica key <key file>                 prints the public key the domain declares
//! access-replica follow <config>                follows; prints `listening <addr>`, `acked <size>`
//! access-replica apply-redactions <config> [<position>…]
//!                                               applies received redactions and the named ones
//! access-replica --replay <config>              the sampling replay agent (not built yet)
//! ```
//!
//! Exit status: 0 ok, 1 failure, 2 usage.

mod client;
mod config;
mod serve;
mod state;
mod verify;

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use access_kernel::json::b64url_encode;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer as _, SoftSigner};
use suiss_ledger::replica::mirror::{Frame, ReplicaAck, SignedReplicaAck, read_all};

use crate::config::Config;
use crate::state::Store;

const USAGE: &str = "usage:\naccess-replica follow <config>\naccess-replica apply-redactions <config> [<position>...]\naccess-replica keygen <key file>\naccess-replica key <key file>\naccess-replica --replay <config>\n";

/// Wait after a failed exchange before asking again.
const BACKOFF: Duration = Duration::from_secs(1);

fn out(text: &str) -> bool {
    let mut o = std::io::stdout().lock();
    o.write_all(text.as_bytes())
        .and_then(|()| o.flush())
        .is_ok()
}

fn err(text: &str) {
    let _ = std::io::stderr()
        .lock()
        .write_all(format!("access-replica: {}\n", text.trim_end()).as_bytes());
}

fn public(signer: &SoftSigner) -> Result<[u8; 32], String> {
    match signer.public_key() {
        PublicKey::Ed25519(k) => Ok(k),
        _ => Err("not an Ed25519 key".into()),
    }
}

/// Reads the operator's key file (never an argument or environment value).
fn load(path: &Path) -> Result<SoftSigner, String> {
    let doc = Secret::new(std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?);
    SoftSigner::ed25519_from_pkcs8(&doc).map_err(|e| format!("{}: {e}", path.display()))
}

fn keygen(path: &Path) -> Result<String, String> {
    let (signer, doc) = SoftSigner::generate_ed25519().map_err(|e| e.to_string())?;
    let key = public(&signer)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(doc.expose())
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(format!("key {}\n", b64url_encode(&key)))
}

fn read_config(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    config::parse(&text)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or_default()
}

struct Follower {
    config: Config,
    signer: SoftSigner,
    store: Arc<Mutex<Store>>,
    unsent: Option<(u64, Vec<u8>)>,
}

impl Follower {
    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sign(&self, size: u64, root: [u8; 32]) -> Result<Vec<u8>, String> {
        let ack = ReplicaAck {
            domain: self.config.domain.0,
            replica: self.config.name.clone(),
            size,
            root,
            at: now_ms(),
        };
        let sig = self
            .signer
            .sign(&ack.message().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let sig: [u8; 64] = sig.try_into().map_err(|_| "signature length")?;
        SignedReplicaAck { ack, sig }
            .to_bytes()
            .map_err(|e| e.to_string())
    }

    /// Applies one mirror answer to the copy; an error stops the agent.
    fn apply(&mut self, frames: Vec<Frame>) -> Result<(), String> {
        let mut appended = false;
        for f in frames {
            match f {
                Frame::Record { envelope, .. } => {
                    self.store().append(&envelope)?;
                    appended = true;
                }
                Frame::Checkpoint {
                    note,
                    excerpt: Some(excerpt),
                    ..
                } => {
                    let cp = verify::checkpoint(
                        &self.config.domain,
                        &self.config.bindings,
                        &note,
                        &excerpt,
                    )?;
                    if self.store().accept(&cp, &note)? {
                        let signed = self.sign(cp.size, cp.root)?;
                        self.store().keep_ack(&signed)?;
                        self.unsent = Some((cp.size, signed));
                    }
                }
                Frame::Checkpoint { excerpt: None, .. } | Frame::Heartbeat { .. } => {}
                Frame::Redaction { position, dek } => self.store().received(position, &dek)?,
            }
        }
        if appended {
            self.store().sync()?;
        }
        Ok(())
    }

    async fn send_ack(&mut self) {
        let Some((size, body)) = self.unsent.clone() else {
            return;
        };
        let path = format!(
            "/access/v1/domains/{}/mirror",
            b64url_encode(&self.config.domain.0)
        );
        match client::exchange(&self.config.server, "POST", &path, &body).await {
            Ok((204, _)) => {
                self.unsent = None;
                out(&format!("acked {size}\n"));
            }
            Ok((status, body)) => {
                err(&format!(
                    "ack {size} refused with {status}: {}",
                    String::from_utf8_lossy(&body)
                ));
                self.unsent = None;
            }
            Err(e) => err(&format!("ack {size} not sent: {e}")),
        }
    }

    async fn run(mut self) -> Result<(), String> {
        loop {
            self.send_ack().await;
            let (from, checkpoint) = {
                let s = self.store();
                (s.follower.size(), s.follower.accepted().map_or(0, |a| a.0))
            };
            let path = format!(
                "/access/v1/domains/{}/mirror?export={}&from={from}&checkpoint={checkpoint}",
                b64url_encode(&self.config.domain.0),
                b64url_encode(&self.config.export),
            );
            match client::exchange(&self.config.server, "GET", &path, &[]).await {
                Ok((200, body)) => {
                    let frames = read_all(&body).map_err(|e| e.to_string())?;
                    self.apply(frames)?;
                }
                Ok((status, body)) => {
                    err(&format!(
                        "mirror answered {status}: {}",
                        String::from_utf8_lossy(&body)
                    ));
                    tokio::time::sleep(BACKOFF).await;
                }
                Err(e) => {
                    err(&format!("mirror: {e}"));
                    tokio::time::sleep(BACKOFF).await;
                }
            }
        }
    }
}

async fn follow(path: &Path) -> Result<(), String> {
    let config = read_config(path)?;
    let signer = load(&config.key)?;
    let store = Arc::new(Mutex::new(Store::open(&config.state, config.domain)?));
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|e| format!("{}: {e}", config.listen))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let reads = serve::router(store.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, reads).await;
    });
    if !out(&format!("listening {addr}\n")) {
        return Err("stdout closed".into());
    }
    let agent = Follower {
        config,
        signer,
        store,
        unsent: None,
    };
    tokio::select! {
        r = agent.run() => r,
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

fn apply_redactions(path: &Path, named: &[String]) -> Result<String, String> {
    let config = read_config(path)?;
    let mut store = Store::open(&config.state, config.domain)?;
    let mut positions = store.pending()?;
    for n in named {
        positions.push(n.parse().map_err(|_| format!("{n}: not a position"))?);
    }
    positions.sort_unstable();
    positions.dedup();
    let mut report = Vec::new();
    for p in positions {
        report.push(if store.redact(p)? {
            format!("applied {p}\n")
        } else {
            format!("not held {p}\n")
        });
    }
    Ok(report.concat())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).map(String::as_str);
    let result = match (arg(0), arg(1)) {
        (Some("--help" | "-h"), _) => {
            out(USAGE);
            return ExitCode::SUCCESS;
        }
        (Some("keygen"), Some(file)) if args.len() == 2 => keygen(Path::new(file)),
        (Some("key"), Some(file)) if args.len() == 2 => load(Path::new(file))
            .and_then(|s| public(&s))
            .map(|k| format!("key {}\n", b64url_encode(&k))),
        (Some("apply-redactions"), Some(config)) => {
            apply_redactions(Path::new(config), args.get(2..).unwrap_or_default())
        }
        (Some("follow"), Some(config)) if args.len() == 2 => {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    err(&e.to_string());
                    return ExitCode::FAILURE;
                }
            };
            runtime
                .block_on(follow(Path::new(config)))
                .map(|()| String::new())
        }
        (Some("--replay"), Some(_)) => {
            err("the sampling replay agent is not built yet");
            return ExitCode::from(2);
        }
        _ => {
            let _ = std::io::stderr().write_all(USAGE.as_bytes());
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(text) => {
            if out(&text) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            err(&e);
            ExitCode::FAILURE
        }
    }
}
