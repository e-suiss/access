//! The host's own ports: the system clock, the OS randomness, the kept state in a file only
//! root reads, and the daemon's socket.

use std::future::Future;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use access_linux_module::wire::{self, Request, Response};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixListener;

use crate::app::{Daemon, Note};
use crate::domain::state::State;
use crate::ports::{Access, Clock, Keep, Random, SecurityKey};

/// The system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> Option<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
    }
}

/// The operating system's randomness.
pub struct OsRandom;

impl Random for OsRandom {
    fn bytes<const N: usize>(&self) -> Option<[u8; N]> {
        let mut out = [0u8; N];
        rustls::crypto::aws_lc_rs::default_provider()
            .secure_random
            .fill(&mut out)
            .ok()?;
        Some(out)
    }
}

/// The kept state as JSON in `path`, written whole and renamed into place, mode 0600.
pub struct StateFile(pub PathBuf);

impl Keep for StateFile {
    fn load(&self) -> State {
        std::fs::read(&self.0)
            .ok()
            .and_then(|b| serde_json::from_slice::<State>(&b).ok())
            .filter(|s| s.snapshot.as_ref().is_none_or(|n| n.check().is_ok()))
            .unwrap_or_default()
    }

    fn save(&self, state: &State) -> bool {
        let Ok(bytes) = serde_json::to_vec(state) else {
            return false;
        };
        let tmp = self.0.with_extension("tmp");
        let written = (|| {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            let mut f = o.open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.0)
        })();
        written.is_ok()
    }
}

/// No local security key: offline console sign-in is refused.
pub struct NoKey;

impl SecurityKey for NoKey {
    fn get_assertion(&self, _request: &[u8]) -> impl Future<Output = Option<Vec<u8>>> + Send {
        std::future::ready(None)
    }
}

async fn one<A, C, R, K, S>(
    daemon: &Daemon<A, C, R, K, S>,
    mut stream: tokio::net::UnixStream,
    operator: u32,
) -> Option<Note>
where
    A: Access,
    C: Clock,
    R: Random,
    K: Keep,
    S: SecurityKey,
{
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.ok()?;
    let n = wire::frame_len(header).ok()?;
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body).await.ok()?;
    let root = stream.peer_cred().is_ok_and(|c| c.uid() == operator);
    let refused = (
        Response::Done {
            allow: false,
            offline: None,
        },
        Note::Online,
    );
    let (answer, note) = match Request::from_cbor(&body) {
        Ok(r) if root || r.is_lookup() => daemon.handle(r).await,
        _ => refused,
    };
    let out = wire::frame(&answer.to_cbor().ok()?).ok()?;
    stream.write_all(&out).await.ok()?;
    stream.flush().await.ok()?;
    Some(note)
}

/// Serves `daemon` on `listener` until the task is dropped; every connection is one request,
/// answered within the exchange timeout or dropped. Sign-ins and step-ups are answered only to
/// processes of user `operator` (root, as `login` and `sudo` run); lookups to anyone.
pub async fn serve<A, C, R, K, S>(
    daemon: Arc<Daemon<A, C, R, K, S>>,
    listener: UnixListener,
    operator: u32,
) where
    A: Access + 'static,
    C: Clock + 'static,
    R: Random + 'static,
    K: Keep + 'static,
    S: SecurityKey + 'static,
{
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let d = Arc::clone(&daemon);
        tokio::spawn(async move {
            let limit = access_linux_module::client::TIMEOUT;
            match tokio::time::timeout(limit, one(&d, stream, operator)).await {
                Ok(Some(Note::Expired)) => {
                    tracing::warn!(
                        event = "linux.cache.expired",
                        kind = "offline",
                        "the kept state no longer answers"
                    );
                }
                Ok(Some(Note::Unreachable)) => {
                    tracing::warn!(
                        event = "linux.daemon.unavailable",
                        error = "access",
                        "Access could not be reached"
                    );
                }
                _ => {}
            }
        });
    }
}

/// Binds the socket at `path` with mode 0666: every local process may look users up, as NSS
/// needs.
///
/// # Errors
/// The bind's error.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let l = UnixListener::bind(path)?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o666))?;
    Ok(l)
}
