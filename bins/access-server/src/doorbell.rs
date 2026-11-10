//! The NATS `JetStream` doorbell in this process (OP-23, T26, OP-156 m.3 (j)): every domain leader
//! rings after a durable commit, one task publishes the rings and waits for the stream's
//! acknowledgement, another listens and wakes the event fan-out. The fan-out still reads its
//! cursors and still polls: a server that is down only delays it.

use std::path::Path;
use std::sync::Arc;

use suiss_ledger::doorbell::client::{self, DoorbellError, Report};
use suiss_ledger::doorbell::{Bell, Topic};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

use crate::config;

/// Rings queued before the publisher drops them (PD).
pub(crate) const QUEUE: usize = 1024;

/// The doorbell's tasks.
pub(crate) struct Doorbell {
    /// What the domain leaders ring.
    pub(crate) bell: Arc<dyn Bell>,
    /// What a ring wakes.
    pub(crate) wake: Arc<Notify>,
    stop: watch::Sender<bool>,
    tasks: [JoinHandle<()>; 2],
}

fn owner_only(path: &Path) -> Result<(), String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{}: must be a regular file readable by its owner only",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    Ok(())
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The client configuration of `section`, with a fresh inbox token for this process.
///
/// # Errors
/// A file that cannot be read, a key file others may read, or PEM that does not load.
pub(crate) fn client(section: &config::Doorbell) -> Result<client::Config, String> {
    owner_only(&section.key_file)?;
    let tls = client::tls(
        &read(&section.ca_file)?,
        &read(&section.cert_file)?,
        &read(&section.key_file)?,
    )
    .map_err(|e| e.to_string())?;
    let token = access_crypto::random::bytes::<16>().map_err(|e| e.to_string())?;
    Ok(client::Config {
        addr: section.addr.clone(),
        server_name: rustls_pki_types::ServerName::try_from(section.server_name.clone())
            .map_err(|e| e.to_string())?,
        tls,
        topic: Topic::ACCESS,
        inbox: token.iter().fold(String::new(), |mut s, b| {
            let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
            s
        }),
        name: String::from("access-server"),
    })
}

fn down(e: &DoorbellError) {
    tracing::warn!(error = %e, "doorbell down; consumers keep polling (OP-23)");
}

impl Doorbell {
    /// Starts publishing and listening over `cfg`.
    pub(crate) fn start(cfg: &client::Config) -> Self {
        let (queue, rings) = client::queue(QUEUE);
        let (stop, stopped) = watch::channel(false);
        let wake = Arc::new(Notify::new());
        let publishing = tokio::spawn(client::publish(cfg.clone(), rings, stopped.clone(), |r| {
            if let Report::Down(e) = r {
                down(&e);
            }
        }));
        let woken = wake.clone();
        let listening = tokio::spawn(client::listen(
            cfg.clone(),
            stopped,
            move |_, _| woken.notify_one(),
            |e| down(&e),
        ));
        Self {
            bell: Arc::new(queue),
            wake,
            stop,
            tasks: [publishing, listening],
        }
    }

    /// Stops both tasks.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
    }
}

#[cfg(test)]
mod tests;
