//! A replica twin (§16.6.1, OP-158 m.3 (f)): a real `access-replica` process following one
//! domain's mirror run, with its key and copy under a directory the test owns. It is started
//! from a binary path, killed with `SIGKILL`, started again from the same copy, and its acks,
//! advisory reads and redactions are read back from the process itself.

use std::io::{BufRead as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// Why the twin could not do what it was asked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReplicaError {
    /// The process could not be run or answered something unexpected.
    #[error("access-replica: {0}")]
    Process(String),
    /// Its files could not be read or written.
    #[error("files: {0}")]
    Io(#[from] std::io::Error),
}

/// How long a replica may take to print its listening line.
pub const START_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the replica follows from.
#[derive(Clone, Debug)]
pub struct Follows {
    /// The provider's listener, `127.0.0.1:<port>`.
    pub server: String,
    /// The domain.
    pub domain: [u8; 32],
    /// The mirror run the operator's audit export Exercise started.
    pub export: [u8; 32],
    /// The domain's Ed25519 binding keys.
    pub bindings: Vec<[u8; 32]>,
}

/// A running replica.
pub struct Replica {
    bin: PathBuf,
    child: Option<Child>,
    lines: Option<Receiver<String>>,
    /// The advisory read endpoint, `127.0.0.1:<port>`.
    pub addr: String,
    /// Its Ed25519 ack key, as the domain declares it.
    pub key: [u8; 32],
    /// Its name.
    pub name: String,
    /// Its configuration file.
    pub config: PathBuf,
    /// Its copy.
    pub state: PathBuf,
}

fn b64url(b: &[u8]) -> String {
    access_kernel::json::b64url_encode(b)
}

fn fail(e: impl std::fmt::Display) -> ReplicaError {
    ReplicaError::Process(e.to_string())
}

impl Replica {
    /// Generates the ack key of the replica `name` in `root` and starts it on `follows`.
    ///
    /// # Errors
    /// [`ReplicaError`].
    pub fn start(
        bin: &Path,
        root: &Path,
        name: &str,
        follows: &Follows,
    ) -> Result<Self, ReplicaError> {
        std::fs::create_dir_all(root)?;
        let key_file = root.join(format!("{name}.pk8"));
        let out = Command::new(bin).arg("keygen").arg(&key_file).output()?;
        if !out.status.success() {
            return Err(fail(String::from_utf8_lossy(&out.stderr)));
        }
        let key = String::from_utf8_lossy(&out.stdout)
            .trim()
            .strip_prefix("key ")
            .and_then(|k| access_kernel::json::b64url_decode(k).ok())
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
            .ok_or_else(|| fail("no key"))?;
        let state = root.join(format!("{name}-state"));
        let config = root.join(format!("{name}.conf"));
        let mut text = format!(
            "name {name}\nkey {}\nstate {}\nserver http://{}\ndomain {}\nexport {}\nlisten 127.0.0.1:0\n",
            key_file.display(),
            state.display(),
            follows.server,
            b64url(&follows.domain),
            b64url(&follows.export),
        );
        for b in &follows.bindings {
            text.push_str("binding ");
            text.push_str(&b64url(b));
            text.push('\n');
        }
        std::fs::write(&config, text)?;
        let mut r = Self {
            bin: bin.to_path_buf(),
            child: None,
            lines: None,
            addr: String::new(),
            key,
            name: name.to_owned(),
            config,
            state,
        };
        r.spawn()?;
        Ok(r)
    }

    fn spawn(&mut self) -> Result<(), ReplicaError> {
        let mut child = Command::new(&self.bin)
            .arg("follow")
            .arg(&self.config)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdout = child.stdout.take().ok_or_else(|| fail("no stdout"))?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let line = rx.recv_timeout(START_TIMEOUT).map_err(fail)?;
        line.trim()
            .strip_prefix("listening ")
            .ok_or_else(|| fail(format!("unexpected start line: {line}")))?
            .clone_into(&mut self.addr);
        self.child = Some(child);
        self.lines = Some(rx);
        Ok(())
    }

    /// Waits until it says it acked a size of at least `size`, at most `wait`; the size it
    /// acked, or `None` when it did not in time.
    #[must_use]
    pub fn acked(&self, size: u64, wait: Duration) -> Option<u64> {
        let rx = self.lines.as_ref()?;
        let deadline = Instant::now().checked_add(wait)?;
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            match rx.recv_timeout(left) {
                Ok(line) => {
                    let got = line
                        .strip_prefix("acked ")
                        .and_then(|n| n.trim().parse::<u64>().ok());
                    if let Some(n) = got.filter(|n| *n >= size) {
                        return Some(n);
                    }
                }
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    /// `SIGKILL`s the process and waits for it.
    ///
    /// # Errors
    /// [`ReplicaError::Io`].
    pub fn kill(&mut self) -> Result<(), ReplicaError> {
        if let Some(mut c) = self.child.take() {
            c.kill()?;
            c.wait()?;
        }
        self.lines = None;
        Ok(())
    }

    /// Starts it again from the same configuration and copy.
    ///
    /// # Errors
    /// [`ReplicaError`].
    pub fn restart(&mut self) -> Result<(), ReplicaError> {
        self.kill()?;
        self.spawn()
    }

    /// Runs `access-replica apply-redactions` on its stopped copy for `positions`, then starts
    /// it again; what the command reported.
    ///
    /// # Errors
    /// [`ReplicaError`].
    pub fn apply_redactions(&mut self, positions: &[u64]) -> Result<String, ReplicaError> {
        self.kill()?;
        let out = Command::new(&self.bin)
            .arg("apply-redactions")
            .arg(&self.config)
            .args(positions.iter().map(u64::to_string))
            .output()?;
        if !out.status.success() {
            return Err(fail(String::from_utf8_lossy(&out.stderr)));
        }
        self.spawn()?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// The JSON its advisory read endpoint answers for `path` (`/v1/head`,
    /// `/v1/records/<position>`), with the status.
    ///
    /// # Errors
    /// [`ReplicaError`].
    pub fn read(&self, path: &str) -> Result<(u16, String), ReplicaError> {
        let mut s = std::net::TcpStream::connect(&self.addr)?;
        s.set_read_timeout(Some(START_TIMEOUT))?;
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.addr
        )?;
        let mut raw = String::new();
        s.read_to_string(&mut raw)?;
        let status = raw
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| fail("no status"))?;
        let body = raw
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_owned())
            .unwrap_or_default();
        Ok((status, body))
    }

    /// The signed acks its copy keeps, in order (one base64url `signed-replica-ack` each).
    ///
    /// # Errors
    /// [`ReplicaError::Io`].
    pub fn kept_acks(&self, domain: [u8; 32]) -> Result<Vec<String>, ReplicaError> {
        let path = self.state.join(b64url(&domain)).join("acks");
        match std::fs::read_to_string(path) {
            Ok(t) => Ok(t.lines().map(String::from).collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }
}

impl Drop for Replica {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}
