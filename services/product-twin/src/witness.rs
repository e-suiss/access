//! A witness twin (§16.6, OP-158 m.3 (d)): a real `access-witness` process with its key and
//! state under a directory the test owns. It is started from a binary path, killed with
//! `SIGKILL`, restarted from the same state on a new port, and its on-disk chain is read back.

use std::io::BufRead as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use suiss_ledger::checkpoint::witness::StateEntry;

/// Why the twin could not do what it was asked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessError {
    /// The process could not be run or answered something unexpected.
    #[error("access-witness: {0}")]
    Process(String),
    /// Its files could not be read or written.
    #[error("files: {0}")]
    Io(#[from] std::io::Error),
}

/// How long a witness may take to print its listening line.
pub const START_TIMEOUT: Duration = Duration::from_secs(30);

/// A running witness.
pub struct Witness {
    bin: PathBuf,
    child: Option<Child>,
    /// `http://127.0.0.1:<port>`.
    pub url: String,
    /// Its cosigner verifier key.
    pub vkey: String,
    /// Its configuration file.
    pub config: PathBuf,
    /// Its state directory.
    pub state: PathBuf,
}

fn b64url(b: &[u8]) -> String {
    access_kernel::json::b64url_encode(b)
}

fn fail(e: impl std::fmt::Display) -> WitnessError {
    WitnessError::Process(e.to_string())
}

impl Witness {
    /// Generates a key named `name` in `root` and starts a witness of `operator` for `domain`
    /// whose binding key is `binding` (Ed25519).
    ///
    /// # Errors
    /// [`WitnessError`].
    pub fn start(
        bin: &Path,
        root: &Path,
        (name, operator): (&str, &str),
        domain: [u8; 32],
        binding: [u8; 32],
    ) -> Result<Self, WitnessError> {
        std::fs::create_dir_all(root)?;
        let key = root.join(format!("{name}.pk8"));
        let out = Command::new(bin)
            .arg("keygen")
            .arg(&key)
            .arg(name)
            .output()?;
        if !out.status.success() {
            return Err(fail(String::from_utf8_lossy(&out.stderr)));
        }
        let vkey = String::from_utf8_lossy(&out.stdout)
            .trim()
            .strip_prefix("vkey ")
            .ok_or_else(|| fail("no vkey"))?
            .to_owned();
        let state = root.join(format!("{name}-state"));
        let config = root.join(format!("{name}.conf"));
        std::fs::write(
            &config,
            format!(
                "name {name}\nkey {}\nstate {}\nlisten 127.0.0.1:0\noperator {operator}\nlog {} {}\n",
                key.display(),
                state.display(),
                b64url(&domain),
                b64url(&binding),
            ),
        )?;
        let mut w = Self {
            bin: bin.to_path_buf(),
            child: None,
            url: String::new(),
            vkey,
            config,
            state,
        };
        w.spawn()?;
        Ok(w)
    }

    fn spawn(&mut self) -> Result<(), WitnessError> {
        let mut child = Command::new(&self.bin)
            .arg("serve")
            .arg(&self.config)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdout = child.stdout.take().ok_or_else(|| fail("no stdout"))?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx.recv_timeout(START_TIMEOUT).map_err(fail)?;
        let addr = line
            .trim()
            .strip_prefix("listening ")
            .ok_or_else(|| fail(format!("unexpected start line: {line}")))?;
        self.url = format!("http://{addr}");
        self.child = Some(child);
        Ok(())
    }

    /// `SIGKILL`s the process and waits for it.
    ///
    /// # Errors
    /// [`WitnessError::Io`].
    pub fn kill(&mut self) -> Result<(), WitnessError> {
        if let Some(mut c) = self.child.take() {
            c.kill()?;
            c.wait()?;
        }
        Ok(())
    }

    /// Starts it again from the same configuration and state, on a new port.
    ///
    /// # Errors
    /// [`WitnessError`].
    pub fn restart(&mut self) -> Result<(), WitnessError> {
        self.kill()?;
        self.spawn()
    }

    /// Runs `access-witness fence` on its stopped state: it cosigns nothing above `size` under
    /// the binding it last cosigned (U11).
    ///
    /// # Errors
    /// [`WitnessError`].
    pub fn fence(&mut self, domain: [u8; 32], size: u64) -> Result<(), WitnessError> {
        self.kill()?;
        let out = Command::new(&self.bin)
            .arg("fence")
            .arg(&self.config)
            .arg(b64url(&domain))
            .arg(size.to_string())
            .output()?;
        if !out.status.success() {
            return Err(fail(String::from_utf8_lossy(&out.stderr)));
        }
        self.spawn()
    }

    fn file(&self, domain: [u8; 32], ext: &str) -> PathBuf {
        self.state.join(format!("{}.{ext}", b64url(&domain)))
    }

    /// The sizes its own state file says it cosigned, in order.
    ///
    /// # Errors
    /// [`WitnessError`] for a line that is not a state entry.
    pub fn cosigned(&self, domain: [u8; 32]) -> Result<Vec<u64>, WitnessError> {
        let text = match std::fs::read_to_string(self.file(domain, "chain")) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let bytes: Option<Vec<u8>> = (0..line.len())
                .step_by(2)
                .map(|i| {
                    line.get(i..i.checked_add(2)?)
                        .and_then(|p| u8::from_str_radix(p, 16).ok())
                })
                .collect();
            let entry = bytes
                .and_then(|b| StateEntry::from_bytes(&b).ok())
                .ok_or_else(|| fail("not a state entry"))?;
            if entry.note.is_some() {
                out.push(entry.size);
            }
        }
        Ok(out)
    }

    /// How many checkpoints it refused as contradicting its base.
    ///
    /// # Errors
    /// [`WitnessError::Io`].
    pub fn refused(&self, domain: [u8; 32]) -> Result<usize, WitnessError> {
        match std::fs::read_to_string(self.file(domain, "refused")) {
            Ok(t) => Ok(t.lines().count()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(e.into()),
        }
    }
}

impl Drop for Witness {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}
