//! `SoftHSM` test tokens for this crate's and other crates' tests (`testing` feature, OP-69).

/// Initialises a free `SoftHSM` token for a test (`softhsm2-util --init-token --free`) under a
/// lock shared by every test process of the store: the tool is not safe to run concurrently
/// against one token directory (OP-69). `conf` is the `SOFTHSM2_CONF` to use; `None` keeps the
/// environment's.
///
/// # Errors
/// The lock file cannot be taken or the tool cannot be started.
pub fn init_softhsm_token(
    conf: Option<&std::path::Path>,
    label: &str,
    pin: &str,
    so_pin: &str,
) -> std::io::Result<std::process::Output> {
    let conf_path = match conf {
        Some(c) => c.to_path_buf(),
        None => std::path::PathBuf::from(
            std::env::var_os("SOFTHSM2_CONF")
                .ok_or_else(|| std::io::Error::other("SOFTHSM2_CONF is not set"))?,
        ),
    };
    let lock = conf_path.with_extension("init-lock");
    let _guard = InitLock::take(&lock)?;
    let mut command = std::process::Command::new("softhsm2-util");
    if let Some(c) = conf {
        command.env("SOFTHSM2_CONF", c);
    }
    command
        .args(["--init-token", "--free", "--label", label])
        .args(["--pin", pin, "--so-pin", so_pin])
        .output()
}

/// A lock file taken with `create_new`; a lock older than two minutes belongs to a dead
/// process and is replaced.
struct InitLock(std::path::PathBuf);

impl InitLock {
    fn take(path: &std::path::Path) -> std::io::Result<Self> {
        let stale = std::time::Duration::from_secs(120);
        let started = std::time::Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(_) => return Ok(Self(path.to_path_buf())),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let old = std::fs::metadata(path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|m| m.elapsed().ok())
                        .is_some_and(|age| age > stale);
                    if old {
                        let _ = std::fs::remove_file(path);
                        continue;
                    }
                    if started.elapsed() > stale.saturating_mul(2) {
                        return Err(std::io::Error::other("SoftHSM init lock held too long"));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for InitLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
