//! Bootstrap credentials from files (CR-35, OP-52, OP-129 m.3): the database password and the
//! PKCS#11 PIN come from a file the workload identity mounts (tmpfs, 0400), never from an
//! environment variable or a Kubernetes Secret; key material never comes from a file at all.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use zeroize::Zeroizing;

use crate::secret::Secret;

/// Largest credential file read.
const MAX_LEN: u64 = 4096;

/// Why a credential file was refused.
#[derive(Debug, thiserror::Error)]
pub enum SecretFileError {
    /// The file could not be read.
    #[error("{}: {kind}", path.display())]
    Io {
        /// File.
        path: PathBuf,
        /// What failed.
        kind: std::io::ErrorKind,
    },
    /// Group or others may read it, or it is not a regular file.
    #[error("{}: must be a regular file readable by its owner only", .0.display())]
    Permissions(PathBuf),
    /// Empty, too large or not UTF-8.
    #[error("{}: must hold one UTF-8 line of at most 4 KiB", .0.display())]
    Content(PathBuf),
    /// A secret-looking `ACCESS_*` environment variable is set (OP-129 m.3).
    #[error(
        "environment variable {0} would carry a secret; point a *_FILE setting at a mounted file instead"
    )]
    Environment(String),
}

/// A credential read from a file, re-read when the file changes (rotation).
pub struct SecretFile {
    path: PathBuf,
    stamp: Option<(SystemTime, u64)>,
    value: Secret<String>,
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> SecretFileError + '_ {
    move |e| SecretFileError::Io {
        path: path.to_owned(),
        kind: e.kind(),
    }
}

fn stamp(path: &Path) -> Result<(SystemTime, u64), SecretFileError> {
    let meta = fs::metadata(path).map_err(io(path))?;
    if !meta.is_file() {
        return Err(SecretFileError::Permissions(path.to_owned()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(SecretFileError::Permissions(path.to_owned()));
        }
    }
    Ok((meta.modified().map_err(io(path))?, meta.len()))
}

fn read(path: &Path) -> Result<Secret<String>, SecretFileError> {
    let mut buf = Zeroizing::new(Vec::new());
    fs::File::open(path)
        .map_err(io(path))?
        .take(MAX_LEN.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(io(path))?;
    if u64::try_from(buf.len()).map_or(true, |n| n > MAX_LEN) {
        return Err(SecretFileError::Content(path.to_owned()));
    }
    let text = std::str::from_utf8(&buf).map_err(|_| SecretFileError::Content(path.to_owned()))?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() || line.contains('\n') {
        return Err(SecretFileError::Content(path.to_owned()));
    }
    Ok(Secret::new(line.to_owned()))
}

impl SecretFile {
    /// Reads `path`, which only its owner may read.
    ///
    /// # Errors
    /// [`SecretFileError`].
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, SecretFileError> {
        let path = path.into();
        let stamp = Some(stamp(&path)?);
        let value = read(&path)?;
        Ok(Self { path, stamp, value })
    }

    /// The credential.
    #[must_use]
    pub const fn value(&self) -> &Secret<String> {
        &self.value
    }

    /// Re-reads the file when its modification time or size changed; returns whether it did.
    /// Open connections keep the old value, new ones use the new (OP-52).
    ///
    /// # Errors
    /// [`SecretFileError`]; the previous value stays in force.
    pub fn reload_if_changed(&mut self) -> Result<bool, SecretFileError> {
        let now = stamp(&self.path)?;
        if self.stamp == Some(now) {
            return Ok(false);
        }
        self.value = read(&self.path)?;
        self.stamp = Some(now);
        Ok(true)
    }
}

/// Refuses to start when an `ACCESS_*` variable looks like it carries a secret (OP-129 m.3);
/// `*_FILE` variables name a file and are allowed.
///
/// # Errors
/// [`SecretFileError::Environment`] with the variable's name, never its value.
pub fn refuse_secret_environment(
    vars: impl IntoIterator<Item = String>,
) -> Result<(), SecretFileError> {
    for name in vars {
        let upper = name.to_ascii_uppercase();
        let secretish = ["SECRET", "PASSWORD", "PIN", "TOKEN", "PRIVATE"]
            .iter()
            .any(|w| upper.contains(w));
        if upper.starts_with("ACCESS_") && secretish && !upper.ends_with("_FILE") {
            return Err(SecretFileError::Environment(name));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
