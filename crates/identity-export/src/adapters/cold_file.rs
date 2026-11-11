//! The cold tier as a local directory (OP-69 local equivalent of an object-locked bucket,
//! OP-158 m.3 (ee)): an object is written once under its key and made read-only; it is never
//! overwritten or removed.

use std::path::{Path, PathBuf};

use access_identity_audit::AuditError;
use access_identity_audit::ports::ColdStore;

/// A directory holding the cold tier's objects.
#[derive(Clone, Debug)]
pub struct FileCold {
    /// The directory; created on first write.
    pub root: PathBuf,
}

fn invalid() -> AuditError {
    AuditError::Cold(String::from("object key"))
}

fn io(e: &std::io::Error) -> AuditError {
    AuditError::Cold(e.kind().to_string())
}

impl FileCold {
    fn path(&self, key: &str) -> Result<PathBuf, AuditError> {
        let ok = !key.is_empty()
            && key.len() <= 512
            && key.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
            });
        if !ok {
            return Err(invalid());
        }
        Ok(self.root.join(key))
    }
}

async fn same(path: &Path, bytes: &[u8]) -> Result<(), AuditError> {
    let held = tokio::fs::read(path).await.map_err(|e| io(&e))?;
    if held == bytes {
        Ok(())
    } else {
        Err(AuditError::Cold(String::from(
            "object exists with other content",
        )))
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl FileCold {
    /// Every key under `prefix` (a directory key), sorted; temporary files are not keys.
    ///
    /// # Errors
    /// [`AuditError::Cold`].
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, AuditError> {
        let mut out = Vec::new();
        let mut dirs = vec![prefix.trim_end_matches('/').to_owned()];
        while let Some(dir) = dirs.pop() {
            let path = self.path(&dir)?;
            let mut entries = match tokio::fs::read_dir(&path).await {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(io(&e)),
            };
            while let Some(entry) = entries.next_entry().await.map_err(|e| io(&e))? {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.starts_with('.') {
                    continue;
                }
                let key = format!("{dir}/{name}");
                if entry.file_type().await.map_err(|e| io(&e))?.is_dir() {
                    dirs.push(key);
                } else {
                    out.push(key);
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

impl ColdStore for FileCold {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), AuditError> {
        let path = self.path(key)?;
        if tokio::fs::try_exists(&path).await.map_err(|e| io(&e))? {
            return same(&path, bytes).await;
        }
        let dir = path.parent().ok_or_else(invalid)?;
        tokio::fs::create_dir_all(dir).await.map_err(|e| io(&e))?;
        let nonce = access_crypto::random::bytes::<8>().map_err(|_| invalid())?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(invalid)?;
        let tmp = dir.join(format!(".{name}.{}", hex(&nonce)));
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .await
            .map_err(|e| io(&e))?;
        tokio::io::AsyncWriteExt::write_all(&mut file, bytes)
            .await
            .map_err(|e| io(&e))?;
        file.sync_all().await.map_err(|e| io(&e))?;
        drop(file);
        let mut perms = tokio::fs::metadata(&tmp)
            .await
            .map_err(|e| io(&e))?
            .permissions();
        perms.set_readonly(true);
        tokio::fs::set_permissions(&tmp, perms)
            .await
            .map_err(|e| io(&e))?;
        let linked = tokio::fs::hard_link(&tmp, &path).await;
        let _ = tokio::fs::remove_file(&tmp).await;
        match linked {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => same(&path, bytes).await,
            Err(e) => Err(io(&e)),
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, AuditError> {
        let path = self.path(key)?;
        match tokio::fs::read(&path).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io(&e)),
        }
    }
}

#[cfg(test)]
mod tests;
