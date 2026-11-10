//! The breach-range mirror refresh (IDP-3, OP-146 m.4 (e), OP-156 m.3 (h)): every 24 hours the
//! range files are downloaded from the operator's source through the padded range API into a new
//! version directory `versions/<id>`; only a complete download is made `current`, by one rename
//! of a link, so a refresh that stops halfway leaves the old version served. The version it
//! replaces stays on disk and is archived, never removed (OP-73).

use std::path::{Path, PathBuf};
use std::time::Duration;

use access_identity_account::adapters::hibp::CURRENT;
use access_identity_account::ports::BreachRanges;
use suiss_crypto::digest::sha256;

use super::range_api::RangeApi;
use crate::ports::RangeFetch;

/// How often the mirror is refreshed.
pub const REFRESH_EVERY: Duration = Duration::from_hours(24);

/// The directory of version directories.
pub const VERSIONS: &str = "versions";

/// Every five-character prefix, `00000` to `FFFFF`.
pub fn all_prefixes() -> impl Iterator<Item = String> {
    (0..0x10_0000_u32).map(|n| format!("{n:05X}"))
}

/// Why a refresh stopped; the current version stays.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RefreshError {
    /// The source did not answer one range.
    #[error("range {0} unavailable")]
    Range(String),
    /// The file system refused.
    #[error("mirror directory: {0}")]
    Io(String),
}

impl RefreshError {
    /// The telemetry reason.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Range(_) => "range_unavailable",
            Self::Io(_) => "io",
        }
    }
}

/// A completed download.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Downloaded {
    /// Range files written.
    pub ranges: u32,
    /// SHA-256 over each prefix and its range, in order.
    pub digest: [u8; 32],
}

/// The directory of version `id` under the mirror `root`.
#[must_use]
pub fn version_dir(root: &Path, id: &[u8; 16]) -> PathBuf {
    let name = id.iter().fold(String::new(), |mut s, b| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
        s
    });
    root.join(VERSIONS).join(name)
}

fn io(e: &std::io::Error) -> RefreshError {
    RefreshError::Io(e.kind().to_string())
}

/// Downloads every range of `prefixes` from `source` into version `id`'s directory. Nothing is
/// made current here.
///
/// # Errors
/// [`RefreshError`] at the first range that does not come.
pub async fn download<F: RangeFetch>(
    source: &RangeApi<F>,
    root: &Path,
    id: &[u8; 16],
    prefixes: impl Iterator<Item = String>,
) -> Result<Downloaded, RefreshError> {
    let dir = version_dir(root, id);
    tokio::fs::create_dir_all(&dir).await.map_err(|e| io(&e))?;
    let mut all = Vec::new();
    let mut ranges = 0_u32;
    for prefix in prefixes {
        let body = source
            .range(&prefix)
            .await
            .map_err(|_| RefreshError::Range(prefix.clone()))?;
        let mut d = sha256(prefix.as_bytes()).to_vec();
        d.extend_from_slice(&sha256(body.as_bytes()));
        all.extend_from_slice(&sha256(&d));
        tokio::fs::write(dir.join(format!("{prefix}.txt")), body.as_bytes())
            .await
            .map_err(|e| io(&e))?;
        ranges = ranges.saturating_add(1);
    }
    Ok(Downloaded {
        ranges,
        digest: sha256(&all),
    })
}

/// Makes version `id` the one the mirror reads: a new link to it replaces `current` in one
/// rename; the version it replaces stays where it is.
///
/// # Errors
/// [`RefreshError::Io`].
pub async fn promote(root: &Path, id: &[u8; 16]) -> Result<(), RefreshError> {
    let target = version_dir(root, id);
    let relative = target
        .strip_prefix(root)
        .map_err(|_| RefreshError::Io(String::from("version outside the mirror")))?
        .to_path_buf();
    let staged = root.join(format!("{CURRENT}.next"));
    if tokio::fs::symlink_metadata(&staged).await.is_ok() {
        tokio::fs::remove_file(&staged).await.map_err(|e| io(&e))?;
    }
    tokio::fs::symlink(&relative, &staged)
        .await
        .map_err(|e| io(&e))?;
    tokio::fs::rename(&staged, root.join(CURRENT))
        .await
        .map_err(|e| io(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-156 m.3 (h)
    #[test]
    fn every_prefix_is_listed_once_in_order() {
        let mut p = all_prefixes();
        assert_eq!(p.next().as_deref(), Some("00000"));
        assert_eq!(all_prefixes().count(), 1_048_576);
        assert_eq!(all_prefixes().last().as_deref(), Some("FFFFF"));
        assert_eq!(
            version_dir(Path::new("/m"), &[0xab; 16]),
            Path::new("/m/versions/abababababababababababababababab")
        );
    }
}
