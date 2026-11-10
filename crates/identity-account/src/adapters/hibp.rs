//! Breach range adapters (IDP-3, OP-146 m.4 (e), OP-156 m.3 (h)). The default is a local mirror
//! of the range files, refreshed by a job, so self-hosted and air-gapped installs check offline.
//! A refreshed mirror reads its `current` version directory, which a refresh replaces in one
//! rename; a mirror without one reads the range files at its root, as the operator laid them out.
//! A missing or unreadable range is unavailable, never "not breached" (G50). The live range API
//! is `access_identity_risk::adapters::range_api::RangeApi`, which sends `Add-Padding`.

use std::path::PathBuf;

use crate::ports::{BreachRanges, RangeUnavailable};

/// The link a refreshed mirror reads through (OP-156 m.3 (h)).
pub const CURRENT: &str = "current";

/// Largest range file read; real ranges are tens of KiB.
pub const MAX_RANGE_BYTES: u64 = 1 << 20;

/// Range files `<dir>/<PREFIX>.txt`, one per five-character prefix.
pub struct MirrorRanges {
    dir: PathBuf,
}

impl MirrorRanges {
    /// Ranges under `dir`.
    #[must_use]
    pub const fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

fn valid_prefix(prefix: &str) -> bool {
    prefix.len() == 5
        && prefix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

impl BreachRanges for MirrorRanges {
    async fn range(&self, prefix: &str) -> Result<String, RangeUnavailable> {
        if !valid_prefix(prefix) {
            return Err(RangeUnavailable);
        }
        let current = self.dir.join(CURRENT);
        let base = if tokio::fs::symlink_metadata(&current).await.is_ok() {
            current
        } else {
            self.dir.clone()
        };
        let path = base.join(format!("{prefix}.txt"));
        let meta = tokio::fs::metadata(&path)
            .await
            .map_err(|_| RangeUnavailable)?;
        if !meta.is_file() || meta.len() > MAX_RANGE_BYTES {
            return Err(RangeUnavailable);
        }
        tokio::fs::read_to_string(&path)
            .await
            .map_err(|_| RangeUnavailable)
    }
}
