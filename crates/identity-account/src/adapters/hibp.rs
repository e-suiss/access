//! Breach range adapters (IDP-3, OP-146 m.4 (e)). The default is a local mirror of the range
//! files, refreshed by a job, so self-hosted and air-gapped installs check offline. A missing
//! or unreadable range is unavailable, never "not breached" (G50).

use std::path::PathBuf;

use crate::ports::{BreachRanges, RangeUnavailable};

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
        let path = self.dir.join(format!("{prefix}.txt"));
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

/// The live range API (`Add-Padding`), optional (OP-146 m.4 (e)). Not wired yet: every call is
/// unavailable, so a realm configured for it answers `503 + Retry-After` on password set.
pub struct LiveRanges;

impl BreachRanges for LiveRanges {
    fn range(
        &self,
        _prefix: &str,
    ) -> impl Future<Output = Result<String, RangeUnavailable>> + Send {
        std::future::ready(Err(RangeUnavailable))
    }
}
