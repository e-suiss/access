use std::path::{Path, PathBuf};
use std::time::Duration;

use cedar_policy_symcc::solver::LocalSolver;
use sha2::{Digest, Sha256};
use tokio::process::Command;

use crate::{AnalysisError, pin};

/// Time limits for one analysis. A limit hit is [`AnalysisError::Timeout`], never a verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// One solver query; also passed to cvc5 as `--tlimit-per`.
    pub query: Duration,
    /// The whole analysis, including symbolic compilation.
    pub total: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            query: Duration::from_secs(60),
            total: Duration::from_secs(600),
        }
    }
}

/// Puts the solver child into its sandbox between fork and exec (OP-115 m.6). The binary that
/// runs the analysis passes the `suiss-sandbox` solver profile for the solver at the given path;
/// an error stops the solver from starting ([`AnalysisError::Sandbox`]).
pub type Confine = fn(&mut std::process::Command, &Path) -> std::io::Result<()>;

/// A cvc5 executable whose sha256 must match `supply-chain/cvc5.toml` (OP-105).
#[derive(Clone, Debug)]
pub struct Cvc5 {
    path: PathBuf,
    sha256: [u8; 32],
    timeouts: Timeouts,
    confine: Confine,
}

impl Cvc5 {
    /// Binds the configured `path` to the pin for this platform. The file is hashed again
    /// before every run, and every run is confined by `confine`.
    ///
    /// # Errors
    /// [`AnalysisError::UnsupportedPlatform`] or [`AnalysisError::Pin`].
    pub fn pinned(
        path: impl Into<PathBuf>,
        timeouts: Timeouts,
        confine: Confine,
    ) -> Result<Self, AnalysisError> {
        Ok(Self {
            path: path.into(),
            sha256: pin::binary_sha256(&pin::platform())?,
            timeouts,
            confine,
        })
    }

    /// The pinned cvc5 version.
    ///
    /// # Errors
    /// [`AnalysisError::Pin`].
    pub fn pinned_version() -> Result<String, AnalysisError> {
        pin::version()
    }

    #[cfg(test)]
    pub(crate) fn with_hash(path: PathBuf, sha256: [u8; 32], timeouts: Timeouts) -> Self {
        Self {
            path,
            sha256,
            timeouts,
            confine: |_, _| Ok(()),
        }
    }

    /// The configured time limits.
    #[must_use]
    pub fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    /// The configured executable path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn verify(&self) -> Result<(), AnalysisError> {
        let bytes = std::fs::read(&self.path).map_err(|_| AnalysisError::SolverUnavailable)?;
        if Sha256::digest(&bytes).as_slice() == self.sha256.as_slice() {
            Ok(())
        } else {
            Err(AnalysisError::PinMismatch)
        }
    }

    // OP-105
    pub(crate) fn spawn(&self) -> Result<LocalSolver, AnalysisError> {
        self.verify()?;
        let ms = u64::try_from(self.timeouts.query.as_millis())
            .map_err(|_| AnalysisError::Timeout)?
            .max(1);
        let mut cmd = Command::new(&self.path);
        cmd.env_clear()
            .current_dir("/")
            .kill_on_drop(true)
            .args(["--lang", "smt"])
            .arg(format!("--tlimit-per={ms}"));
        // OP-115 m.6
        (self.confine)(cmd.as_std_mut(), &self.path).map_err(|_| AnalysisError::Sandbox)?;
        LocalSolver::from_command(&mut cmd).map_err(|_| AnalysisError::SolverUnavailable)
    }
}
