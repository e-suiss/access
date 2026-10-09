//! Runtime lockdown for Access processes (SA-22, §14.5, OP-2).

#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]

use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(target_os = "linux"))]
mod unsupported;

#[cfg(target_os = "linux")]
use linux as imp;
#[cfg(not(target_os = "linux"))]
use unsupported as imp;

/// Which process the lockdown is for (OP-2 process table). Each profile has its own seccomp
/// allowlists; the signer and the parser worker are narrower than the server (§14.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// Network-facing process (authority core, identity core, gateways). Unlisted syscalls fail
    /// with `EPERM` instead of killing the process, because network processes must not abort
    /// (R-3, OP-4).
    Server,
    /// Authority or identity signer (CMP-22a/b). Only `AF_UNIX` sockets (UDS + `SCM_CREDENTIALS`),
    /// no network syscalls; unlisted syscalls kill the process (isolated process, R-3).
    Signer,
    /// Disposable parser worker (XML, ASN.1). No sockets at all; talks over inherited
    /// descriptors only; unlisted syscalls kill the process (isolated process, R-3).
    ParserWorker,
}

impl Profile {
    /// Stable lowercase name, for logs and `/healthz`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Signer => "signer",
            Self::ParserWorker => "parser-worker",
        }
    }
}

/// Landlock ABI version the process requires. The kernel must support at least this version or
/// [`Lockdown::apply`] fails ([`Error::Landlock`]); there is no best-effort fallback (SA-22
/// `HardRequirement`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LandlockAbi {
    /// Linux 5.13: basic filesystem access rights.
    V1 = 1,
    /// Linux 5.19: adds `REFER` (cross-directory rename/link).
    V2 = 2,
    /// Linux 6.2: adds `TRUNCATE`.
    V3 = 3,
    /// Linux 6.7: adds TCP bind/connect rights (not used by this crate yet).
    V4 = 4,
    /// Linux 6.10: adds `IOCTL_DEV`.
    V5 = 5,
    /// Linux 6.12: adds abstract-UDS and signal scoping (not used by this crate yet).
    V6 = 6,
}

impl LandlockAbi {
    /// The minimum every Access process requires (OP-92): V4 adds TCP bind/connect control,
    /// a second wall behind seccomp for the signer's and parser workers' network ban.
    pub const REQUIRED: Self = Self::V4;

    /// The numeric ABI version.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Unprivileged identity a root-started process switches to (SA-22 step 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RunAs {
    uid: u32,
    gid: u32,
}

impl RunAs {
    /// Creates the identity. Root (`0`) and the "no change" sentinel (`u32::MAX`) are rejected:
    /// the lockdown never leaves a process running as root.
    ///
    /// # Errors
    /// [`Error::InvalidRunAs`] for uid or gid `0` or `u32::MAX`.
    pub const fn new(uid: u32, gid: u32) -> Result<Self, Error> {
        if uid == 0 || gid == 0 || uid == u32::MAX || gid == u32::MAX {
            return Err(Error::InvalidRunAs);
        }
        Ok(Self { uid, gid })
    }

    /// Target user id.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Target group id.
    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }
}

/// Builder for the SA-22 lockdown. See the crate docs for the step order.
#[derive(Debug, Clone)]
#[must_use = "a Lockdown does nothing until `apply` is called"]
pub struct Lockdown {
    profile: Profile,
    landlock_abi: LandlockAbi,
    read_only: Vec<PathBuf>,
    read_write: Vec<PathBuf>,
    tcp_connect: Vec<u16>,
    tcp_bind: Vec<u16>,
    run_as: Option<RunAs>,
}

impl Lockdown {
    /// Starts a lockdown for `profile`, requiring at least `landlock_abi` from the kernel.
    /// No path is reachable until it is declared.
    pub const fn new(profile: Profile, landlock_abi: LandlockAbi) -> Self {
        Self {
            profile,
            landlock_abi,
            read_only: Vec::new(),
            read_write: Vec::new(),
            tcp_connect: Vec::new(),
            tcp_bind: Vec::new(),
            run_as: None,
        }
    }

    /// Declares a path (file or directory tree) the process may read but not modify or execute.
    pub fn allow_read(mut self, path: impl AsRef<Path>) -> Self {
        self.read_only.push(path.as_ref().to_path_buf());
        self
    }

    /// Declares a path (file or directory tree) the process may read, create and write under.
    /// Executing files and creating device nodes, FIFOs, sockets or symlinks stay denied.
    pub fn allow_read_write(mut self, path: impl AsRef<Path>) -> Self {
        self.read_write.push(path.as_ref().to_path_buf());
        self
    }

    /// Declares a TCP port the process may connect to. With Landlock ABI V4 or newer every
    /// other TCP `connect` is denied (OP-92); below V4 Landlock cannot restrict TCP.
    pub fn allow_tcp_connect(mut self, port: u16) -> Self {
        self.tcp_connect.push(port);
        self
    }

    /// Declares a TCP port the process may bind after the lockdown. Sockets bound before the
    /// lockdown keep working; with ABI V4 or newer every other TCP `bind` is denied (OP-92).
    pub fn allow_tcp_bind(mut self, port: u16) -> Self {
        self.tcp_bind.push(port);
        self
    }

    /// Identity to switch to when the process starts as root. A process started as root without
    /// one is refused ([`Error::RootWithoutRunAs`]); a process already running unprivileged keeps
    /// its identity, which must then equal this one if set ([`Error::IdentityMismatch`]).
    pub const fn run_as(mut self, run_as: RunAs) -> Self {
        self.run_as = Some(run_as);
        self
    }

    /// The profile this lockdown applies.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    /// Applies SA-22 steps 1 and 3–7 to the calling process.
    ///
    /// Must be called on the main thread while the process is still single-threaded; otherwise
    /// it fails with [`Error::NotSingleThreaded`] before changing anything.
    ///
    /// # Errors
    /// Any failed step aborts the lockdown with the matching [`Error`]. The process is then in a
    /// partially restricted state and must exit; it must never continue unsandboxed.
    pub fn apply(self) -> Result<Locked, Error> {
        imp::apply(&self)
    }
}

/// What the lockdown established, for logs and `/healthz` (SA-22: the Landlock ABI is reported).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockdownReport {
    /// Profile that was applied.
    pub profile: Profile,
    /// Seccomp phase now in force: `1` after [`Lockdown::apply`], `2` after [`Locked::narrow`].
    pub seccomp_phase: u8,
    /// Landlock ABI the process required.
    pub landlock_required_abi: LandlockAbi,
    /// Landlock ABI the running kernel reports (may be higher than the newest one this crate
    /// knows).
    pub landlock_kernel_abi: u32,
    /// Real, effective and saved uid after the lockdown.
    pub uid: u32,
    /// Real, effective and saved gid after the lockdown.
    pub gid: u32,
}

/// A locked-down process waiting for seccomp phase 2.
#[derive(Debug)]
#[must_use = "call `narrow` once startup is done to install seccomp phase 2"]
pub struct Locked {
    report: LockdownReport,
    phase2: imp::Phase2,
}

impl Locked {
    /// What the lockdown established.
    #[must_use]
    pub const fn report(&self) -> &LockdownReport {
        &self.report
    }

    /// Installs seccomp phase 2 (the narrowed allowlist) on every thread (TSYNC). Call it once
    /// startup is complete; it may run on any thread, including inside the async runtime.
    ///
    /// # Errors
    /// [`Error::Seccomp`] if the filter cannot be installed; the process must then exit.
    pub fn narrow(self) -> Result<LockdownReport, Error> {
        let Self { mut report, phase2 } = self;
        imp::narrow(&phase2)?;
        report.seccomp_phase = 2;
        Ok(report)
    }
}

/// The lockdown step that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    /// Reading process state (`/proc`) before any change.
    Preflight,
    /// `PR_SET_DUMPABLE=0`.
    Dumpable,
    /// `PR_SET_NO_NEW_PRIVS=1`.
    NoNewPrivs,
    /// Bounding, ambient or process capability sets.
    Capabilities,
    /// `setgroups` / `setresgid` / `setresuid`.
    Identity,
}

/// Why a lockdown or a secret-memory allocation failed. Every error is fatal for the process
/// (fail closed).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The target OS has no implementation of the SA-22 lockdown.
    #[error("runtime lockdown is not supported on this operating system")]
    Unsupported,
    /// [`Lockdown::apply`] was called while other threads exist.
    #[error("lockdown must run before any other thread starts ({threads} threads found)")]
    NotSingleThreaded {
        /// Number of threads observed.
        threads: usize,
    },
    /// The process runs as root and no [`RunAs`] identity was configured.
    #[error("process runs as root and no unprivileged identity was configured")]
    RootWithoutRunAs,
    /// The process already runs unprivileged, under a different identity than configured.
    #[error("process runs as uid {uid} gid {gid}, which differs from the configured identity")]
    IdentityMismatch {
        /// Current uid.
        uid: u32,
        /// Current gid.
        gid: u32,
    },
    /// [`RunAs::new`] got root or the `-1` sentinel.
    #[error("run-as identity must be a non-root uid and gid")]
    InvalidRunAs,
    /// A capability is still present after it was dropped (or could not be dropped because the
    /// process lacks `CAP_SETPCAP`).
    #[error("capability {capability} could not be removed from the bounding set")]
    CapabilityNotDropped {
        /// Capability number.
        capability: u32,
    },
    /// A prctl / capability / identity system call failed.
    #[error("lockdown step {step:?} failed")]
    Os {
        /// Step that failed.
        step: Step,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// Landlock could not be enforced (kernel too old, Landlock disabled, or a declared path is
    /// missing).
    #[error("landlock could not be enforced")]
    Landlock(#[source] Box<dyn core::error::Error + Send + Sync>),
    /// A seccomp filter could not be built or installed.
    #[error("seccomp filter could not be installed")]
    Seccomp(#[source] Box<dyn core::error::Error + Send + Sync>),
    /// `memfd_secret` is not available (kernel < 5.14, or secretmem disabled).
    #[error("memfd_secret is not available on this kernel")]
    SecretMemoryUnavailable(#[source] std::io::Error),
    /// Allocating or mapping secret memory failed (for example `RLIMIT_MEMLOCK`).
    #[error("secret memory could not be allocated")]
    SecretMemory(#[source] std::io::Error),
}

/// Memory backed by `memfd_secret(2)`: the pages are removed from the kernel's direct map, so
/// neither other processes nor the kernel itself (short of a kernel compromise) can read them
/// (§14.5 signer: `memfd_secret`). Needs Linux ≥ 5.14 with secretmem enabled; the pages count
/// against `RLIMIT_MEMLOCK`.
///
/// The contents are zeroed before the mapping is released. `Debug` never shows the contents.
pub struct SecretMemory {
    inner: imp::SecretMemory,
}

impl SecretMemory {
    /// Allocates `len` bytes of zeroed secret memory.
    ///
    /// # Errors
    /// [`Error::SecretMemoryUnavailable`] when the kernel lacks `memfd_secret` (callers must not
    /// fall back to ordinary memory), [`Error::SecretMemory`] when sizing or mapping fails,
    /// [`Error::Unsupported`] off Linux.
    pub fn new(len: core::num::NonZeroUsize) -> Result<Self, Error> {
        Ok(Self {
            inner: imp::SecretMemory::new(len)?,
        })
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.as_slice().len()
    }

    /// Always `false`: secret memory is at least one byte long.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.as_slice().is_empty()
    }

    /// Read access to the secret bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// Write access to the secret bytes.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.inner.as_mut_slice()
    }
}

impl core::fmt::Debug for SecretMemory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretMemory")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}
