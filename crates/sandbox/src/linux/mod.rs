//! Linux implementation of the SA-22 lockdown.

mod caps;
mod fs;
mod identity;
mod seccomp;
mod secretmem;

pub(crate) use secretmem::SecretMemory;

use rustix::process::DumpableBehavior;

use crate::{Error, Lockdown, LockdownReport, Locked, Step};

/// Precompiled seccomp phase 2, installed by [`narrow`].
pub(crate) struct Phase2 {
    program: seccompiler::BpfProgram,
}

impl core::fmt::Debug for Phase2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Phase2")
            .field("instructions", &self.program.len())
            .finish()
    }
}

pub(crate) fn apply(lockdown: &Lockdown) -> Result<Locked, Error> {
    let arch = seccomp::target_arch()?;
    let pid = rustix::process::getpid().as_raw_pid();
    let phase1 = seccomp::startup_filters(lockdown.profile, arch, pid)?;
    let phase2 = seccomp::narrowed_filter(lockdown.profile, arch, pid)?;

    // SA-22
    ensure_single_threaded()?;

    // SA-22
    set_not_dumpable()?;

    // SA-22

    // SA-22
    rustix::thread::set_no_new_privs(true).map_err(|e| os(Step::NoNewPrivs, e))?;

    // SA-22
    caps::drop_bounding_and_ambient()?;

    // SA-22
    let (uid, gid) = identity::switch(lockdown.run_as)?;
    set_not_dumpable()?;
    caps::clear_process_sets()?;

    // SA-22
    let landlock_kernel_abi = fs::restrict(lockdown)?;

    // SA-22
    for program in &phase1 {
        seccompiler::apply_filter_all_threads(program).map_err(seccomp::error)?;
    }

    Ok(Locked {
        report: LockdownReport {
            profile: lockdown.profile,
            seccomp_phase: 1,
            landlock_required_abi: lockdown.landlock_abi,
            landlock_kernel_abi,
            uid,
            gid,
        },
        phase2: Phase2 { program: phase2 },
    })
}

pub(crate) fn narrow(phase2: &Phase2) -> Result<(), Error> {
    // SA-22
    seccompiler::apply_filter_all_threads(&phase2.program).map_err(seccomp::error)
}

fn set_not_dumpable() -> Result<(), Error> {
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|e| os(Step::Dumpable, e))
}

fn ensure_single_threaded() -> Result<(), Error> {
    let threads = std::fs::read_dir("/proc/self/task")
        .map_err(|e| Error::Os {
            step: Step::Preflight,
            source: e,
        })?
        .count();
    if threads == 1 {
        Ok(())
    } else {
        Err(Error::NotSingleThreaded { threads })
    }
}

fn os(step: Step, errno: rustix::io::Errno) -> Error {
    Error::Os {
        step,
        source: errno.into(),
    }
}
