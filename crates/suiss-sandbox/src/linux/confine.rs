//! OP-115 m.6: a lockdown that a child enters between fork and exec.

use std::io;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

use landlock::{RulesetCreated, RulesetStatus};
use rustix::process::{Gid, Resource, Rlimit, Uid};
use rustix::thread::{CapabilitySet, CapabilitySets};
use seccompiler::BpfProgram;

use super::{caps, fs, seccomp};
use crate::{Error, Lockdown, RunAs};

/// Everything the child needs, built in the parent so the child only makes system calls.
struct Plan {
    ruleset: Option<RulesetCreated>,
    filters: Vec<BpfProgram>,
    switch: Option<(RunAs, u32)>,
}

pub(crate) fn confine(lockdown: &Lockdown, command: &mut Command) -> Result<(), Error> {
    let arch = seccomp::target_arch()?;
    let filters = seccomp::solver_filters(arch)?;
    if filters.iter().any(Vec::is_empty) {
        return Err(Error::Seccomp("empty filter".into()));
    }
    let switch = identity(lockdown.run_as)?;
    let mut plan = Plan {
        ruleset: Some(fs::ruleset(lockdown)?),
        filters,
        switch,
    };
    #[allow(unsafe_code)]
    // SAFETY: the closure runs in the forked child before exec, where only async-signal-safe
    // work is allowed. It moves the prepared ruleset out of its own copy of `plan` and issues
    // prctl, prlimit, capget/capset, setgroups/setresgid/setresuid, landlock_restrict_self and
    // seccomp through rustix, landlock and seccompiler; none of them allocates, locks or touches
    // state shared with other threads of the parent. Errors are raw errno values.
    unsafe {
        command.pre_exec(move || plan.enter());
    }
    Ok(())
}

/// `None` keeps the caller's unprivileged identity; `Some` switches a root caller in the child.
fn identity(run_as: Option<RunAs>) -> Result<Option<(RunAs, u32)>, Error> {
    let uids = (
        rustix::process::getuid().as_raw(),
        rustix::process::geteuid().as_raw(),
    );
    let gids = (
        rustix::process::getgid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    if uids.0 != 0 && uids.1 != 0 {
        let consistent = uids.0 == uids.1 && gids.0 == gids.1;
        let matches = run_as.is_none_or(|r| r.uid() == uids.0 && r.gid() == gids.0);
        return if consistent && matches {
            Ok(None)
        } else {
            Err(Error::IdentityMismatch {
                uid: uids.1,
                gid: gids.1,
            })
        };
    }
    let target = run_as.ok_or(Error::RootWithoutRunAs)?;
    Ok(Some((target, caps::last_cap()?.min(63))))
}

fn denied() -> io::Error {
    io::Error::from_raw_os_error(libc::EPERM)
}

impl Plan {
    fn enter(&mut self) -> io::Result<()> {
        // SA-22
        rustix::process::setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )?;
        rustix::thread::set_no_new_privs(true)?;
        rustix::thread::clear_ambient_capability_set()?;
        if let Some((target, last)) = self.switch {
            for capability in 0..=last {
                let set = CapabilitySet::from_bits_retain(1_u64 << capability);
                rustix::thread::remove_capability_from_bounding_set(set)?;
            }
            let uid = Uid::from_raw_unchecked(target.uid());
            let gid = Gid::from_raw_unchecked(target.gid());
            rustix::thread::set_thread_groups(&[])?;
            rustix::thread::set_thread_res_gid(gid, gid, gid)?;
            rustix::thread::set_thread_res_uid(uid, uid, uid)?;
        }
        let empty = CapabilitySets {
            effective: CapabilitySet::empty(),
            permitted: CapabilitySet::empty(),
            inheritable: CapabilitySet::empty(),
        };
        rustix::thread::set_capabilities(None, empty)?;

        // SA-22, OP-92
        let ruleset = self.ruleset.take().ok_or_else(denied)?;
        let status = ruleset.restrict_self().map_err(|_| denied())?;
        if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
            return Err(denied());
        }

        // SA-22
        for filter in &self.filters {
            seccompiler::apply_filter(filter).map_err(|_| io::Error::last_os_error())?;
        }
        Ok(())
    }
}
