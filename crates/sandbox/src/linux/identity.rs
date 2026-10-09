//! SA-22 step 5: setgroups / setgid / setuid.

use rustix::process::{Gid, Uid};

use super::os;
use crate::{Error, RunAs, Step};

/// Switches a root-started process to `run_as`; keeps an unprivileged process as it is.
/// Returns the resulting `(uid, gid)`.
pub(super) fn switch(run_as: Option<RunAs>) -> Result<(u32, u32), Error> {
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
            Ok((uids.0, gids.0))
        } else {
            Err(Error::IdentityMismatch {
                uid: uids.1,
                gid: gids.1,
            })
        };
    }

    let target = run_as.ok_or(Error::RootWithoutRunAs)?;
    let uid = Uid::from_raw_unchecked(target.uid());
    let gid = Gid::from_raw_unchecked(target.gid());

    rustix::thread::set_thread_groups(&[]).map_err(|e| os(Step::Identity, e))?;
    rustix::thread::set_thread_res_gid(gid, gid, gid).map_err(|e| os(Step::Identity, e))?;
    rustix::thread::set_thread_res_uid(uid, uid, uid).map_err(|e| os(Step::Identity, e))?;

    let after = (
        rustix::process::getuid().as_raw(),
        rustix::process::geteuid().as_raw(),
        rustix::process::getgid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    if after == (target.uid(), target.uid(), target.gid(), target.gid()) {
        Ok((target.uid(), target.gid()))
    } else {
        Err(Error::IdentityMismatch {
            uid: after.1,
            gid: after.3,
        })
    }
}
