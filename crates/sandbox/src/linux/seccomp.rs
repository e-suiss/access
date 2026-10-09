//! SA-22 step 7: the two-phase seccomp policy.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::{Error, Profile};

type Rules = BTreeMap<i64, Vec<SeccompRule>>;

/// The `io_uring` syscalls. Never allowed (SA-22).
pub(super) const IO_URING: [i64; 3] = [
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
];

/// x32 ABI syscall numbers carry this bit on `x86_64`. Allowlists never match them; the
/// `io_uring` filter denies the x32 variants explicitly as well.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: i64 = 0x4000_0000;

/// Namespace-creating `clone` flags. Threads never need them; new namespaces widen the kernel
/// attack surface.
fn clone_namespace_flags() -> u64 {
    u64::from(
        (libc::CLONE_NEWNS
            | libc::CLONE_NEWCGROUP
            | libc::CLONE_NEWUTS
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWUSER
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWNET)
            .unsigned_abs(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Startup,
    Narrowed,
}

pub(super) fn error(e: seccompiler::Error) -> Error {
    Error::Seccomp(Box::new(e))
}

fn backend(e: seccompiler::BackendError) -> Error {
    Error::Seccomp(Box::new(e))
}

pub(super) fn target_arch() -> Result<TargetArch, Error> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(TargetArch::x86_64),
        "aarch64" => Ok(TargetArch::aarch64),
        _ => Err(Error::Unsupported),
    }
}

/// Phase 1 filters, in installation order.
pub(super) fn startup_filters(
    profile: Profile,
    arch: TargetArch,
    pid: i32,
) -> Result<Vec<BpfProgram>, Error> {
    Ok(vec![
        deny_io_uring(arch)?,
        clone3_enosys(arch)?,
        compile(allowlist(profile, Phase::Startup, pid)?, profile, arch)?,
    ])
}

/// The phase 2 filter.
pub(super) fn narrowed_filter(
    profile: Profile,
    arch: TargetArch,
    pid: i32,
) -> Result<BpfProgram, Error> {
    compile(allowlist(profile, Phase::Narrowed, pid)?, profile, arch)
}

fn compile(rules: Rules, profile: Profile, arch: TargetArch) -> Result<BpfProgram, Error> {
    let filter = SeccompFilter::new(rules, mismatch_action(profile), SeccompAction::Allow, arch)
        .map_err(backend)?;
    BpfProgram::try_from(filter).map_err(backend)
}

pub(super) const fn mismatch_action(profile: Profile) -> SeccompAction {
    match profile {
        // R-3
        Profile::Server => SeccompAction::Errno(libc::EPERM.unsigned_abs()),
        // R-3
        Profile::Signer | Profile::ParserWorker => SeccompAction::KillProcess,
    }
}

fn deny_io_uring(arch: TargetArch) -> Result<BpfProgram, Error> {
    let mut rules = Rules::new();
    for nr in IO_URING {
        rules.insert(nr, Vec::new());
        #[cfg(target_arch = "x86_64")]
        rules.insert(nr | X32_SYSCALL_BIT, Vec::new());
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM.unsigned_abs()),
        arch,
    )
    .map_err(backend)?;
    BpfProgram::try_from(filter).map_err(backend)
}

fn clone3_enosys(arch: TargetArch) -> Result<BpfProgram, Error> {
    let mut rules = Rules::new();
    rules.insert(libc::SYS_clone3, Vec::new());
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS.unsigned_abs()),
        arch,
    )
    .map_err(backend)?;
    BpfProgram::try_from(filter).map_err(backend)
}

fn cond(
    arg: u8,
    len: SeccompCmpArgLen,
    op: SeccompCmpOp,
    value: u64,
) -> Result<SeccompCondition, Error> {
    SeccompCondition::new(arg, len, op, value).map_err(backend)
}

/// One rule per allowed value of argument `arg` (rules are OR-ed).
fn any_of(arg: u8, len: &SeccompCmpArgLen, values: &[u64]) -> Result<Vec<SeccompRule>, Error> {
    values
        .iter()
        .map(|v| {
            SeccompRule::new(vec![cond(arg, len.clone(), SeccompCmpOp::Eq, *v)?]).map_err(backend)
        })
        .collect()
}

fn allow(rules: &mut Rules, syscalls: &[i64]) {
    for nr in syscalls {
        rules.insert(*nr, Vec::new());
    }
}

/// Common to every profile and phase: memory, descriptors, polling, signals, time,
/// synchronisation, thread lifecycle, introspection.
const COMMON: &[i64] = &[
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_close,
    libc::SYS_lseek,
    libc::SYS_fstat,
    libc::SYS_fcntl,
    libc::SYS_dup,
    libc::SYS_dup3,
    libc::SYS_pipe2,
    libc::SYS_eventfd2,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    libc::SYS_ppoll,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_gettimeofday,
    libc::SYS_futex,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
    libc::SYS_clone3,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_restart_syscall,
    libc::SYS_getpid,
    libc::SYS_gettid,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_getrandom,
    libc::SYS_capget,
];

/// Builds the allowlist for `profile` in `phase`.
pub(super) fn allowlist(profile: Profile, phase: Phase, pid: i32) -> Result<Rules, Error> {
    let mut rules = Rules::new();
    common_rules(&mut rules, phase, pid)?;
    profile_rules(&mut rules, profile, phase)?;
    for nr in IO_URING {
        rules.remove(&nr);
    }
    Ok(rules)
}

/// Syscalls every profile needs in `phase`.
fn common_rules(rules: &mut Rules, phase: Phase, pid: i32) -> Result<(), Error> {
    let dword = SeccompCmpArgLen::Dword;
    allow(rules, COMMON);
    #[cfg(target_arch = "x86_64")]
    allow(rules, &[libc::SYS_poll, libc::SYS_epoll_wait]);

    let clone_thread = u64::from(libc::CLONE_THREAD.unsigned_abs());
    rules.insert(
        libc::SYS_clone,
        vec![
            SeccompRule::new(vec![
                cond(
                    0,
                    SeccompCmpArgLen::Qword,
                    SeccompCmpOp::MaskedEq(clone_thread),
                    clone_thread,
                )?,
                cond(
                    0,
                    SeccompCmpArgLen::Qword,
                    SeccompCmpOp::MaskedEq(clone_namespace_flags()),
                    0,
                )?,
            ])
            .map_err(backend)?,
        ],
    );

    rules.insert(
        libc::SYS_tgkill,
        vec![
            SeccompRule::new(vec![cond(
                0,
                dword.clone(),
                SeccompCmpOp::Eq,
                u64::from(pid.unsigned_abs()),
            )?])
            .map_err(backend)?,
        ],
    );

    rules.insert(
        libc::SYS_prlimit64,
        vec![
            SeccompRule::new(vec![cond(2, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)?])
                .map_err(backend)?,
        ],
    );

    rules.insert(
        libc::SYS_ioctl,
        any_of(1, &dword, &[libc::FIONBIO, libc::FIOCLEX, libc::TCGETS])?,
    );

    let mut prctl_ops = vec![
        libc::PR_SET_NAME,
        libc::PR_GET_NAME,
        libc::PR_SET_VMA,
        libc::PR_GET_DUMPABLE,
        libc::PR_GET_NO_NEW_PRIVS,
        libc::PR_CAPBSET_READ,
    ];
    if phase == Phase::Startup {
        prctl_ops.push(libc::PR_SET_NO_NEW_PRIVS);
        rules.insert(
            libc::SYS_seccomp,
            any_of(0, &dword, &[u64::from(libc::SECCOMP_SET_MODE_FILTER)])?,
        );
    }
    let prctl_ops: Vec<u64> = prctl_ops
        .into_iter()
        .map(|op| u64::from(op.unsigned_abs()))
        .collect();
    rules.insert(libc::SYS_prctl, any_of(0, &dword, &prctl_ops)?);
    Ok(())
}

/// Filesystem and socket syscalls, per profile (OP-2).
fn profile_rules(rules: &mut Rules, profile: Profile, phase: Phase) -> Result<(), Error> {
    let dword = SeccompCmpArgLen::Dword;

    let read_fs: &[i64] = &[
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_getdents64,
        libc::SYS_readlinkat,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
    ];
    #[cfg(target_arch = "x86_64")]
    let read_fs_x86: &[i64] = &[
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_access,
        libc::SYS_readlink,
    ];
    let write_fs: &[i64] = &[
        libc::SYS_mkdirat,
        libc::SYS_unlinkat,
        libc::SYS_renameat2,
        libc::SYS_ftruncate,
    ];

    let socket_io: &[i64] = &[
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_shutdown,
        libc::SYS_accept4,
    ];
    let af_unix = u64::from(libc::AF_UNIX.unsigned_abs());

    match profile {
        Profile::Server => {
            allow(rules, read_fs);
            #[cfg(target_arch = "x86_64")]
            allow(rules, read_fs_x86);
            allow(rules, write_fs);
            allow(rules, socket_io);
            allow(
                rules,
                &[libc::SYS_connect, libc::SYS_sendmmsg, libc::SYS_recvmmsg],
            );
            #[cfg(target_arch = "x86_64")]
            allow(rules, &[libc::SYS_accept]);
            // SA-22
            rules.insert(
                libc::SYS_socket,
                any_of(
                    0,
                    &dword,
                    &[
                        af_unix,
                        u64::from(libc::AF_INET.unsigned_abs()),
                        u64::from(libc::AF_INET6.unsigned_abs()),
                    ],
                )?,
            );
            rules.insert(libc::SYS_socketpair, any_of(0, &dword, &[af_unix])?);
        }
        Profile::Signer => {
            // OP-2
            allow(rules, read_fs);
            #[cfg(target_arch = "x86_64")]
            allow(rules, read_fs_x86);
            allow(rules, socket_io);
            if phase == Phase::Startup {
                rules.insert(libc::SYS_socket, any_of(0, &dword, &[af_unix])?);
                rules.insert(libc::SYS_socketpair, any_of(0, &dword, &[af_unix])?);
                // §14.5
                allow(rules, &[libc::SYS_memfd_secret, libc::SYS_ftruncate]);
            }
        }
        Profile::ParserWorker => {
            // OP-2
            if phase == Phase::Startup {
                allow(rules, read_fs);
                #[cfg(target_arch = "x86_64")]
                allow(rules, read_fs_x86);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILES: [Profile; 3] = [Profile::Server, Profile::Signer, Profile::ParserWorker];
    const PHASES: [Phase; 2] = [Phase::Startup, Phase::Narrowed];

    #[test]
    fn no_allowlist_contains_io_uring() {
        // SA-22, OP-4
        for profile in PROFILES {
            for phase in PHASES {
                let rules = allowlist(profile, phase, 1).unwrap();
                for nr in IO_URING {
                    assert!(
                        !rules.contains_key(&nr),
                        "{profile:?} {phase:?} allows {nr}"
                    );
                }
            }
        }
    }

    #[test]
    fn narrowed_phase_is_a_subset_of_startup() {
        // SA-22
        for profile in PROFILES {
            let startup = allowlist(profile, Phase::Startup, 1).unwrap();
            let narrowed = allowlist(profile, Phase::Narrowed, 1).unwrap();
            for nr in narrowed.keys() {
                assert!(startup.contains_key(nr), "{profile:?} phase 2 adds {nr}");
            }
            assert!(!narrowed.contains_key(&libc::SYS_seccomp));
        }
    }

    #[test]
    fn signer_has_no_network_syscalls() {
        // OP-2
        for phase in PHASES {
            let rules = allowlist(Profile::Signer, phase, 1).unwrap();
            for nr in [libc::SYS_connect, libc::SYS_bind, libc::SYS_listen] {
                assert!(!rules.contains_key(&nr), "{phase:?} allows {nr}");
            }
        }
        let narrowed = allowlist(Profile::Signer, Phase::Narrowed, 1).unwrap();
        assert!(!narrowed.contains_key(&libc::SYS_socket));
    }

    #[test]
    fn parser_worker_has_no_socket_syscalls() {
        // OP-2
        for phase in PHASES {
            let rules = allowlist(Profile::ParserWorker, phase, 1).unwrap();
            for nr in [
                libc::SYS_socket,
                libc::SYS_socketpair,
                libc::SYS_connect,
                libc::SYS_bind,
                libc::SYS_listen,
                libc::SYS_accept4,
                libc::SYS_sendto,
                libc::SYS_recvfrom,
                libc::SYS_sendmsg,
                libc::SYS_recvmsg,
            ] {
                assert!(!rules.contains_key(&nr), "{phase:?} allows {nr}");
            }
        }
    }

    #[test]
    fn no_profile_allows_exec_or_fork() {
        // SA-22
        for profile in PROFILES {
            for phase in PHASES {
                let rules = allowlist(profile, phase, 1).unwrap();
                for nr in [libc::SYS_execve, libc::SYS_execveat, libc::SYS_ptrace] {
                    assert!(
                        !rules.contains_key(&nr),
                        "{profile:?} {phase:?} allows {nr}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_filter_compiles_for_the_native_arch() {
        let arch = target_arch().unwrap();
        for profile in PROFILES {
            assert_eq!(startup_filters(profile, arch, 1).unwrap().len(), 3);
            assert_ne!(narrowed_filter(profile, arch, 1).unwrap().len(), 0);
        }
    }
}
