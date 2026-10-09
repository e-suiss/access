//! SA-22 runtime lockdown tests.

use std::process::ExitCode;

/// The subset of the libtest command line that cargo test and cargo-nextest use:
/// `--list [--format terse] [--ignored]`, and `[--exact] [FILTER]`.
struct Cli {
    list: bool,
    ignored: bool,
    exact: bool,
    filter: Option<String>,
}

impl Cli {
    fn parse() -> Self {
        let mut cli = Self {
            list: false,
            ignored: false,
            exact: false,
            filter: None,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--list" => cli.list = true,
                "--ignored" => cli.ignored = true,
                "--exact" => cli.exact = true,
                "--format" | "--test-threads" | "--color" | "--logfile" => {
                    let _ = args.next();
                }
                flag if flag.starts_with('-') => {}
                filter => cli.filter = Some(filter.to_owned()),
            }
        }
        cli
    }

    fn selects(&self, name: &str) -> bool {
        match &self.filter {
            None => true,
            Some(filter) if self.exact => name == filter,
            Some(filter) => name.contains(filter.as_str()),
        }
    }

    /// Prints `name: test` lines (the terse list format). There are no ignored tests.
    fn print_list<'a>(&self, names: impl Iterator<Item = &'a str>) -> ExitCode {
        use std::io::Write as _;
        let mut out = std::io::stdout();
        if !self.ignored {
            for name in names.filter(|name| self.selects(name)) {
                let _ = writeln!(out, "{name}: test");
            }
        }
        ExitCode::SUCCESS
    }
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    if let Ok(name) = std::env::var(linux::SCENARIO_ENV) {
        return linux::child(&name);
    }
    let cli = Cli::parse();
    if cli.list {
        return cli.print_list(linux::scenario_names());
    }
    if cli.ignored {
        return ExitCode::SUCCESS;
    }
    linux::parent(&cli)
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    use std::io::Write as _;

    use access_sandbox::{Error, LandlockAbi, Lockdown, Profile, SecretMemory};

    const NAME: &str = "lockdown_fails_closed_on_unsupported_os";
    let cli = Cli::parse();
    if cli.list {
        return cli.print_list(std::iter::once(NAME));
    }
    if cli.ignored || !cli.selects(NAME) {
        return ExitCode::SUCCESS;
    }

    // SA-22
    let mut out = std::io::stdout();
    let lockdown = Lockdown::new(Profile::Server, LandlockAbi::V1).apply();
    let secret = SecretMemory::new(core::num::NonZeroUsize::MIN);
    let ok =
        matches!(lockdown, Err(Error::Unsupported)) && matches!(secret, Err(Error::Unsupported));
    let _ = writeln!(out, "test {NAME} ... {}", if ok { "ok" } else { "FAILED" });
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::{ErrorKind, Write as _};
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::PathBuf;
    use std::process::{Command, ExitCode};

    use access_sandbox::{Error, LandlockAbi, Lockdown, Locked, Profile, RunAs, SecretMemory};
    use rustix::process::DumpableBehavior;

    pub(super) const SCENARIO_ENV: &str = "ACCESS_SANDBOX_SCENARIO";
    const REQUIRE_MEMFD_SECRET_ENV: &str = "ACCESS_SANDBOX_REQUIRE_MEMFD_SECRET";
    /// Exit code a child uses to report "capability not present on this kernel".
    const SKIP: u8 = 77;
    const RUN_AS_ID: u32 = 65532;
    const SIGSYS: i32 = 31;
    /// Printed by a child right before the call that seccomp must kill it on.
    const REACHED: &str = "reached forbidden call";

    fn reached() {
        let _ = writeln!(std::io::stdout(), "{REACHED}");
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Expect {
        /// The child exits 0.
        Pass,
        /// Seccomp kills the child (`SECCOMP_RET_KILL_PROCESS` delivers SIGSYS).
        KilledBySeccomp,
        /// The child exits 0, or reports SKIP when the kernel lacks the capability.
        PassOrSkip,
    }

    /// Scenario name, expected outcome. Names state the behaviour; comments cite the rule.
    const SCENARIOS: &[(&str, Expect)] = &[
        // SA-22
        ("dumpable_flag_is_cleared_after_lockdown", Expect::Pass),
        // SA-22
        ("no_new_privs_is_set_after_lockdown", Expect::Pass),
        // SA-22
        ("capability_sets_are_empty_after_lockdown", Expect::Pass),
        // SA-22
        (
            "root_process_runs_as_configured_identity_after_lockdown",
            Expect::Pass,
        ),
        ("root_process_without_run_as_is_refused", Expect::Pass),
        // SA-22
        ("lockdown_is_refused_once_other_threads_exist", Expect::Pass),
        // SA-22, R-2, §14.5
        ("landlock_denies_paths_that_were_not_declared", Expect::Pass),
        ("landlock_read_only_path_cannot_be_written", Expect::Pass),
        // OP-92
        (
            "landlock_denies_tcp_connect_to_undeclared_port",
            Expect::Pass,
        ),
        ("landlock_allows_tcp_connect_to_declared_port", Expect::Pass),
        (
            "landlock_reports_kernel_abi_at_least_the_required_one",
            Expect::Pass,
        ),
        // SA-22, OP-4
        ("server_io_uring_setup_fails_with_eperm", Expect::Pass),
        ("server_io_uring_setup_fails_after_narrow", Expect::Pass),
        (
            "signer_io_uring_setup_kills_the_process",
            Expect::KilledBySeccomp,
        ),
        (
            "parser_worker_io_uring_setup_kills_the_process",
            Expect::KilledBySeccomp,
        ),
        // SA-22
        (
            "server_threads_work_and_narrow_from_a_worker_thread_reaches_main",
            Expect::Pass,
        ),
        ("signer_threads_work_through_both_phases", Expect::Pass),
        // OP-2
        ("signer_can_create_unix_socket_during_startup", Expect::Pass),
        ("signer_cannot_create_inet_socket", Expect::KilledBySeccomp),
        (
            "signer_cannot_create_any_socket_after_narrow",
            Expect::KilledBySeccomp,
        ),
        // OP-2
        (
            "parser_worker_cannot_create_unix_socket",
            Expect::KilledBySeccomp,
        ),
        (
            "parser_worker_cannot_open_files_after_narrow",
            Expect::KilledBySeccomp,
        ),
        // SA-22
        ("server_cannot_spawn_processes", Expect::Pass),
        // OP-2, §14.5
        (
            "signer_memfd_secret_memory_is_usable_after_lockdown",
            Expect::PassOrSkip,
        ),
    ];

    pub(super) fn scenario_names() -> impl Iterator<Item = &'static str> {
        SCENARIOS.iter().map(|&(name, _)| name)
    }

    pub(super) fn parent(cli: &super::Cli) -> ExitCode {
        let mut out = std::io::stdout();
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(e) => {
                let _ = writeln!(out, "cannot locate test binary: {e}");
                return ExitCode::FAILURE;
            }
        };
        let require_memfd = std::env::var(REQUIRE_MEMFD_SECRET_ENV).is_ok_and(|v| v == "1");
        let kernel = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let _ = writeln!(out, "kernel {}", kernel.trim());
        let selected: Vec<_> = SCENARIOS
            .iter()
            .filter(|(name, _)| cli.selects(name))
            .collect();
        let _ = writeln!(out, "running {} lockdown scenarios", selected.len());

        let mut failed = Vec::new();
        for &&(name, expect) in &selected {
            let output = Command::new(&exe).env(SCENARIO_ENV, name).output();
            let verdict = match output {
                Err(e) => Err(format!("spawn failed: {e}")),
                Ok(o) => {
                    let code = o.status.code();
                    let signal = o.status.signal();
                    let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
                    let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
                    let detail = format!(
                        "exit={code:?} signal={signal:?}\n  stdout: {}\n  stderr: {}",
                        stdout.trim(),
                        stderr.trim()
                    );
                    match (expect, code, signal) {
                        (Expect::Pass | Expect::PassOrSkip, Some(0), _) => Ok(stdout),
                        (Expect::KilledBySeccomp, _, Some(SIGSYS)) if stdout.contains(REACHED) => {
                            Ok(stdout)
                        }
                        (Expect::PassOrSkip, Some(c), _)
                            if c == i32::from(SKIP) && !require_memfd =>
                        {
                            Ok(format!("SKIPPED: {}", stdout.trim()))
                        }
                        _ => Err(detail),
                    }
                }
            };
            match verdict {
                Ok(stdout) => {
                    let note = stdout
                        .lines()
                        .filter(|l| l.starts_with("SKIPPED") || l.starts_with("info:"))
                        .collect::<Vec<_>>()
                        .join("; ");
                    let _ = writeln!(out, "test {name} ... ok {note}");
                }
                Err(detail) => {
                    let _ = writeln!(out, "test {name} ... FAILED\n  {detail}");
                    failed.push(name);
                }
            }
        }
        if failed.is_empty() {
            let _ = writeln!(out, "test result: ok. {} passed", selected.len());
            ExitCode::SUCCESS
        } else {
            let _ = writeln!(out, "test result: FAILED. failures: {failed:?}");
            ExitCode::FAILURE
        }
    }

    pub(super) fn child(name: &str) -> ExitCode {
        let result = run(name);
        let mut out = std::io::stdout();
        match result {
            Ok(Outcome::Pass(info)) => {
                if !info.is_empty() {
                    let _ = writeln!(out, "info: {info}");
                }
                ExitCode::SUCCESS
            }
            Ok(Outcome::Skip(reason)) => {
                let _ = writeln!(out, "{reason}");
                ExitCode::from(SKIP)
            }
            Err(msg) => {
                let _ = writeln!(out, "{msg}");
                ExitCode::FAILURE
            }
        }
    }

    enum Outcome {
        Pass(String),
        Skip(String),
    }

    type Check = Result<Outcome, String>;

    #[allow(clippy::unnecessary_wraps)]
    fn pass() -> Check {
        Ok(Outcome::Pass(String::new()))
    }

    fn ensure(cond: bool, msg: impl Into<String>) -> Result<(), String> {
        if cond { Ok(()) } else { Err(msg.into()) }
    }

    fn is_root() -> bool {
        rustix::process::geteuid().is_root()
    }

    /// A lockdown with the identity the tests run under.
    fn lockdown(profile: Profile) -> Lockdown {
        let lockdown = Lockdown::new(profile, LandlockAbi::REQUIRED);
        if is_root() {
            match RunAs::new(RUN_AS_ID, RUN_AS_ID) {
                Ok(run_as) => lockdown.run_as(run_as),
                Err(_) => lockdown,
            }
        } else {
            lockdown
        }
    }

    fn apply(lockdown: Lockdown) -> Result<Locked, String> {
        lockdown
            .apply()
            .map_err(|e| format!("lockdown failed: {e} ({e:?})"))
    }

    fn narrow(locked: Locked) -> Result<(), String> {
        locked
            .narrow()
            .map(|_| ())
            .map_err(|e| format!("narrow failed: {e} ({e:?})"))
    }

    /// Calls `io_uring_setup(1, NULL)`. Unfiltered, the kernel answers EFAULT (or ENOSYS when
    /// `io_uring` is compiled out); under the lockdown seccomp answers first.
    #[allow(unsafe_code)]
    fn io_uring_setup() -> std::io::Error {
        let params = core::ptr::null_mut::<u8>();
        // SAFETY: io_uring_setup with a NULL params pointer never writes through it; the kernel
        // rejects the pointer (EFAULT) or seccomp rejects the call before it is read.
        let rc = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1_u32, params) };
        if rc >= 0 {
            return std::io::Error::other(format!("io_uring_setup returned fd {rc}"));
        }
        std::io::Error::last_os_error()
    }

    /// A scratch tree readable by the post-lockdown identity: `allowed/` and `denied/`, each
    /// with a `file`.
    fn scratch_tree() -> Result<PathBuf, String> {
        use std::os::unix::fs::PermissionsExt as _;
        let root = std::env::temp_dir().join(format!("access-sandbox-{}", std::process::id()));
        for dir in ["allowed", "denied"] {
            let d = root.join(dir);
            fs::create_dir_all(&d).map_err(|e| e.to_string())?;
            fs::write(d.join("file"), b"content").map_err(|e| e.to_string())?;
            fs::set_permissions(&d, fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
            fs::set_permissions(d.join("file"), fs::Permissions::from_mode(0o666))
                .map_err(|e| e.to_string())?;
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
        Ok(root)
    }

    #[allow(clippy::too_many_lines)]
    fn run(name: &str) -> Check {
        match name {
            "dumpable_flag_is_cleared_after_lockdown" => {
                let _locked = apply(lockdown(Profile::Server))?;
                let dumpable = rustix::process::dumpable_behavior().map_err(|e| e.to_string())?;
                ensure(
                    dumpable == DumpableBehavior::NotDumpable,
                    format!("dumpable = {dumpable:?}"),
                )?;
                pass()
            }
            "no_new_privs_is_set_after_lockdown" => {
                let _locked = apply(lockdown(Profile::Server))?;
                let nnp = rustix::thread::no_new_privs().map_err(|e| e.to_string())?;
                ensure(nnp, "no_new_privs is not set")?;
                pass()
            }
            "capability_sets_are_empty_after_lockdown" => {
                let last: u32 = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
                    .map_err(|e| e.to_string())?
                    .trim()
                    .parse()
                    .map_err(|e| format!("{e}"))?;
                let _locked = apply(lockdown(Profile::Server))?;
                let sets = rustix::thread::capabilities(None).map_err(|e| e.to_string())?;
                ensure(
                    sets.effective.is_empty()
                        && sets.permitted.is_empty()
                        && sets.inheritable.is_empty(),
                    format!("capabilities not empty: {sets:?}"),
                )?;
                for cap in 0..=last.min(63) {
                    let set = rustix::thread::CapabilitySet::from_bits_retain(1_u64 << cap);
                    let present = rustix::thread::capability_is_in_bounding_set(set)
                        .map_err(|e| e.to_string())?;
                    ensure(!present, format!("capability {cap} still in bounding set"))?;
                }
                pass()
            }
            "root_process_runs_as_configured_identity_after_lockdown" => {
                let was_root = is_root();
                let locked = apply(lockdown(Profile::Server))?;
                let uid = rustix::process::getuid().as_raw();
                let euid = rustix::process::geteuid().as_raw();
                let gid = rustix::process::getgid().as_raw();
                if was_root {
                    ensure(
                        (uid, euid, gid) == (RUN_AS_ID, RUN_AS_ID, RUN_AS_ID),
                        format!("uid={uid} euid={euid} gid={gid}"),
                    )?;
                    ensure(locked.report().uid == RUN_AS_ID, "report uid")?;
                    let back = rustix::thread::set_thread_res_uid(
                        rustix::process::Uid::ROOT,
                        rustix::process::Uid::ROOT,
                        rustix::process::Uid::ROOT,
                    );
                    ensure(back.is_err(), "setresuid(0) succeeded after lockdown")?;
                    pass()
                } else {
                    Ok(Outcome::Pass(format!("not root; kept uid {uid}")))
                }
            }
            "root_process_without_run_as_is_refused" => {
                if !is_root() {
                    return Ok(Outcome::Pass("not root; nothing to refuse".into()));
                }
                match Lockdown::new(Profile::Server, LandlockAbi::REQUIRED).apply() {
                    Err(Error::RootWithoutRunAs) => pass(),
                    other => Err(format!("expected RootWithoutRunAs, got {other:?}")),
                }
            }
            "lockdown_is_refused_once_other_threads_exist" => {
                let (tx, rx) = std::sync::mpsc::channel::<()>();
                let worker = std::thread::spawn(move || {
                    let _ = rx.recv();
                });
                let result = lockdown(Profile::Server).apply();
                let _ = tx.send(());
                let _ = worker.join();
                match result {
                    Err(Error::NotSingleThreaded { threads }) if threads >= 2 => pass(),
                    other => Err(format!("expected NotSingleThreaded, got {other:?}")),
                }
            }
            "landlock_denies_paths_that_were_not_declared" => {
                let root = scratch_tree()?;
                let _locked = apply(lockdown(Profile::Server).allow_read(root.join("allowed")))?;
                let allowed =
                    fs::read(root.join("allowed/file")).map_err(|e| format!("allowed: {e}"))?;
                ensure(allowed == b"content", "allowed file content")?;
                match fs::read(root.join("denied/file")) {
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => {}
                    other => return Err(format!("denied file: expected EACCES, got {other:?}")),
                }
                match fs::read_dir(&root) {
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => pass(),
                    other => Err(format!(
                        "parent dir: expected EACCES, got {:?}",
                        other.map(|_| ())
                    )),
                }
            }
            "landlock_denies_tcp_connect_to_undeclared_port" => {
                let listener =
                    std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
                let addr = listener.local_addr().map_err(|e| format!("addr: {e}"))?;
                let _locked = apply(lockdown(Profile::Server))?;
                match std::net::TcpStream::connect(addr) {
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => pass(),
                    other => Err(format!(
                        "connect: expected EACCES, got {:?}",
                        other.map(|_| ())
                    )),
                }
            }
            "landlock_allows_tcp_connect_to_declared_port" => {
                let listener =
                    std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
                let addr = listener.local_addr().map_err(|e| format!("addr: {e}"))?;
                let _locked = apply(lockdown(Profile::Server).allow_tcp_connect(addr.port()))?;
                std::net::TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
                pass()
            }
            "landlock_read_only_path_cannot_be_written" => {
                let root = scratch_tree()?;
                let _locked = apply(lockdown(Profile::Server).allow_read(root.join("allowed")))?;
                match fs::write(root.join("allowed/file"), b"changed") {
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => {}
                    other => return Err(format!("write: expected EACCES, got {other:?}")),
                }
                match fs::write(root.join("allowed/new"), b"x") {
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => pass(),
                    other => Err(format!("create: expected EACCES, got {other:?}")),
                }
            }
            "landlock_reports_kernel_abi_at_least_the_required_one" => {
                let locked = apply(lockdown(Profile::Server))?;
                let report = locked.report();
                ensure(
                    report.landlock_kernel_abi >= report.landlock_required_abi.as_u32(),
                    format!("kernel ABI {} below required", report.landlock_kernel_abi),
                )?;
                Ok(Outcome::Pass(format!(
                    "landlock_kernel_abi={}",
                    report.landlock_kernel_abi
                )))
            }
            "server_io_uring_setup_fails_with_eperm" => {
                let before = io_uring_setup();
                let _locked = apply(lockdown(Profile::Server))?;
                let after = io_uring_setup();
                ensure(
                    after.raw_os_error() == Some(libc::EPERM),
                    format!("after lockdown: {after:?} (before: {before:?})"),
                )?;
                Ok(Outcome::Pass(format!("before lockdown: {before}")))
            }
            "server_io_uring_setup_fails_after_narrow" => {
                let locked = apply(lockdown(Profile::Server))?;
                narrow(locked)?;
                let after = io_uring_setup();
                ensure(
                    after.raw_os_error() == Some(libc::EPERM),
                    format!("{after:?}"),
                )?;
                pass()
            }
            "signer_io_uring_setup_kills_the_process" => {
                let _locked = apply(lockdown(Profile::Signer))?;
                reached();
                let e = io_uring_setup();
                Err(format!("still alive after io_uring_setup: {e:?}"))
            }
            "parser_worker_io_uring_setup_kills_the_process" => {
                let _locked = apply(lockdown(Profile::ParserWorker))?;
                reached();
                let e = io_uring_setup();
                Err(format!("still alive after io_uring_setup: {e:?}"))
            }
            "server_threads_work_and_narrow_from_a_worker_thread_reaches_main" => {
                let locked = apply(lockdown(Profile::Server))?;
                exercise_threads()?;
                let narrowed = std::thread::Builder::new()
                    .name("narrow".into())
                    .spawn(move || locked.narrow().map(|r| r.seccomp_phase))
                    .map_err(|e| e.to_string())?
                    .join()
                    .map_err(|_| "narrow thread panicked".to_string())?
                    .map_err(|e| e.to_string())?;
                ensure(narrowed == 2, "phase not 2")?;
                let r = rustix::thread::set_no_new_privs(true);
                ensure(
                    r == Err(rustix::io::Errno::PERM),
                    format!("main thread still in phase 1: {r:?}"),
                )?;
                exercise_threads()?;
                pass()
            }
            "signer_threads_work_through_both_phases" => {
                let locked = apply(lockdown(Profile::Signer))?;
                exercise_threads()?;
                narrow(locked)?;
                exercise_threads()?;
                pass()
            }
            "signer_can_create_unix_socket_during_startup" => {
                let _locked = apply(lockdown(Profile::Signer))?;
                let (a, b) = std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
                (&a).write_all(b"ping").map_err(|e| e.to_string())?;
                let mut buf = [0_u8; 4];
                std::io::Read::read_exact(&mut &b, &mut buf).map_err(|e| e.to_string())?;
                ensure(&buf == b"ping", "uds roundtrip")?;
                pass()
            }
            "signer_cannot_create_inet_socket" => {
                let _locked = apply(lockdown(Profile::Signer))?;
                reached();
                let r = std::net::UdpSocket::bind("127.0.0.1:0");
                Err(format!("still alive after socket(AF_INET): {r:?}"))
            }
            "signer_cannot_create_any_socket_after_narrow" => {
                let locked = apply(lockdown(Profile::Signer))?;
                narrow(locked)?;
                reached();
                let r = std::os::unix::net::UnixDatagram::unbound();
                Err(format!(
                    "still alive after socket(AF_UNIX) in phase 2: {r:?}"
                ))
            }
            "parser_worker_cannot_create_unix_socket" => {
                let _locked = apply(lockdown(Profile::ParserWorker))?;
                reached();
                let r = std::os::unix::net::UnixDatagram::unbound();
                Err(format!("still alive after socket(AF_UNIX): {r:?}"))
            }
            "parser_worker_cannot_open_files_after_narrow" => {
                let root = scratch_tree()?;
                let locked =
                    apply(lockdown(Profile::ParserWorker).allow_read(root.join("allowed")))?;
                fs::read(root.join("allowed/file")).map_err(|e| format!("startup read: {e}"))?;
                narrow(locked)?;
                reached();
                let r = fs::read(root.join("allowed/file"));
                Err(format!("still alive after openat in phase 2: {r:?}"))
            }
            "server_cannot_spawn_processes" => {
                let _locked = apply(lockdown(Profile::Server))?;
                match Command::new("/bin/true").status() {
                    Err(_) => pass(),
                    Ok(status) => Err(format!("spawned a process: {status:?}")),
                }
            }
            "signer_memfd_secret_memory_is_usable_after_lockdown" => {
                let _locked = apply(lockdown(Profile::Signer))?;
                match SecretMemory::new(core::num::NonZeroUsize::new(4096).ok_or("len")?) {
                    Ok(mut secret) => {
                        ensure(secret.as_slice().iter().all(|b| *b == 0), "not zero-filled")?;
                        secret.as_mut_slice().fill(0xA5);
                        ensure(secret.as_slice().iter().all(|b| *b == 0xA5), "write lost")?;
                        ensure(
                            !format!("{secret:?}").contains("165"),
                            "Debug leaks contents",
                        )?;
                        drop(secret);
                        pass()
                    }
                    Err(Error::SecretMemoryUnavailable(e)) => Ok(Outcome::Skip(format!(
                        "SKIPPED: memfd_secret unavailable on this kernel ({e}); \
                         CI sets {REQUIRE_MEMFD_SECRET_ENV}=1 and must run it"
                    ))),
                    Err(e) => Err(format!("memfd_secret failed: {e} ({e:?})")),
                }
            }
            other => Err(format!("unknown scenario {other}")),
        }
    }

    /// Thread spawn, named threads, allocation, hashing, channels, join: what a runtime does.
    fn exercise_threads() -> Result<(), String> {
        let handles: Vec<_> = (0..4_u64)
            .map(|i| {
                std::thread::Builder::new()
                    .name(format!("worker-{i}"))
                    .spawn(move || {
                        let mut map = std::collections::HashMap::new();
                        for k in 0..1000_u64 {
                            map.insert(k, vec![i; 64]);
                        }
                        map.len()
                    })
                    .map_err(|e| e.to_string())
            })
            .collect::<Result<_, _>>()?;
        for h in handles {
            let n = h.join().map_err(|_| "worker panicked".to_string())?;
            ensure(n == 1000, "map size")?;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(7_u8))
            .join()
            .map_err(|_| "send panicked")?
            .map_err(|e| e.to_string())?;
        ensure(rx.recv().map_err(|e| e.to_string())? == 7, "channel")?;
        std::thread::sleep(std::time::Duration::from_millis(1));
        Ok(())
    }
}
