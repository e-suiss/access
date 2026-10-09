//! OP-90: the server refuses to start when the runtime lockdown (SA-22) cannot be applied.

use std::process::Command;
use std::time::{Duration, Instant};

/// True when this host could apply the lockdown (Linux with an empty capability bounding
/// set, e.g. a container with `--cap-drop ALL`); the refusal path is then not reachable.
fn lockdown_possible() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|l| l.strip_prefix("CapBnd:").map(|v| v.trim().to_owned()))
        })
        .is_some_and(|bounding| bounding.trim_start_matches('0').is_empty())
}

#[test]
fn op_90_server_refuses_to_start_without_lockdown() {
    if lockdown_possible() {
        return;
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_access-server"))
        .env("ACCESS_LISTEN", "127.0.0.1:0")
        .env("ACCESS_CONFIG", "/nonexistent/access.toml")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn access-server");
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("access-server kept running without a lockdown (OP-90)");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let output = child.wait_with_output().expect("output");
    let logs = String::from_utf8_lossy(&output.stdout);
    assert!(!status.success(), "exit status: {status}");
    assert!(logs.contains("refusing to start"), "logs: {logs}");
}
