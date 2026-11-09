//! OP-155 m.3 (c), MD-18, U43, OP-90: the parser worker binary as real processes. The isolation
//! tests need the Linux lockdown and run as root in the CI `sandbox` job
//! (`just test-parser-worker`); elsewhere the worker and the supervisor must refuse to start.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_access-parser-worker");

/// True when this host could apply the lockdown (Linux with an empty capability bounding set);
/// the refusal path is then not reachable.
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

fn as_root() -> bool {
    cfg!(target_os = "linux")
        && std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines().find_map(|l| {
                    l.strip_prefix("Uid:")
                        .map(|v| v.split_whitespace().next() == Some("0"))
                })
            })
            .unwrap_or(false)
}

// OP-90, U43
#[test]
fn a_worker_refuses_to_start_without_its_lockdown() {
    if lockdown_possible() {
        return;
    }
    let status = Command::new(BIN)
        .arg("work")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
}

// OP-90
#[test]
fn the_supervisor_refuses_to_start_without_its_lockdown() {
    if lockdown_possible() || as_root() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("access-parser-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let unconfigured = Command::new(BIN)
        .env_clear()
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!unconfigured.success());
    let status = Command::new(BIN)
        .env_clear()
        .env("ACCESS_PARSER_SOCKET", dir.join("parser.sock"))
        .env("ACCESS_PARSER_CALLERS", "1000")
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
}

#[cfg(target_os = "linux")]
mod sandboxed {
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    use access_edge_core::ipc::{Op, Reply};
    use access_edge_core::parser::ParserClient;

    use super::BIN;

    struct Supervisor {
        child: Child,
        socket: PathBuf,
    }

    impl Drop for Supervisor {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// The supervisor with `workers` workers, as root switching to `SUDO_UID`/`SUDO_GID`.
    async fn supervisor(name: &str, workers: usize) -> Supervisor {
        let dir = std::env::temp_dir().join(format!("access-parser-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("parser.sock");
        let uid = std::env::var("SUDO_UID").unwrap_or_else(|_| String::from("65534"));
        let gid = std::env::var("SUDO_GID").unwrap_or_else(|_| String::from("65534"));
        let child = Command::new(BIN)
            .env_clear()
            .env("ACCESS_PARSER_SOCKET", &socket)
            .env("ACCESS_PARSER_CALLERS", "0")
            .env("ACCESS_PARSER_WORKERS", workers.to_string())
            .env("ACCESS_PARSER_RUN_AS", format!("{uid}:{gid}"))
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        wait_for(&socket).await;
        Supervisor { child, socket }
    }

    async fn wait_for(socket: &Path) {
        for _ in 0..200 {
            if tokio::net::UnixStream::connect(socket).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(200)).await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the supervisor did not open its socket");
    }

    fn deep(n: usize) -> Vec<u8> {
        let mut d = "<a>".repeat(n);
        d.push_str(&"</a>".repeat(n));
        d.into_bytes()
    }

    // U43, MD-18, OP-155 m.3 (c)
    #[tokio::test]
    #[ignore = "needs root for the Linux lockdown; run by `just test-parser-worker` in the CI sandbox job"]
    async fn u43_a_crashing_worker_takes_down_only_itself() {
        let s = supervisor("u43", 1).await;
        let client = ParserClient::new(s.socket.clone(), Some(0));
        let ok = client.parse(Op::XmlCheck, b"<r/>".to_vec()).await.unwrap();
        assert!(matches!(ok, Reply::Ok { .. }), "{ok:?}");
        let crashed = client.parse(Op::Abort, Vec::new()).await.unwrap();
        assert_eq!(crashed, Reply::WorkerFailed);
        for _ in 0..3 {
            let again = client.parse(Op::XmlCheck, deep(10)).await.unwrap();
            assert!(
                matches!(again, Reply::Ok { ref summary, .. } if summary.depth == 10),
                "{again:?}"
            );
        }
        let mut sup = s;
        assert!(
            sup.child.try_wait().unwrap().is_none(),
            "the supervisor died"
        );
    }

    // OP-125, OP-155 m.3 (c)
    #[tokio::test]
    #[ignore = "needs root for the Linux lockdown; run by `just test-parser-worker` in the CI sandbox job"]
    async fn limits_refuse_before_parsing() {
        let s = supervisor("limits", 2).await;
        let client = ParserClient::new(s.socket.clone(), Some(0));
        let doctype = br#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "b">]><r>&a;</r>"#.to_vec();
        assert_eq!(
            client.parse(Op::XmlCheck, doctype).await.unwrap(),
            Reply::Refused(String::from("xml-doctype"))
        );
        let mut der = vec![0x04, 0x82, 0x20, 0x00];
        der.resize(8 * 1024 + 1, 0);
        assert_eq!(
            client.parse(Op::DerCheck, der).await.unwrap(),
            Reply::Refused(String::from("der-too-large"))
        );
        assert_eq!(
            client.parse(Op::XmlCheck, deep(65)).await.unwrap(),
            Reply::Refused(String::from("xml-depth"))
        );
        let ok = client
            .parse(Op::DerCheck, vec![0x30, 0x03, 0x02, 0x01, 0x05])
            .await
            .unwrap();
        assert!(matches!(ok, Reply::Ok { .. }), "{ok:?}");
    }
}
