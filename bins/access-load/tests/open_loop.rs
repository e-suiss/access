//! OP-32, OP-61, OP-158 m.3 (z): `access-load` against a local HTTP/1.1 server: an open-loop run
//! reports every request, its latency percentiles and the environment.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::process::Command;

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpListener;

async fn serve(listener: TcpListener) {
    loop {
        let Ok((sock, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut r = BufReader::new(sock);
            loop {
                let mut length = 0usize;
                let mut line = String::new();
                if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                loop {
                    line.clear();
                    r.read_line(&mut line).await.unwrap();
                    if line.trim_end().is_empty() {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0u8; length];
                r.read_exact(&mut body).await.unwrap();
                let answer = b"{\"decision\":true}";
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                    answer.len()
                );
                let s = r.get_mut();
                s.write_all(head.as_bytes()).await.unwrap();
                s.write_all(answer).await.unwrap();
            }
        });
    }
}

// OP-32, OP-61, OP-158 m.3 (z), Ek B 6049
#[tokio::test(flavor = "multi_thread")]
async fn an_open_loop_run_reports_every_request_with_its_environment() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener));
    let dir = std::env::temp_dir().join(format!("access-load-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let requests = dir.join("requests.jsonl");
    std::fs::write(
        &requests,
        "{\"body\":{\"subject\":{\"type\":\"party\",\"id\":\"a\"}}}\n{\"method\":\"GET\",\"path\":\"/x\"}\n",
    )
    .unwrap();
    let out = dir.join("report.json");
    let bin = env!("CARGO_BIN_EXE_access-load");
    let run = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["run", "check", &format!("http://{addr}")])
            .args(["--requests", requests.to_str().unwrap()])
            .args(["--rate", "200", "--seconds", "1", "--connections", "8"])
            .args(["--out", out.to_str().unwrap()])
            .env("ACCESS_LOAD_PG_VERSION", "18")
            .env("ACCESS_LOAD_SYNC_STANDBYS", "2")
            .output()
            .unwrap()
    });
    let output = tokio::time::timeout(std::time::Duration::from_secs(60), run)
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["scenario"], "check");
    assert_eq!(report["sent"], 200);
    assert_eq!(report["answered"], 200);
    assert_eq!(report["ok"], 200);
    assert_eq!(report["open_loop"], true);
    for p in ["p50", "p90", "p99", "p999", "max"] {
        assert!(report["latency_us"][p].as_u64().is_some(), "{p}: {report}");
    }
    let env = &report["environment"];
    assert_eq!(env["pg_version"], "18");
    assert_eq!(env["sync_standbys"], 2);
    assert!(env["cores"].as_u64().is_some_and(|c| c > 0));
    let written: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("report.json")).unwrap()).unwrap();
    assert_eq!(written["sent"], 200);
}

// OP-158 m.3 (z)
#[test]
fn every_scenario_is_listed() {
    let out = Command::new(env!("CARGO_BIN_EXE_access-load"))
        .arg("list")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    for s in [
        "commit",
        "check",
        "search",
        "login",
        "refresh",
        "introspection",
        "revocation",
    ] {
        assert!(text.lines().any(|l| l.starts_with(s)), "{s}");
    }
}
