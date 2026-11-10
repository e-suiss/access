//! OP-155 m.3 (f), (q), Ek B 4664: the `radclient` tool (`freeradius-utils`) against the gateway, with
//! access-server's real edge router on a real PostgreSQL. `radclient` speaks RADIUS over UDP
//! only, which the gateway never answers. CI's `edge-interop` job installs `radclient` and runs
//! this with `--ignored`; it needs no container.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use std::io::Write as _;
use std::process::{Command, Stdio};

use support::world;

// IDP-18, OP-155 m.3 (f)
#[tokio::test]
#[ignore = "needs radclient (freeradius-utils); CI job edge-interop"]
async fn radclient_over_udp_gets_no_answer() {
    let w = world(116).await;
    let ada = w.person("ada").await;
    let token = w.app_password(ada).await;
    let target = format!("127.0.0.1:{}", w.radsec.port());
    let out = tokio::task::spawn_blocking(move || {
        let mut child = Command::new("radclient")
            .args([
                "-x",
                "-r",
                "1",
                "-t",
                "2",
                &target,
                "auth",
                "ci-only-not-a-secret",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "User-Name = \"ada\", User-Password = \"{token}\"").unwrap();
        drop(stdin);
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    assert!(!out.status.success(), "{out:?}");
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(!text.contains("Access-Accept"), "{text}");
    assert!(!text.contains("Access-Reject"), "{text}");
    let (audit, outbox) = w.rows().await;
    assert!(!audit.contains(&String::from("login.radius.succeeded")));
    assert!(!outbox.iter().any(|k| k.ends_with("authentication")));
}
