#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use suiss_ledger::doorbell::Ring;
use suiss_ledger::doorbell::testing::{Pki, Twin};
use suiss_ledger::fence::Cursor;

use super::*;

fn section(dir: &Path, pki: &Pki, addr: &str, key_mode: u32) -> config::Doorbell {
    let write = |name: &str, body: &str, mode: u32| {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    };
    config::Doorbell {
        addr: addr.to_owned(),
        server_name: String::from("localhost"),
        ca_file: write("ca.pem", &pki.ca_pem, 0o644),
        cert_file: write("client.pem", &pki.cert_pem, 0o644),
        key_file: write("client.key", &pki.key_pem, key_mode),
    }
}

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("doorbell-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// OP-156 m.3 (j), CR-35
#[test]
fn a_key_others_may_read_is_refused() {
    let pki = Pki::new().unwrap();
    let d = dir("perm");
    assert!(client(&section(&d, &pki, "127.0.0.1:1", 0o644)).is_err());
    let ok = client(&section(&d, &pki, "127.0.0.1:1", 0o600)).unwrap();
    assert_eq!(ok.inbox.len(), 32);
    assert_ne!(
        ok.inbox,
        client(&section(&d, &pki, "127.0.0.1:1", 0o600))
            .unwrap()
            .inbox
    );
}

// OP-156 m.3 (j)
#[tokio::test(flavor = "multi_thread")]
async fn a_ring_is_published_and_wakes_the_listener() {
    let pki = Pki::new().unwrap();
    let twin = Twin::start(pki.server.clone()).await.unwrap();
    let d = dir("ring");
    let bell = Doorbell::start(&client(&section(&d, &pki, &twin.addr(), 0o600)).unwrap());
    let ring = Ring {
        domain: [3; 32],
        at: Cursor { pos: 8, idx: 0 },
        id: [4; 32],
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            bell.bell.ring(ring);
            let woken = tokio::time::timeout(Duration::from_millis(200), bell.wake.notified());
            if woken.await.is_ok() {
                break;
            }
        }
    })
    .await
    .unwrap();
    let stored = twin.stored("ACCESS_DOORBELL");
    assert_eq!(stored.len(), 1, "one event id is stored once");
    assert_eq!(
        Ring::read(&stored[0].payload).unwrap(),
        ([3; 32], Cursor { pos: 8, idx: 0 })
    );
    bell.stop().await;
}
