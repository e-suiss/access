#![allow(clippy::unwrap_used, reason = "test code")]

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use access_crypto::Secret;
use access_store::testing::{attach_app, fresh};

use super::*;
use crate::testing::hsm;

const DB: &str = "ACCESS_IDS_ROOT_DB";
const MODULE: &str = "ACCESS_IDS_ROOT_MODULE";
const TOKEN: &str = "ACCESS_IDS_ROOT_TOKEN";

/// A token handle that is never dropped: unloading `SoftHSM` after it used OpenSSL crashes
/// the test process at exit on some hosts.
fn open(module: &Path, label: &str) -> &'static KeyStore {
    let pin = Secret::new(String::from("1234-test-only"));
    Box::leak(Box::new(KeyStore::open(module, label, &pin).unwrap()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// One server start in a process of its own, as in production: its own module instance and
/// sessions on the shared token, and its own connections to the shared database.
fn start(db: &str, module: &Path, label: &str) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "ids::tests::one_start",
            "--ignored",
            "--nocapture",
        ])
        .env(DB, db)
        .env(MODULE, module)
        .env(TOKEN, label)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
}

/// The id key a start derived, read from its output once it exited.
fn derived(mut child: std::process::Child) -> String {
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("a start did not exit");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert!(status.success(), "{status}: {out}");
    out.lines()
        .find_map(|l| l.strip_prefix("id-key "))
        .unwrap()
        .to_owned()
}

// OP-137, OP-149 m.22 (g)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_starts_make_one_opaque_id_root() {
    let db = fresh().await.unwrap();
    let (module, label) = hsm("ids-root");
    let starts: Vec<_> = (0..6).map(|_| start(&db.name, &module, &label)).collect();
    let mut keys_derived = Vec::new();
    for s in starts {
        keys_derived.push(
            tokio::task::spawn_blocking(move || derived(s))
                .await
                .unwrap(),
        );
    }
    assert!(keys_derived.windows(2).all(|w| w[0] == w[1]));
    let keys = open(&module, &label);
    assert!(keys.mac(ID_KEY_ROOT).is_ok());
    open_root(&db.app, keys).await.unwrap();
    assert_eq!(
        hex(&crate::login::id_key_bytes(keys).unwrap()),
        keys_derived[0]
    );
}

#[tokio::test]
#[ignore = "child of concurrent_starts_make_one_opaque_id_root"]
async fn one_start() {
    let (Some(db), Some(module), Some(label)) = (
        std::env::var_os(DB),
        std::env::var_os(MODULE),
        std::env::var(TOKEN).ok(),
    ) else {
        return;
    };
    let app = attach_app(db.to_str().unwrap()).await.unwrap();
    let keys = open(Path::new(&module), &label);
    open_root(&app, keys).await.unwrap();
    writeln!(
        std::io::stdout(),
        "id-key {}",
        hex(&crate::login::id_key_bytes(keys).unwrap())
    )
    .unwrap();
}
