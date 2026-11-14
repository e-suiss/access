#![allow(clippy::unwrap_used, reason = "test code")]

use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Write as _};
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
/// sessions on the shared token, and its own connections to the shared database. It opens the
/// token, says `ids-ready`, and starts when a line arrives on its stdin.
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
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Opens every start's token first, then lets them all start together, and returns the id key
/// each derived. The token opens before any start writes: `SoftHSM` 2.6.1 can miss a token
/// whose directory another process is writing to.
fn run_starts(mut children: Vec<std::process::Child>) -> Vec<String> {
    let (tx, rx) = std::sync::mpsc::channel::<(usize, String)>();
    for (i, child) in children.iter_mut().enumerate() {
        let out = child.stdout.take().unwrap();
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                if tx.send((i, line)).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);
    let deadline = Instant::now().checked_add(Duration::from_secs(60)).unwrap();
    let wait = |want: &str, n: usize, rx: &std::sync::mpsc::Receiver<(usize, String)>| {
        let mut got = vec![None; n];
        while got.iter().any(Option::is_none) {
            let left = deadline.saturating_duration_since(Instant::now());
            let (i, line) = rx.recv_timeout(left).expect("a start went quiet");
            if let Some((_, rest)) = line.split_once(want) {
                got[i] = Some(rest.trim().to_owned());
            }
        }
        got.into_iter().map(Option::unwrap).collect::<Vec<_>>()
    };
    let n = children.len();
    wait("ids-ready", n, &rx);
    for child in &mut children {
        writeln!(child.stdin.take().unwrap(), "go").unwrap();
    }
    let keys = wait("id-key ", n, &rx);
    for mut child in children {
        let status = child.wait().unwrap();
        assert!(status.success(), "{status}");
    }
    keys
}

// OP-137, OP-149 m.22 (g)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_starts_make_one_opaque_id_root() {
    let db = fresh().await.unwrap();
    let (module, label) = hsm("ids-root");
    let starts: Vec<_> = (0..6).map(|_| start(&db.name, &module, &label)).collect();
    let keys_derived = tokio::task::spawn_blocking(move || run_starts(starts))
        .await
        .unwrap();
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
    writeln!(std::io::stdout(), "ids-ready").unwrap();
    std::io::stdout().flush().unwrap();
    let mut go = String::new();
    std::io::stdin().read_line(&mut go).unwrap();
    open_root(&app, keys).await.unwrap();
    writeln!(
        std::io::stdout(),
        "id-key {}",
        hex(&crate::login::id_key_bytes(keys).unwrap())
    )
    .unwrap();
}
