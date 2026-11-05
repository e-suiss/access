#![allow(clippy::unwrap_used, reason = "test code")]

use access_crypto::Secret;
use access_store::testing::fresh;

use super::*;
use crate::testing::hsm;

/// A token handle that is never dropped: unloading `SoftHSM` after it used OpenSSL crashes
/// the test process at exit on some hosts.
fn open(module: &std::path::Path, label: &str) -> &'static KeyStore {
    let pin = Secret::new(String::from("1234-test-only"));
    Box::leak(Box::new(KeyStore::open(module, label, &pin).unwrap()))
}

// OP-137, OP-149 m.22 (g): servers of one cell starting together leave one opaque-id root in
// the token, and every one of them derives the same id key from it
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_starts_make_one_opaque_id_root() {
    let db = fresh().await.unwrap();
    let (module, label) = hsm("ids-root");
    let starts: Vec<_> = (0..6)
        .map(|_| {
            let keys = open(&module, &label);
            let app = db.app.clone();
            tokio::spawn(async move {
                open_root(&app, keys).await.unwrap();
                crate::login::id_key_bytes(keys).unwrap()
            })
        })
        .collect();
    let mut derived = Vec::new();
    for s in starts {
        derived.push(s.await.unwrap());
    }
    assert!(derived.windows(2).all(|w| w[0] == w[1]));
    let keys = open(&module, &label);
    assert!(keys.mac(ID_KEY_ROOT).is_ok());
    open_root(&db.app, keys).await.unwrap();
    assert_eq!(crate::login::id_key_bytes(keys).unwrap(), derived[0]);
}
