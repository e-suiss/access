#![allow(clippy::unwrap_used, reason = "test code")]

use super::*;

fn dir() -> FileCold {
    let n = access_crypto::random::bytes::<8>().unwrap();
    let name = format!("{:016x}", u64::from_be_bytes(n));
    FileCold {
        root: std::env::temp_dir().join(format!("access-cold-{name}")),
    }
}

// OP-73 m.4, OP-158 m.3 (w)
#[tokio::test]
async fn an_object_is_written_once_and_never_overwritten() {
    let cold = dir();
    let key = "identity-audit/2026/01/identity_audit_202601_default.parquet";
    assert_eq!(cold.get(key).await.unwrap(), None);
    cold.put(key, b"first").await.unwrap();
    cold.put(key, b"first").await.unwrap();
    assert!(matches!(
        cold.put(key, b"second").await,
        Err(AuditError::Cold(_))
    ));
    assert_eq!(cold.get(key).await.unwrap().unwrap(), b"first");
    let meta = std::fs::metadata(cold.root.join(key)).unwrap();
    assert!(meta.permissions().readonly());
    for bad in ["", "/abs", "a/../b", "a//b", "a/b c", "./a"] {
        assert!(cold.put(bad, b"x").await.is_err(), "{bad}");
    }
    let entries = std::fs::read_dir(cold.root.join("identity-audit/2026/01"))
        .unwrap()
        .count();
    assert_eq!(entries, 1);
}

// OP-42
#[tokio::test]
async fn listing_a_prefix_gives_its_keys_only() {
    let cold = dir();
    cold.put("shred-journal/a/b/1.json", b"x").await.unwrap();
    cold.put("shred-journal/a/c/2.json", b"y").await.unwrap();
    cold.put("tiles/x", b"z").await.unwrap();
    assert_eq!(
        cold.list("shred-journal").await.unwrap(),
        vec!["shred-journal/a/b/1.json", "shred-journal/a/c/2.json"]
    );
    assert_eq!(cold.list("absent").await.unwrap(), Vec::<String>::new());
}
