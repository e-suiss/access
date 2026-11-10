//! OP-155 m.3 (o), Ek B 4993, RR-28: the keytab goes from the operator's file into
//! `memfd_secret` memory and into libkrb5's in-memory keytab, and the acceptor credential comes
//! from it; nothing is written to disk. Linux only; the nightly job runs it under the address sanitizer.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::io::Read as _;
use std::path::{Path, PathBuf};

use access_gw_kerberos::accept::{AcceptError, Acceptor};
use access_gw_kerberos::keytab::{self, MEMORY_KEYTAB};

const SPN: &str = "HTTP/access.corp.example@CORP.EXAMPLE";

fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0_u8; n];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut b)
        .unwrap();
    b
}

fn entry(components: &[&str], enctype: u16, kvno: u32, key: &[u8]) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend(u16::try_from(components.len()).unwrap().to_be_bytes());
    for s in std::iter::once(&"CORP.EXAMPLE").chain(components) {
        e.extend(u16::try_from(s.len()).unwrap().to_be_bytes());
        e.extend(s.as_bytes());
    }
    e.extend(1_u32.to_be_bytes());
    e.extend(0_u32.to_be_bytes());
    e.push(u8::try_from(kvno).unwrap());
    e.extend(enctype.to_be_bytes());
    e.extend(u16::try_from(key.len()).unwrap().to_be_bytes());
    e.extend(key);
    e.extend(kvno.to_be_bytes());
    let mut out = i32::try_from(e.len()).unwrap().to_be_bytes().to_vec();
    out.extend(e);
    out
}

fn holding(dir: &Path, needle: &[u8], out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            holding(&p, needle, out);
        } else if std::fs::read(&p).is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle)) {
            out.push(p);
        }
    }
}

// OP-155 m.3 (o), Ek B 4993
#[test]
fn the_keytab_lives_in_secret_memory_and_never_reaches_disk() {
    let key = random(32);
    let rc4 = random(16);
    let mut kt = vec![0x05, 0x02];
    kt.extend(entry(&["HTTP", "access.corp.example"], 18, 4, &key));
    kt.extend(entry(&["HTTP", "access.corp.example"], 23, 4, &rc4));
    let dir = std::env::temp_dir().join(format!("access-keytab-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("http.keytab");
    std::fs::write(&path, &kt).unwrap();
    let installed = keytab::install(&path, SPN).unwrap();
    assert!(installed.in_secret_memory());
    assert_eq!(installed.kvnos, vec![4]);
    assert!(MEMORY_KEYTAB.starts_with("MEMORY:"));
    std::fs::remove_file(&path).unwrap();
    let acceptor = Acceptor::new(SPN, false).unwrap();
    assert_eq!(
        acceptor
            .accept(&[0x60, 0x03, 0x06, 0x01, 0x00])
            .unwrap_err(),
        AcceptError::Refused
    );
    let mut found = Vec::new();
    for place in [
        std::env::temp_dir(),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/dev/shm"),
    ] {
        holding(&place, &key, &mut found);
    }
    assert!(found.is_empty(), "the key reached disk: {found:?}");
    drop(installed);
}

// IDP-17
#[test]
fn a_keytab_without_an_aes256_key_of_the_spn_is_refused() {
    let mut kt = vec![0x05, 0x02];
    kt.extend(entry(&["HTTP", "access.corp.example"], 23, 4, &random(16)));
    kt.extend(entry(&["HTTP", "other.corp.example"], 18, 4, &random(32)));
    let dir = std::env::temp_dir().join(format!("access-keytab-rc4-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("http.keytab");
    std::fs::write(&path, &kt).unwrap();
    assert!(keytab::install(&path, SPN).is_err());
    std::fs::remove_file(&path).unwrap();
}
