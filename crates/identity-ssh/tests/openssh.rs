//! Our own certificate and KRL encoders against OpenSSH's `ssh-keygen` (OP-156 m.3 (o), (z)):
//! `ssh-keygen -L` parses a certificate and checks its CA signature, `ssh-keygen -Q` tests it
//! against a KRL. Keys and nonces are made at test time.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use access_identity_ssh::domain::cert::{Extension, Fields};
use access_identity_ssh::domain::key::Ed25519Public;
use access_identity_ssh::domain::krl::Krl;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::signer::{Signer, SoftSigner};

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("access-ssh-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn ed25519(s: &SoftSigner) -> Ed25519Public {
    match s.public_key() {
        PublicKey::Ed25519(k) => Ed25519Public(k),
        other => panic!("{other:?}"),
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0_u8; N];
    aws_lc_rs::rand::fill(&mut out).unwrap();
    out
}

fn keygen(args: &[&str], at: &Path) -> (bool, String) {
    let out = Command::new("ssh-keygen")
        .args(args)
        .current_dir(at)
        .output()
        .expect("ssh-keygen runs");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn certificate(ca: &SoftSigner, user: Ed25519Public, serial: u64) -> String {
    let fields = Fields {
        nonce: random(),
        key: user,
        serial,
        key_id: String::from("prj_test"),
        principals: BTreeSet::from([String::from("ayse"), String::from("deploy")]),
        valid_after: 1_767_225_000,
        valid_before: 1_767_253_800,
        force_command: Some(String::from("/usr/local/bin/deploy")),
        source_address: BTreeSet::from([String::from("10.0.0.0/8")]),
        extensions: BTreeSet::from([Extension::Pty, Extension::PortForwarding]),
        ca: ed25519(ca),
    };
    let tbs = fields.to_be_signed().unwrap();
    let sig = <[u8; 64]>::try_from(ca.sign(&tbs).unwrap().as_slice()).unwrap();
    fields.certificate(&sig).unwrap().line("ayse@acme")
}

// OP-156 m.3 (o)
#[test]
fn ssh_keygen_reads_our_certificate() {
    let at = dir("cert");
    let (ca, _) = SoftSigner::generate_ed25519().unwrap();
    let (user, _) = SoftSigner::generate_ed25519().unwrap();
    std::fs::write(
        at.join("id-cert.pub"),
        certificate(&ca, ed25519(&user), 4242),
    )
    .unwrap();
    let (ok, out) = keygen(&["-L", "-f", "id-cert.pub"], &at);
    assert!(ok, "{out}");
    assert!(
        out.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"),
        "{out}"
    );
    assert!(out.contains(&ed25519(&ca).fingerprint()), "{out}");
    assert!(out.contains("Key ID: \"prj_test\""), "{out}");
    assert!(out.contains("Serial: 4242"), "{out}");
    assert!(out.contains("ayse") && out.contains("deploy"), "{out}");
    assert!(out.contains("force-command /usr/local/bin/deploy"), "{out}");
    assert!(out.contains("source-address 10.0.0.0/8"), "{out}");
    assert!(
        out.contains("permit-pty") && out.contains("permit-port-forwarding"),
        "{out}"
    );
    assert!(!out.contains("permit-agent-forwarding"), "{out}");
    let mut broken = std::fs::read_to_string(at.join("id-cert.pub")).unwrap();
    broken = broken.replacen("AAAA", "AAAB", 2);
    std::fs::write(at.join("bad-cert.pub"), broken).unwrap();
    assert!(!keygen(&["-L", "-f", "bad-cert.pub"], &at).0);
    std::fs::write(at.join("ca.pub"), ed25519(&ca).line("ca@acme")).unwrap();
    let (ok, out) = keygen(&["-l", "-f", "ca.pub"], &at);
    assert!(ok && out.contains(&ed25519(&ca).fingerprint()), "{out}");
}

// OP-156 m.3 (o)
#[test]
fn ssh_keygen_finds_revoked_certificates_in_our_krl() {
    let at = dir("krl");
    let (ca, _) = SoftSigner::generate_ed25519().unwrap();
    let (old, _) = SoftSigner::generate_ed25519().unwrap();
    let (user, _) = SoftSigner::generate_ed25519().unwrap();
    std::fs::write(
        at.join("revoked-cert.pub"),
        certificate(&ca, ed25519(&user), 7),
    )
    .unwrap();
    std::fs::write(
        at.join("live-cert.pub"),
        certificate(&ca, ed25519(&user), 8),
    )
    .unwrap();
    std::fs::write(
        at.join("old-cert.pub"),
        certificate(&old, ed25519(&user), 8),
    )
    .unwrap();
    let krl = Krl {
        version: 3,
        generated: 1_767_225_000,
        serials: BTreeMap::from([(ed25519(&ca), BTreeSet::from([7, 99]))]),
        keys: BTreeSet::from([ed25519(&old)]),
    };
    std::fs::write(at.join("krl"), krl.encode().unwrap()).unwrap();
    let (ok, out) = keygen(&["-Q", "-f", "krl", "revoked-cert.pub"], &at);
    assert!(!ok && out.contains("REVOKED"), "{out}");
    let (ok, out) = keygen(&["-Q", "-f", "krl", "live-cert.pub"], &at);
    assert!(ok && out.contains("ok"), "{out}");
    let (ok, out) = keygen(&["-Q", "-f", "krl", "old-cert.pub"], &at);
    assert!(!ok && out.contains("REVOKED"), "{out}");
    let (ok, out) = keygen(&["-Q", "-l", "-f", "krl"], &at);
    assert!(
        ok && out.contains("serial: 7") && out.contains("serial: 99"),
        "{out}"
    );
}
