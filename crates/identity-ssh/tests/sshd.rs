//! A real OpenSSH `sshd` against our certificates and KRL (OP-156 m.3 (o), m.5): the server
//! trusts the CA key and reads the KRL; a certificate for the running user signs in, the same
//! certificate is refused once its serial is in the KRL, and a certificate naming another
//! principal is refused. `sshd` runs unprivileged on a loopback port, so only the running user
//! can sign in. Linux CI runs it (`--run-ignored only`); it needs `sshd`, `ssh` and `ssh-keygen`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use access_identity_ssh::domain::cert::{Extension, Fields};
use access_identity_ssh::domain::holder::private_key_file;
use access_identity_ssh::domain::key::Ed25519Public;
use access_identity_ssh::domain::krl::Krl;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::signer::{Signer, SoftSigner};

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0_u8; N];
    aws_lc_rs::rand::fill(&mut out).unwrap();
    out
}

fn ed25519(s: &SoftSigner) -> Ed25519Public {
    match s.public_key() {
        PublicKey::Ed25519(k) => Ed25519Public(k),
        other => panic!("{other:?}"),
    }
}

fn user_key() -> ([u8; 32], Ed25519Public) {
    use aws_lc_rs::signature::KeyPair as _;
    let seed: [u8; 32] = random();
    let pair = aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    (
        seed,
        Ed25519Public(<[u8; 32]>::try_from(pair.public_key().as_ref()).unwrap()),
    )
}

fn sshd_binary() -> PathBuf {
    ["/usr/sbin/sshd", "/usr/local/sbin/sshd"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .expect("sshd is installed")
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn certificate(ca: &SoftSigner, key: Ed25519Public, serial: u64, principal: &str) -> String {
    let fields = Fields {
        nonce: random(),
        key,
        serial,
        key_id: String::from("prj_sshd"),
        principals: BTreeSet::from([String::from(principal)]),
        valid_after: now_s() - 60,
        valid_before: now_s() + 600,
        force_command: None,
        source_address: BTreeSet::from([String::from("127.0.0.1/32")]),
        extensions: BTreeSet::from([Extension::Pty]),
        ca: ed25519(ca),
    };
    let tbs = fields.to_be_signed().unwrap();
    let sig = <[u8; 64]>::try_from(ca.sign(&tbs).unwrap().as_slice()).unwrap();
    fields.certificate(&sig).unwrap().line("sshd-test")
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(dir: &Path, port: u16) -> Server {
    let host = dir.join("host_key");
    let made = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host)
        .status()
        .unwrap();
    assert!(made.success());
    let config = format!(
        "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nStrictModes no\n\
         PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\n\
         AuthorizedKeysFile none\nTrustedUserCAKeys {}\nRevokedKeys {}\nUsePAM no\nLogLevel VERBOSE\n",
        host.display(),
        dir.join("sshd.pid").display(),
        dir.join("ca.pub").display(),
        dir.join("krl").display(),
    );
    std::fs::write(dir.join("sshd_config"), config).unwrap();
    let child = Command::new(sshd_binary())
        .args(["-D", "-e", "-f"])
        .arg(dir.join("sshd_config"))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(dir.join("sshd.log")).unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "sshd did not listen");
        std::thread::sleep(Duration::from_millis(50));
    }
    Server(child)
}

fn ssh(dir: &Path, port: u16, user: &str) -> bool {
    let mut child = Command::new("ssh")
        .args([
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "ConnectTimeout=10",
        ])
        .arg("-i")
        .arg(dir.join("id"))
        .arg("-o")
        .arg(format!(
            "CertificateFile={}",
            dir.join("id-cert.pub").display()
        ))
        .args(["-p", &port.to_string()])
        .arg(format!("{user}@127.0.0.1"))
        .arg("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.success();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// OP-156 m.3 (o), m.5, IDP-32
#[test]
#[ignore = "needs sshd; Linux CI runs it with --run-ignored only"]
fn sshd_accepts_our_certificate_and_refuses_it_once_revoked() {
    let user = std::env::var("USER").expect("USER is set");
    let dir = std::env::temp_dir().join(format!("access-sshd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (ca, _) = SoftSigner::generate_ed25519().unwrap();
    std::fs::write(
        dir.join("ca.pub"),
        ed25519(&ca).line("access-ca@test") + "\n",
    )
    .unwrap();
    let empty = Krl {
        version: 1,
        generated: now_s(),
        ..Krl::default()
    };
    std::fs::write(dir.join("krl"), empty.encode().unwrap()).unwrap();
    let (seed, key) = user_key();
    let check = u32::from_be_bytes(random());
    std::fs::write(
        dir.join("id"),
        private_key_file(&seed, &key, "u", check).unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(dir.join("id"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(dir.join("id-cert.pub"), certificate(&ca, key, 4242, &user)).unwrap();
    let port = free_port();
    let server = start(&dir, port);

    let accepted = ssh(&dir, port, &user);
    let log = std::fs::read_to_string(dir.join("sshd.log")).unwrap_or_default();
    assert!(accepted, "{log}");

    std::fs::write(
        dir.join("id-cert.pub"),
        certificate(&ca, key, 4243, "someone-else"),
    )
    .unwrap();
    assert!(!ssh(&dir, port, &user));

    std::fs::write(dir.join("id-cert.pub"), certificate(&ca, key, 4242, &user)).unwrap();
    let revoked = Krl {
        version: 2,
        generated: now_s(),
        serials: BTreeMap::from([(ed25519(&ca), BTreeSet::from([4242]))]),
        keys: BTreeSet::new(),
    };
    std::fs::write(dir.join("krl"), revoked.encode().unwrap()).unwrap();
    assert!(!ssh(&dir, port, &user));
    let log = std::fs::read_to_string(dir.join("sshd.log")).unwrap_or_default();
    assert!(log.contains("revoked"), "{log}");
    drop(server);
}
