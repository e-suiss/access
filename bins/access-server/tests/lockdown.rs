//! OP-90: the server refuses to start when the runtime lockdown (SA-22) cannot be applied.

#![allow(
    clippy::expect_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

const PIN: &str = "1234-test-only";

/// `SoftHSM` (OP-69): `SUISS_PKCS11_MODULE`, or the usual install paths.
fn module() -> PathBuf {
    [
        std::env::var("SUISS_PKCS11_MODULE").unwrap_or_default(),
        String::from("/opt/homebrew/lib/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so"),
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
    .expect("SoftHSM is required (OP-69); set SUISS_PKCS11_MODULE")
}

/// A fresh token in a `SoftHSM` store of its own under `dir`, so that it never races the other
/// PKCS#11 tests' store; returns the token label and the configuration path (OP-69).
fn token(dir: &std::path::Path) -> (String, PathBuf) {
    let tokens = dir.join("tokens");
    std::fs::create_dir_all(&tokens).expect("token dir");
    let conf = dir.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )
    .expect("softhsm config");
    let label = format!("server-lockdown-{}", std::process::id());
    let out = Command::new("softhsm2-util")
        .env("SOFTHSM2_CONF", &conf)
        .args(["--init-token", "--free", "--label", &label, "--pin", PIN])
        .args(["--so-pin", "5678-test-only"])
        .output()
        .expect("softhsm2-util");
    assert!(out.status.success(), "{out:?}");
    (label, conf)
}

/// True when this host could apply the lockdown (Linux with an empty capability bounding
/// set, e.g. a container with `--cap-drop ALL`); the refusal path is then not reachable.
fn lockdown_possible() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|l| l.strip_prefix("CapBnd:").map(|v| v.trim().to_owned()))
        })
        .is_some_and(|bounding| bounding.trim_start_matches('0').is_empty())
}

#[test]
fn op_90_server_refuses_to_start_without_lockdown() {
    if lockdown_possible() {
        return;
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_access-server"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("ACCESS_") {
            command.env_remove(key);
        }
    }
    // CR-12, OP-141 m.18: the server reads its TLS files, credentials and token before it
    // reaches the lockdown
    let dir = std::env::temp_dir().join(format!("access-server-lockdown-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
    std::fs::write(dir.join("tls.crt"), cert.cert.pem()).expect("write cert");
    std::fs::write(dir.join("tls.key"), cert.signing_key.serialize_pem()).expect("write key");
    for secret in ["db-password", "pin"] {
        let value = if secret == "pin" { PIN } else { "x" };
        std::fs::write(dir.join(secret), value).expect("write secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir.join(secret), std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
        }
    }
    let (token, softhsm) = token(&dir);
    let config = dir.join("access.toml");
    std::fs::write(
        &config,
        format!(
            "issuer = \"https://access.example\"\n\
             [tls]\ncert_file = {crt:?}\nkey_file = {key:?}\n\
             [database]\nhost = \"localhost\"\nport = 5432\nname = \"access\"\n\
             root_cert_file = {crt:?}\ndurability = \"single-node\"\n\
             sequencer = {{ user = \"s\", password_file = {pw:?}, pool = 1 }}\n\
             app = {{ user = \"a\", password_file = {pw:?}, pool = 1 }}\n\
             deriver = {{ user = \"d\", password_file = {pw:?}, pool = 1 }}\n\
             [hsm]\nmodule = {module:?}\ntoken = {token:?}\npin_file = {pin:?}\n",
            crt = dir.join("tls.crt"),
            key = dir.join("tls.key"),
            pw = dir.join("db-password"),
            module = module(),
            pin = dir.join("pin"),
        ),
    )
    .expect("write config");
    let mut child = command
        .env("ACCESS_LISTEN", "127.0.0.1:0")
        .env("ACCESS_CONFIG", &config)
        .env("SOFTHSM2_CONF", &softhsm)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn access-server");
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("access-server kept running without a lockdown (OP-90)");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let output = child.wait_with_output().expect("output");
    let logs = String::from_utf8_lossy(&output.stdout);
    let errors = String::from_utf8_lossy(&output.stderr);
    assert!(!status.success(), "exit status: {status}");
    assert!(
        logs.contains("runtime lockdown failed; refusing to start"),
        "logs: {logs}\nstderr: {errors}"
    );
}
