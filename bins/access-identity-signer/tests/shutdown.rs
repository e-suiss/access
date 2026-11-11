//! OP-94, OP-158 m.3 (y), SAI-45: the identity signer process on a `SoftHSM` token stops in
//! order on `SIGTERM` (stop accepting, finish in flight, drop the keys, close the sessions,
//! `C_Finalize`) and exits cleanly. Linux only: the signer's lockdown needs Landlock and seccomp.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use access_identity_signer::adapters::call;
use access_identity_signer::protocol::{Request, Response};

const PIN: &str = "1234-test-only";

fn module() -> PathBuf {
    [
        std::env::var("SUISS_PKCS11_MODULE").unwrap_or_default(),
        String::from("/usr/lib/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so"),
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
    .unwrap()
}

fn tokens_dir() -> PathBuf {
    let conf = std::fs::read_to_string(std::env::var_os("SOFTHSM2_CONF").unwrap()).unwrap();
    conf.lines()
        .find_map(|l| l.trim().strip_prefix("directories.tokendir"))
        .map(|v| PathBuf::from(v.trim_start_matches([' ', '=']).trim()))
        .unwrap()
}

fn config(dir: &Path, token: &str) -> PathBuf {
    let pin = dir.join("pin");
    std::fs::write(&pin, PIN).unwrap();
    std::fs::set_permissions(&pin, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let vault = dir.join("vault");
    std::fs::create_dir_all(&vault).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(dir).unwrap());
    let path = dir.join("access-identity-signer.toml");
    std::fs::write(
        &path,
        format!(
            "socket = \"{socket}\"\nvault = \"{vault}\"\ncallers = [{uid}]\ncell = \"local\"\n\
             [hsm]\nmodule = \"{module}\"\ntoken = {token:?}\npin_file = \"{pin}\"\n\
             kek = \"access/identity-signer/kek\"\npaths = [\"{tokens}\"]\n",
            socket = dir.join("s.sock").display(),
            vault = vault.display(),
            module = module().display(),
            pin = pin.display(),
            tokens = tokens_dir().display(),
        ),
    )
    .unwrap();
    path
}

fn signer(config: &Path, args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_access-identity-signer"))
        .args(args)
        .env("ACCESS_IDENTITY_SIGNER_CONFIG", config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait(child: &mut Child, limit: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now().checked_add(limit).unwrap();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "the signer did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn output(child: &mut Child) -> String {
    let mut out = String::new();
    if let Some(mut s) = child.stdout.take() {
        s.read_to_string(&mut out).unwrap();
    }
    if let Some(mut s) = child.stderr.take() {
        s.read_to_string(&mut out).unwrap();
    }
    out
}

// OP-94, OP-158 m.3 (y), SAI-45
#[test]
#[ignore = "the signer applies its lockdown at start, which needs root: just test-signer-shutdown"]
fn sigterm_closes_the_token_in_order() {
    let dir = std::env::temp_dir().join(format!("ais-proc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let token = format!("ais-proc-{}", std::process::id());
    let init = Command::new("softhsm2-util")
        .args(["--init-token", "--free", "--label", &token])
        .args(["--pin", PIN, "--so-pin", "5678-test-only"])
        .output()
        .unwrap();
    assert!(init.status.success(), "{init:?}");
    let config = config(&dir, &token);
    let mut provision = signer(&config, &["init"]);
    let status = wait(&mut provision, Duration::from_secs(30));
    assert!(status.success(), "{}", output(&mut provision));

    let mut running = signer(&config, &[]);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let socket = dir.join("s.sock");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = running.try_wait().unwrap() {
            panic!("the signer exited: {status:?}\n{}", output(&mut running));
        }
        let pong = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), call(&socket, &Request::Ping)).await
        });
        if matches!(pong, Ok(Ok(Response::Pong))) {
            break;
        }
        assert!(Instant::now() < deadline, "the signer never answered");
        std::thread::sleep(Duration::from_millis(20));
    }
    let kill = Command::new("kill")
        .args(["-TERM", &running.id().to_string()])
        .status()
        .unwrap();
    assert!(kill.success());
    let status = wait(&mut running, Duration::from_secs(30));
    let log = output(&mut running);
    assert!(status.success(), "{status:?}\n{log}");
    assert!(log.contains("HSM sessions closed"), "{log}");
}
