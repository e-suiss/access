//! Access identity signer (CMP-22b, OP-143 m.9 (e)). Thin by design: it reads configuration,
//! opens the KEK, locks itself down and serves the identity signer crate over a Unix socket
//! (OP-62). Its key store is its own, never the authority signer's.

mod config;

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_crypto::secret_file::SecretFile;
use access_identity_signer::adapters::{DirVault, SealedFactory, draw, now_ms, serve_until};
use access_identity_signer::kat::SelfTestError;
use access_identity_signer::service::Service;
use config::Config;
use suiss_crypto::pkcs11::{HsmError, KeyStore};
use suiss_crypto::rotation::Policy;
use suiss_sandbox::{LandlockAbi, Lockdown, Profile};

/// OP-129 m.3: the PIN and the token are opened before the lockdown. The store is kept for
/// the orderly shutdown (OP-94).
fn open_kek(hsm: &config::Hsm) -> Result<(KeyStore, suiss_crypto::pkcs11::HsmKek), String> {
    let pin = SecretFile::load(&hsm.pin_file).map_err(|e| e.to_string())?;
    let store = KeyStore::open(&hsm.module, &hsm.token, pin.value()).map_err(|e| e.to_string())?;
    let kek = store.kek(&hsm.kek).map_err(|e| e.to_string())?;
    Ok((store, kek))
}

/// `SIGTERM` or `SIGINT`, registered before seccomp phase 2 (OP-94).
fn stop_signal() -> std::io::Result<impl std::future::Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = interrupt.recv() => {}
        }
    })
}

/// OP-94, OP-158 m.3 (y): the last steps of the shutdown, once the socket stopped accepting
/// and the requests in flight finished: drop the service, which drops every key handle and
/// closes its session, then `C_Finalize`.
fn close_token(service: Arc<Mutex<Signer>>, store: KeyStore) -> bool {
    drop(service);
    match store.finalize() {
        Ok(()) => {
            tracing::info!("identity signer stopped; HSM sessions closed and the module finalized");
            true
        }
        Err(error) => {
            tracing::error!(%error, code = error.code(), "HSM not finalized at shutdown");
            false
        }
    }
}

/// SA-22, CR-21 m.2: no network, only the vault and the token's files.
fn lockdown(config: &Config, hsm: &config::Hsm) -> Lockdown {
    let mut lockdown =
        Lockdown::new(Profile::Signer, LandlockAbi::REQUIRED).allow_read_write(&config.vault);
    for path in &hsm.paths {
        lockdown = lockdown.allow_read_write(path);
    }
    lockdown
}

fn configured() -> Option<Config> {
    if unsafe_host() {
        return None;
    }
    let config = match Config::load() {
        Ok(config) => config,
        Err(error) => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("access-identity-signer: invalid configuration: {error}");
            }
            return None;
        }
    };
    // OP-67, CR-51
    let telemetry = access_telemetry::Config {
        service: "access-identity-signer",
        version: env!("CARGO_PKG_VERSION"),
        ..access_telemetry::Config::local(&config.log)
    };
    if let Err(error) = access_telemetry::install(&telemetry, std::io::stdout) {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("access-identity-signer: {error}");
        }
        return None;
    }
    // CMP-22b, OP-143 m.14 (a), SAI-45
    if !self_tested(access_identity_signer::kat::run) {
        return None;
    }
    Some(config)
}

/// Whether the start-up self-tests passed; a failure is logged with its code and the signer
/// does not start.
fn self_tested(test: impl FnOnce() -> Result<(), SelfTestError>) -> bool {
    match test() {
        Ok(()) => true,
        Err(error) => {
            tracing::error!(
                code = error.code(),
                "known-answer test failed; refusing to start"
            );
            false
        }
    }
}

/// Makes the KEK labelled `label` in the token when it is missing; a KEK that exists is kept.
/// True when it was made.
fn ensure_kek(store: &KeyStore, label: &str) -> Result<bool, HsmError> {
    if store.kek(label).is_ok() {
        return Ok(false);
    }
    store.generate_kek(label).map(|_| true)
}

/// CR-21, OP-69: `init` provisions the token for this signer and exits. It runs before the
/// signer, which still refuses to start without its KEK; on a production HSM the KEK comes
/// from the key ceremony instead.
fn init(config: &Config, hsm: &config::Hsm) -> ExitCode {
    let opened = SecretFile::load(&hsm.pin_file)
        .map_err(|e| e.to_string())
        .and_then(|pin| {
            KeyStore::open(&hsm.module, &hsm.token, pin.value()).map_err(|e| e.to_string())
        });
    let store = match opened {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "HSM unusable (CR-21)");
            return ExitCode::FAILURE;
        }
    };
    let locked = match lockdown(config, hsm).apply() {
        Ok(locked) => locked,
        Err(error) => {
            tracing::error!(%error, "runtime lockdown failed; refusing to start (OP-90)");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = locked.narrow() {
        tracing::error!(%error, "seccomp phase 2 failed; refusing to continue");
        return ExitCode::FAILURE;
    }
    match ensure_kek(&store, &hsm.kek) {
        Ok(made) => {
            tracing::info!(made, kek = %hsm.kek, "token provisioned");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(%error, "KEK not made (CR-21)");
            ExitCode::FAILURE
        }
    }
}

type Signer = Service<SealedFactory<suiss_crypto::pkcs11::HsmKek>, DirVault>;

/// The service with every realm restored and the cell's `audit-checkpoint` key open (CR-23,
/// OP-150 m.3 (h)).
fn start(config: &Config, kek: suiss_crypto::pkcs11::HsmKek) -> Option<Signer> {
    let mut service = match Service::start(
        SealedFactory::new(kek),
        DirVault::new(&config.vault),
        Policy::REALM,
    ) {
        Ok(service) => service,
        Err(error) => {
            tracing::error!(%error, "vault unreadable; refusing to start (CR-23)");
            return None;
        }
    };
    if let Err(error) = service.open_cell(&config.cell) {
        tracing::error!(%error, "audit-checkpoint key unusable; refusing to start (OP-150)");
        return None;
    }
    Some(service)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
        out
    })
}

/// CR-23, CR-27: each realm key transition is logged as an audit event; a rotation the round
/// could not make raises the rotation delay alarm.
fn audit(report: &access_identity_signer::service::Report) {
    for (realm, step) in &report.transitions {
        tracing::info!(
            event = "key.rotation",
            step = step.name(),
            realm = hex(&realm.0),
            kid = step.kid().map(|k| hex(k)).unwrap_or_default(),
        );
    }
    // §10.1.7, OP-157 m.3 (x)
    for (realm, kid) in report.rotated() {
        tracing::info!(
            event = "signer.rotated",
            realm = hex(&realm.0),
            kid = hex(kid),
            trigger = "schedule",
            "a scheduled rotation made a new signing key; no Exercise"
        );
    }
    for (realm, late_ms) in &report.delayed {
        tracing::error!(
            event = "key.rotation.delayed",
            realm = hex(&realm.0),
            late_ms,
            "realm key rotation delayed (CR-23)"
        );
    }
    if !report.troubled.is_empty() {
        tracing::warn!(
            realms = report.troubled.len(),
            "realm key schedule round failed (CR-23)"
        );
    }
}

/// CR-39, OP-150 (o): a production signer does not start on `aarch64-apple-*`.
fn unsafe_host() -> bool {
    access_crypto::platform::signer_host(access_crypto::platform::Target::BUILT)
        .map_err(|error| {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("access-identity-signer: {error}; refusing to start");
            }
        })
        .is_err()
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let provision = match args.as_slice() {
        [] => false,
        [a] if a == "init" => true,
        _ => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("usage: access-identity-signer [init]");
            }
            return ExitCode::FAILURE;
        }
    };
    let Some(config) = configured() else {
        return ExitCode::FAILURE;
    };
    let Some(hsm) = &config.hsm else {
        return ExitCode::FAILURE;
    };
    if provision {
        return init(&config, hsm);
    }
    let (store, kek) = match open_kek(hsm) {
        Ok(opened) => opened,
        Err(error) => {
            tracing::error!(%error, "KEK unusable; refusing to start (CR-21)");
            return ExitCode::FAILURE;
        }
    };
    let _ = std::fs::remove_file(&config.socket);
    let listener = match std::os::unix::net::UnixListener::bind(&config.socket) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(%error, socket = %config.socket.display(), "cannot bind the socket");
            return ExitCode::FAILURE;
        }
    };
    let locked = match lockdown(&config, hsm).apply() {
        Ok(locked) => locked,
        Err(error) => {
            tracing::error!(%error, "runtime lockdown failed; refusing to start (OP-90)");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "cannot start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    let stop = {
        let _entered = runtime.enter();
        match stop_signal() {
            Ok(stop) => stop,
            Err(error) => {
                tracing::error!(%error, "cannot watch for the stop signal");
                return ExitCode::FAILURE;
            }
        }
    };
    if let Err(error) = locked.narrow() {
        tracing::error!(%error, "seccomp phase 2 failed; refusing to continue");
        return ExitCode::FAILURE;
    }
    let Some(service) = start(&config, kek) else {
        return ExitCode::FAILURE;
    };
    let service = Arc::new(Mutex::new(service));
    let result = runtime.block_on(run(&config, Arc::clone(&service), listener, stop));
    drop(runtime);
    let closed = close_token(service, store);
    match result {
        Ok(()) if closed => ExitCode::SUCCESS,
        Ok(()) => ExitCode::FAILURE,
        Err(error) => {
            tracing::error!(%error, "identity signer stopped with an error");
            ExitCode::FAILURE
        }
    }
}

/// CR-28: the key schedule rounds and the socket until `stop`; the rounds end after the one
/// in progress.
async fn run(
    config: &Config,
    service: Arc<Mutex<Signer>>,
    listener: std::os::unix::net::UnixListener,
    stop: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    let ticking = Arc::clone(&service);
    let every = Duration::from_secs(config.tick_seconds);
    let (stopped, mut halted) = tokio::sync::watch::channel(false);
    let rounds = tokio::spawn(async move {
        let mut interval = tokio::time::interval(every);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = halted.changed() => break,
            }
            let service = Arc::clone(&ticking);
            // CR-28
            let report = tokio::task::spawn_blocking(move || {
                service
                    .lock()
                    .map(|mut s| s.round(now_ms(), draw()))
                    .unwrap_or_default()
            })
            .await
            .unwrap_or_default();
            audit(&report);
        }
    });
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let served = serve_until(listener, service, config.callers.clone(), now_ms, stop).await;
    let _ = stopped.send(true);
    let _ = rounds.await;
    served
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use access_crypto::Secret;

    use super::*;

    /// A fresh token in this test process's own `SoftHSM` store (`SOFTHSM2_CONF`, OP-69). Its
    /// handle is never dropped: unloading `SoftHSM` after it used OpenSSL leaves OpenSSL's exit
    /// handler behind in some hosts' loaders, and the test process then crashes at exit.
    fn token() -> &'static KeyStore {
        assert!(
            std::env::var_os("SOFTHSM2_CONF").is_some(),
            "run the PKCS#11 tests through `just test`, which sets SOFTHSM2_CONF (OP-69)"
        );
        let module = [
            std::env::var("SUISS_PKCS11_MODULE").unwrap_or_default(),
            String::from("/opt/homebrew/lib/softhsm/libsofthsm2.so"),
            String::from("/usr/lib/softhsm/libsofthsm2.so"),
            String::from("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
            String::from("/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so"),
        ]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.is_file())
        .unwrap();
        let label = format!("kek-init-{}", std::process::id());
        let out = suiss_crypto::pkcs11::token_tests::init_softhsm_token(
            None,
            &label,
            "1234-test-only",
            "5678-test-only",
        )
        .unwrap();
        assert!(out.status.success(), "{out:?}");
        Box::leak(Box::new(
            KeyStore::open(
                &module,
                &label,
                &Secret::new(String::from("1234-test-only")),
            )
            .unwrap(),
        ))
    }

    // CMP-22b, SAI-45, OP-143
    #[test]
    fn a_failed_self_test_refuses_to_start() {
        assert!(self_tested(|| Ok(())));
        assert!(!self_tested(|| Err(SelfTestError::Rsa)));
        assert!(!self_tested(|| Err(SelfTestError::Known(
            access_identity_signer::kat::KatError::Ed25519
        ))));
        assert!(self_tested(access_identity_signer::kat::run));
    }

    // CR-21, OP-69
    #[test]
    fn init_makes_the_kek_once() {
        let store = token();
        assert!(store.kek("access/test/kek").is_err());
        assert!(ensure_kek(store, "access/test/kek").unwrap());
        assert!(!ensure_kek(store, "access/test/kek").unwrap());
        assert!(store.kek("access/test/kek").is_ok());
    }
}
