//! Access authority signer (CMP-22a, CR-21). Thin by design: it reads configuration, opens the
//! HSM, locks itself down and serves the signer crate over a Unix socket (OP-62).

mod config;

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_authority_signer::adapters::{DirVault, HsmBindings, SealedFactory, serve};
use access_authority_signer::service::Service;
use access_crypto::secret_file::SecretFile;
use config::Config;
use suiss_crypto::pkcs11::{HsmError, KeyStore};
use suiss_crypto::rotation::Policy;
use suiss_sandbox::{LandlockAbi, Lockdown, Profile};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn draw() -> u64 {
    access_crypto::random::bytes::<8>().map_or(0, u64::from_le_bytes)
}

/// OP-129 m.3: the PIN and the token are opened before the lockdown.
fn open_hsm(hsm: &config::Hsm) -> Result<(KeyStore, suiss_crypto::pkcs11::HsmKek), String> {
    let pin = SecretFile::load(&hsm.pin_file).map_err(|e| e.to_string())?;
    let store = KeyStore::open(&hsm.module, &hsm.token, pin.value()).map_err(|e| e.to_string())?;
    let kek = store.kek(&hsm.kek).map_err(|e| e.to_string())?;
    Ok((store, kek))
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

/// The configuration with telemetry installed, once the known-answer tests passed.
fn configured() -> Option<Config> {
    if unsafe_host() {
        return None;
    }
    let config = match Config::load() {
        Ok(config) => config,
        Err(error) => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("access-signer: invalid configuration: {error}");
            }
            return None;
        }
    };
    // OP-67: a signer logs; it opens no connection to export telemetry (CR-51)
    let telemetry = access_telemetry::Config {
        service: "access-signer",
        version: env!("CARGO_PKG_VERSION"),
        ..access_telemetry::Config::local(&config.log)
    };
    if let Err(error) = access_telemetry::install(&telemetry, std::io::stdout) {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("access-signer: {error}");
        }
        return None;
    }
    // CR-51 m.3
    if let Err(error) = access_authority_signer::kat::run() {
        tracing::error!(
            code = error.code(),
            "known-answer test failed; refusing to start"
        );
        return None;
    }
    Some(config)
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
        out
    })
}

/// CR-23, CR-27: each key transition goes to the OPERATIONAL audit stream; a rotation the
/// round could not make raises the rotation delay alarm.
fn audit(report: &access_authority_signer::service::Report) {
    for (domain, step) in &report.transitions {
        tracing::info!(
            event = "key.rotation",
            step = step.name(),
            domain = hex(&domain.0),
            kid = step.kid().map(|k| hex(k)).unwrap_or_default(),
        );
    }
    for (domain, late_ms) in &report.delayed {
        tracing::error!(
            event = "key.rotation.delayed",
            domain = hex(&domain.0),
            late_ms,
            "operational key rotation delayed (CR-23)"
        );
    }
    if !report.troubled.is_empty() {
        tracing::warn!(
            domains = report.troubled.len(),
            "key schedule round failed (CR-23)"
        );
    }
}

/// CR-39, OP-150 (o): a production signer does not start on `aarch64-apple-*`.
fn unsafe_host() -> bool {
    access_crypto::platform::signer_host(access_crypto::platform::Target::BUILT)
        .map_err(|error| {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("access-signer: {error}; refusing to start");
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
                eprintln!("usage: access-signer [init]");
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
    let opened = open_hsm(hsm);
    let (store, kek) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            tracing::error!(%error, "HSM unusable; refusing to start (CR-21)");
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
    if let Err(error) = locked.narrow() {
        tracing::error!(%error, "seccomp phase 2 failed; refusing to continue");
        return ExitCode::FAILURE;
    }
    let service = match Service::start(
        SealedFactory::new(kek),
        HsmBindings::new(store),
        DirVault::new(&config.vault),
        Policy::AUTHORITY,
        now_ms(),
    ) {
        Ok(service) => Arc::new(Mutex::new(service)),
        Err(error) => {
            tracing::error!(%error, "vault unreadable; refusing to start (CR-23)");
            return ExitCode::FAILURE;
        }
    };
    let ticking = Arc::clone(&service);
    let every = Duration::from_secs(config.tick_seconds);
    let result = runtime.block_on(async move {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(every);
            loop {
                interval.tick().await;
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
        serve(listener, service, config.callers.clone(), now_ms).await
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "signer stopped with an error");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use access_crypto::Secret;

    use super::*;

    /// A fresh token in the `SoftHSM` store `just test` prepares (`SOFTHSM2_CONF`, OP-69). Its
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

    // CR-21, OP-69: provisioning makes the KEK once and keeps it
    #[test]
    fn init_makes_the_kek_once() {
        let store = token();
        assert!(store.kek("access/test/kek").is_err());
        assert!(ensure_kek(store, "access/test/kek").unwrap());
        assert!(!ensure_kek(store, "access/test/kek").unwrap());
        assert!(store.kek("access/test/kek").is_ok());
    }
}
