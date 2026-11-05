//! Access identity signer (CMP-22b, OP-143 m.9 (e)). Thin by design: it reads configuration,
//! opens the KEK, locks itself down and serves the identity signer crate over a Unix socket
//! (OP-62). Its key store is its own, never the authority signer's.

mod config;

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_crypto::secret_file::SecretFile;
use access_identity_signer::adapters::{DirVault, SealedFactory, draw, now_ms, serve};
use access_identity_signer::service::Service;
use config::Config;
use suiss_crypto::pkcs11::{HsmError, KeyStore};
use suiss_crypto::rotation::Policy;
use suiss_sandbox::{LandlockAbi, Lockdown, Profile};

/// OP-129 m.3: the PIN and the token are opened before the lockdown.
fn open_kek(hsm: &config::Hsm) -> Result<suiss_crypto::pkcs11::HsmKek, String> {
    let pin = SecretFile::load(&hsm.pin_file).map_err(|e| e.to_string())?;
    let store = KeyStore::open(&hsm.module, &hsm.token, pin.value()).map_err(|e| e.to_string())?;
    store.kek(&hsm.kek).map_err(|e| e.to_string())
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
    if let Err(error) = access_telemetry::init(&config.log) {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("access-identity-signer: {error}");
        }
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
    let kek = match open_kek(hsm) {
        Ok(kek) => kek,
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
    if let Err(error) = locked.narrow() {
        tracing::error!(%error, "seccomp phase 2 failed; refusing to continue");
        return ExitCode::FAILURE;
    }
    let service = match Service::start(
        SealedFactory::new(kek),
        DirVault::new(&config.vault),
        Policy::REALM,
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
                let troubled = ticking
                    .lock()
                    .map(|mut s| s.tick(now_ms(), draw()))
                    .unwrap_or_default();
                if !troubled.is_empty() {
                    tracing::warn!(
                        realms = troubled.len(),
                        "realm key schedule round failed (CR-23)"
                    );
                }
            }
        });
        let listener = tokio::net::UnixListener::from_std(listener)?;
        serve(listener, service, config.callers.clone(), now_ms).await
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "identity signer stopped with an error");
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
        let out = std::process::Command::new("softhsm2-util")
            .args(["--init-token", "--free", "--label", &label])
            .args(["--pin", "1234-test-only", "--so-pin", "5678-test-only"])
            .output()
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
