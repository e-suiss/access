//! `access-linuxd`: the Access Linux client daemon (OP-156 m.3 (p), B21). It reaches Access only
//! over the realm's public listener with the host's client certificate and answers the NSS and
//! PAM modules on its socket.
//!
//! Configuration (environment, from the systemd unit's `EnvironmentFile`):
//! - `ACCESS_LINUXD_ISSUER`: the realm's issuer, `https://host[:port][/realms/slug]`.
//! - `ACCESS_LINUXD_CLIENT_ID`: the realm's public client with the device grant.
//! - `ACCESS_LINUXD_CA`, `ACCESS_LINUXD_CERT`, `ACCESS_LINUXD_KEY`: PEM files of the roots
//!   Access chains to, the host's client certificate chain (its `x5t#S256` is what
//!   `idp.linux.host_register` names) and its key.
//! - `ACCESS_LINUXD_SOCKET`: the socket, default `/run/access-linuxd/socket`.
//! - `ACCESS_LINUXD_STATE`: the state directory, default `/var/lib/access-linuxd`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use access_linux_client::adapters::https::AccessHttps;
use access_linux_client::adapters::local::{OsRandom, StateFile, SystemClock, bind, serve};
use access_linux_client::app::{Daemon, Note};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// How often the snapshot is refreshed while Access answers.
const REFRESH: Duration = Duration::from_secs(300);

#[derive(Debug, thiserror::Error)]
enum Startup {
    #[error("missing or invalid {0}")]
    Config(&'static str),
    #[error("{0}")]
    Setup(#[from] access_linux_client::adapters::https::Setup),
    #[error("socket: {0}")]
    Io(#[from] std::io::Error),
}

fn var(name: &'static str) -> Result<String, Startup> {
    std::env::var(name).map_err(|_| Startup::Config(name))
}

fn access() -> Result<AccessHttps, Startup> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(var("ACCESS_LINUXD_CA")?)
        .map_err(|_| Startup::Config("ACCESS_LINUXD_CA"))?
    {
        roots
            .add(c.map_err(|_| Startup::Config("ACCESS_LINUXD_CA"))?)
            .map_err(|_| Startup::Config("ACCESS_LINUXD_CA"))?;
    }
    let chain = CertificateDer::pem_file_iter(var("ACCESS_LINUXD_CERT")?)
        .map_err(|_| Startup::Config("ACCESS_LINUXD_CERT"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Startup::Config("ACCESS_LINUXD_CERT"))?;
    let key = PrivateKeyDer::from_pem_file(var("ACCESS_LINUXD_KEY")?)
        .map_err(|_| Startup::Config("ACCESS_LINUXD_KEY"))?;
    Ok(AccessHttps::new(
        roots,
        chain,
        key,
        &var("ACCESS_LINUXD_ISSUER")?,
        &var("ACCESS_LINUXD_CLIENT_ID")?,
    )?)
}

#[cfg(target_os = "linux")]
fn key() -> access_linux_client::adapters::hidraw::Hidraw {
    access_linux_client::adapters::hidraw::Hidraw::default()
}

#[cfg(not(target_os = "linux"))]
const fn key() -> access_linux_client::adapters::local::NoKey {
    access_linux_client::adapters::local::NoKey
}

async fn run() -> Result<(), Startup> {
    let socket = std::env::var("ACCESS_LINUXD_SOCKET").map_or_else(
        |_| PathBuf::from(access_linux_module::client::SOCKET),
        PathBuf::from,
    );
    let state = std::env::var("ACCESS_LINUXD_STATE")
        .map_or_else(|_| PathBuf::from("/var/lib/access-linuxd"), PathBuf::from);
    let daemon = Arc::new(Daemon::new(
        access()?,
        SystemClock,
        OsRandom,
        StateFile(state.join("state.json")),
        key(),
        Some(state.join("break-glass")),
    ));
    let listener = bind(&socket)?;
    let refresher = Arc::clone(&daemon);
    tokio::spawn(async move {
        loop {
            if refresher.refresh().await == Note::Unreachable {
                tracing::warn!(
                    event = "linux.daemon.unavailable",
                    error = "access",
                    "Access could not be reached"
                );
            }
            tokio::time::sleep(REFRESH).await;
        }
    });
    serve(daemon, listener, 0).await;
    Ok(())
}

fn main() -> ExitCode {
    tracing_subscriber::fmt().json().init();
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    match rt.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "access-linuxd could not start");
            ExitCode::FAILURE
        }
    }
}
