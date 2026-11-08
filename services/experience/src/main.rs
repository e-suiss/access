//! `access-experience`: the experience backend as its own process (CMP-16). It reaches Access
//! only over Access's public listener with its client certificate; stopping it leaves every
//! authority read and write of Access as it was (OP-153 m.3 (v)).
//!
//! Configuration (environment):
//! - `ACCESS_EXPERIENCE_LISTEN`: the address to serve on, e.g. `127.0.0.1:8480`.
//! - `ACCESS_EXPERIENCE_UPSTREAM`: Access's public origin, `https://host[:port]`.
//! - `ACCESS_EXPERIENCE_ROUTES`: optional `DomainID=https://host[:port]` pairs, comma separated,
//!   for domains served by another Access.
//! - `ACCESS_EXPERIENCE_CA`, `ACCESS_EXPERIENCE_CERT`, `ACCESS_EXPERIENCE_KEY`: PEM files of the
//!   trusted roots, this service's certificate chain and its key.

use std::collections::BTreeMap;
use std::process::ExitCode;

use access_experience::adapters::{Beacon, router};
use access_experience::app::Experience;
use access_experience::https::{Endpoint, Https, pep_name};
use access_experience::ports::{Clock, Random};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or(0)
    }
}

struct SystemRandom(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl Random for SystemRandom {
    fn nonce(&self) -> Option<[u8; 16]> {
        let mut out = [0u8; 16];
        self.0.secure_random.fill(&mut out).ok()?;
        Some(out)
    }
}

/// Why the process could not start.
#[derive(Debug, thiserror::Error)]
enum Startup {
    #[error("missing or invalid {0}")]
    Config(&'static str),
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("listen: {0}")]
    Io(#[from] std::io::Error),
}

fn var(name: &'static str) -> Result<String, Startup> {
    std::env::var(name).map_err(|_| Startup::Config(name))
}

fn routes(text: &str) -> Result<BTreeMap<String, Endpoint>, Startup> {
    text.split(',')
        .filter(|p| !p.trim().is_empty())
        .map(|pair| {
            let (d, url) = pair
                .split_once('=')
                .ok_or(Startup::Config("ACCESS_EXPERIENCE_ROUTES"))?;
            let at =
                Endpoint::parse(url.trim()).ok_or(Startup::Config("ACCESS_EXPERIENCE_ROUTES"))?;
            Ok((d.trim().to_owned(), at))
        })
        .collect()
}

async fn run() -> Result<(), Startup> {
    let listen = var("ACCESS_EXPERIENCE_LISTEN")?;
    let default = Endpoint::parse(&var("ACCESS_EXPERIENCE_UPSTREAM")?)
        .ok_or(Startup::Config("ACCESS_EXPERIENCE_UPSTREAM"))?;
    let routes = routes(&std::env::var("ACCESS_EXPERIENCE_ROUTES").unwrap_or_default())?;
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(var("ACCESS_EXPERIENCE_CA")?)
        .map_err(|_| Startup::Config("ACCESS_EXPERIENCE_CA"))?
    {
        roots
            .add(c.map_err(|_| Startup::Config("ACCESS_EXPERIENCE_CA"))?)
            .map_err(|_| Startup::Config("ACCESS_EXPERIENCE_CA"))?;
    }
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(var("ACCESS_EXPERIENCE_CERT")?)
            .map_err(|_| Startup::Config("ACCESS_EXPERIENCE_CERT"))?
            .collect::<Result<_, _>>()
            .map_err(|_| Startup::Config("ACCESS_EXPERIENCE_CERT"))?;
    let pep = pep_name(
        chain
            .first()
            .ok_or(Startup::Config("ACCESS_EXPERIENCE_CERT"))?,
    );
    let key = PrivateKeyDer::from_pem_file(var("ACCESS_EXPERIENCE_KEY")?)
        .map_err(|_| Startup::Config("ACCESS_EXPERIENCE_KEY"))?;
    let upstream = Https::new(roots, chain, key, default, routes)?;
    let experience = Experience::new(
        upstream,
        SystemClock,
        SystemRandom(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        )),
        pep,
    );
    let app = router(experience, Beacon::default());
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // OP-67
    tracing_subscriber::fmt().json().init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "access-experience did not start");
            ExitCode::FAILURE
        }
    }
}
