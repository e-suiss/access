//! `access-executor`: the Access Executor as its own process (B21). It reaches Access only over
//! Access's public listener with its client certificate, keeps its job history in its own
//! database, and on start picks every open job up again, asking Access before its next effect.
//!
//! Configuration (environment):
//! - `ACCESS_EXECUTOR_LISTEN`: the address to serve on, e.g. `127.0.0.1:8490`.
//! - `ACCESS_EXECUTOR_ACCESS`: Access's public origin, `https://host[:port]`.
//! - `ACCESS_EXECUTOR_CA`, `ACCESS_EXECUTOR_CERT`, `ACCESS_EXECUTOR_KEY`: PEM files of the roots
//!   Access's certificate chains to, this executor's client certificate chain and its key; the
//!   certificate's `x5t#S256` is the PEP name a Resource lists.
//! - `ACCESS_EXECUTOR_UPSTREAM_CA`: PEM file of the roots upstream servers chain to.
//! - `ACCESS_EXECUTOR_DATABASE_URL`: the executor's own PostgreSQL database.
//! - `ACCESS_EXECUTOR_KIND`: `cloud`, `customer` or `local`.
//! - `ACCESS_EXECUTOR_OPERATOR`, `ACCESS_EXECUTOR_INSTANCE`: base64url ids of the operator
//!   Party and of the executor Instance whose key signs.
//! - `ACCESS_EXECUTOR_SIGNING_KEY`: PKCS#8 file of the executor Instance's Ed25519 key.
//! - `ACCESS_EXECUTOR_SIGNATURE_AGENT`: the Suiss Web Bot Auth directory URL.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use access_executor::adapters::router;
use access_executor::app::{Config, Executor, Tokens};
use access_executor::domain::Kind;
use access_executor::domain::attest::Reporter;
use access_executor::https::{AccessHttps, UpstreamHttps, pep_name};
use access_executor::ports::{Clock, Random};
use access_executor::store::Store;
use access_kernel::json::b64url_decode;
use access_kernel::model::Id;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::SoftSigner;

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Option<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
    }
}

struct SystemRandom(Arc<rustls::crypto::CryptoProvider>);

impl Random for SystemRandom {
    fn bytes(&self) -> Option<[u8; 16]> {
        let mut out = <[u8; 16]>::default();
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
    #[error("{0}")]
    Store(#[from] access_executor::store::StoreError),
}

fn var(name: &'static str) -> Result<String, Startup> {
    std::env::var(name).map_err(|_| Startup::Config(name))
}

fn roots(name: &'static str) -> Result<rustls::RootCertStore, Startup> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(var(name)?).map_err(|_| Startup::Config(name))? {
        roots
            .add(c.map_err(|_| Startup::Config(name))?)
            .map_err(|_| Startup::Config(name))?;
    }
    Ok(roots)
}

fn id(name: &'static str) -> Result<Id, Startup> {
    b64url_decode(&var(name)?)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .map(Id)
        .ok_or(Startup::Config(name))
}

async fn run() -> Result<(), Startup> {
    let listen = var("ACCESS_EXECUTOR_LISTEN")?;
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(var("ACCESS_EXECUTOR_CERT")?)
            .map_err(|_| Startup::Config("ACCESS_EXECUTOR_CERT"))?
            .collect::<Result<_, _>>()
            .map_err(|_| Startup::Config("ACCESS_EXECUTOR_CERT"))?;
    let pep = pep_name(
        chain
            .first()
            .ok_or(Startup::Config("ACCESS_EXECUTOR_CERT"))?,
    );
    let key = PrivateKeyDer::from_pem_file(var("ACCESS_EXECUTOR_KEY")?)
        .map_err(|_| Startup::Config("ACCESS_EXECUTOR_KEY"))?;
    let access = AccessHttps::new(
        roots("ACCESS_EXECUTOR_CA")?,
        chain,
        key,
        &var("ACCESS_EXECUTOR_ACCESS")?,
    )?;
    let upstream = UpstreamHttps::new(roots("ACCESS_EXECUTOR_UPSTREAM_CA")?)?;
    let kind = Kind::parse(&var("ACCESS_EXECUTOR_KIND")?)
        .ok_or(Startup::Config("ACCESS_EXECUTOR_KIND"))?;
    let pkcs8 = std::fs::read(var("ACCESS_EXECUTOR_SIGNING_KEY")?)
        .map_err(|_| Startup::Config("ACCESS_EXECUTOR_SIGNING_KEY"))?;
    let signer = SoftSigner::ed25519_from_pkcs8(&Secret::new(pkcs8))
        .map_err(|_| Startup::Config("ACCESS_EXECUTOR_SIGNING_KEY"))?;
    let store = Store::connect(&var("ACCESS_EXECUTOR_DATABASE_URL")?).await?;
    store.migrate().await?;
    let config = Config {
        pep,
        kind,
        reporter: Reporter {
            operator: id("ACCESS_EXECUTOR_OPERATOR")?,
            executor: id("ACCESS_EXECUTOR_INSTANCE")?,
        },
        signature_agent: var("ACCESS_EXECUTOR_SIGNATURE_AGENT")?,
    };
    let exec = Arc::new(Executor::new(
        (store, access, upstream),
        (
            SystemClock,
            SystemRandom(Arc::new(rustls::crypto::aws_lc_rs::default_provider())),
            signer,
        ),
        config,
        Arc::new(Tokens::default()),
    ));
    // §7.9.7.2
    for job in exec.open_jobs().await.unwrap_or_default() {
        if let Err(e) = exec.recover(job).await {
            tracing::warn!(error = %e, "a job was not picked up");
        }
    }
    let runner = Arc::clone(&exec);
    tokio::spawn(async move {
        loop {
            for job in runner.open_jobs().await.unwrap_or_default() {
                if let Err(e) = runner.drive(job).await {
                    tracing::warn!(code = e.code(), "a job waits");
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, router(exec)).await?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // OP-67
    tracing_subscriber::fmt().json().init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "access-executor did not start");
            ExitCode::FAILURE
        }
    }
}
