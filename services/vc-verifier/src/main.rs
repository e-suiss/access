//! `access-vc-verifier`: the OID4VP verifier as its own process (OP-155 m.3 (p)). It reaches
//! Access only over Access's public listener with its client certificate, keeps its requests and
//! outcomes in its own database, and loads the trusted lists through the parser worker.
//!
//! Configuration (environment):
//! - `ACCESS_VC_VERIFIER_LISTEN`: the address to serve on, e.g. `127.0.0.1:8491`.
//! - `ACCESS_VC_VERIFIER_ORIGIN`: the verifier's public origin, `https://host[:port]`.
//! - `ACCESS_VC_VERIFIER_ACCESS`: Access's public origin, `https://host[:port]`.
//! - `ACCESS_VC_VERIFIER_CA`, `ACCESS_VC_VERIFIER_CERT`, `ACCESS_VC_VERIFIER_KEY`: PEM files of
//!   the roots Access's certificate chains to, the verifier's client certificate chain and key.
//! - `ACCESS_VC_VERIFIER_FETCH_CA`: PEM file of the roots fetched servers chain to.
//! - `ACCESS_VC_VERIFIER_DATABASE_URL`: the verifier's own PostgreSQL database.
//! - `ACCESS_VC_VERIFIER_OPERATOR`, `ACCESS_VC_VERIFIER_INSTANCE`: base64url ids of the operator
//!   Party and of the verifier Instance whose key signs the Claims.
//! - `ACCESS_VC_VERIFIER_SIGNING_KEY`: PKCS#8 file of the verifier Instance's P-256 key; it signs
//!   the Claims and the request objects.
//! - `ACCESS_VC_VERIFIER_REQUEST_CERT`: PEM file of the request-signing certificate chain for that
//!   key; its leaf names the `x509_hash` `client_id`.
//! - `ACCESS_VC_VERIFIER_RESPONSE_SECRET`: file of 32 random bytes the response keys derive from.
//! - `ACCESS_VC_VERIFIER_CALLERS`: comma-separated base64url SHA-256 digests of the caller keys.
//! - `ACCESS_VC_VERIFIER_ISSUERS`: comma-separated issuers trusted outside the trusted lists
//!   (may be empty).

use std::process::ExitCode;
use std::sync::Arc;

use access_kernel::json::b64url_decode;
use access_kernel::model::Id;
use access_vc_verifier::app::{Config, Verifier};
use access_vc_verifier::domain::claims::Reporter;
use access_vc_verifier::https::{AccessHttps, GuardedFetch};
use access_vc_verifier::ports::{Clock, Random};
use access_vc_verifier::router;
use access_vc_verifier::store::Store;
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

#[derive(Debug, thiserror::Error)]
enum Startup {
    #[error("missing or invalid {0}")]
    Config(&'static str),
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("listen: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Store(#[from] access_vc_verifier::store::StoreError),
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

fn chain(name: &'static str) -> Result<Vec<CertificateDer<'static>>, Startup> {
    CertificateDer::pem_file_iter(var(name)?)
        .map_err(|_| Startup::Config(name))?
        .collect::<Result<_, _>>()
        .map_err(|_| Startup::Config(name))
}

fn id(name: &'static str) -> Result<Id, Startup> {
    b64url_decode(&var(name)?)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .map(Id)
        .ok_or(Startup::Config(name))
}

fn list(name: &'static str) -> Result<Vec<String>, Startup> {
    Ok(var(name)?
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect())
}

async fn run() -> Result<(), Startup> {
    let listen = var("ACCESS_VC_VERIFIER_LISTEN")?;
    let client_chain = chain("ACCESS_VC_VERIFIER_CERT")?;
    let key = PrivateKeyDer::from_pem_file(var("ACCESS_VC_VERIFIER_KEY")?)
        .map_err(|_| Startup::Config("ACCESS_VC_VERIFIER_KEY"))?;
    let access = AccessHttps::new(
        roots("ACCESS_VC_VERIFIER_CA")?,
        client_chain,
        key,
        &var("ACCESS_VC_VERIFIER_ACCESS")?,
    )?;
    let fetch = GuardedFetch::new(roots("ACCESS_VC_VERIFIER_FETCH_CA")?)?;
    let pkcs8 = std::fs::read(var("ACCESS_VC_VERIFIER_SIGNING_KEY")?)
        .map_err(|_| Startup::Config("ACCESS_VC_VERIFIER_SIGNING_KEY"))?;
    let signer = SoftSigner::p256_from_pkcs8(&Secret::new(pkcs8))
        .map_err(|_| Startup::Config("ACCESS_VC_VERIFIER_SIGNING_KEY"))?;
    let secret: [u8; 32] = std::fs::read(var("ACCESS_VC_VERIFIER_RESPONSE_SECRET")?)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(Startup::Config("ACCESS_VC_VERIFIER_RESPONSE_SECRET"))?;
    let callers = list("ACCESS_VC_VERIFIER_CALLERS")?
        .iter()
        .map(|c| {
            b64url_decode(c)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(Startup::Config("ACCESS_VC_VERIFIER_CALLERS"))?;
    let store = Store::connect(&var("ACCESS_VC_VERIFIER_DATABASE_URL")?).await?;
    store.migrate().await?;
    let config = Config {
        origin: var("ACCESS_VC_VERIFIER_ORIGIN")?
            .trim_end_matches('/')
            .to_owned(),
        chain: chain("ACCESS_VC_VERIFIER_REQUEST_CERT")?
            .into_iter()
            .map(|c| c.as_ref().to_vec())
            .collect(),
        response_secret: Secret::new(secret),
        reporter: Reporter {
            operator: id("ACCESS_VC_VERIFIER_OPERATOR")?,
            instance: id("ACCESS_VC_VERIFIER_INSTANCE")?,
        },
        callers,
        issuers: list("ACCESS_VC_VERIFIER_ISSUERS")?,
    };
    let verifier = Arc::new(Verifier::new(
        store,
        (access, fetch),
        (
            SystemClock,
            SystemRandom(Arc::new(rustls::crypto::aws_lc_rs::default_provider())),
            signer,
        ),
        config,
    ));
    if let Err(e) = verifier.restore_lists().await {
        tracing::warn!(error = %e, "no trusted list snapshot restored");
    }
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, router(verifier)).await?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // OP-67
    tracing_subscriber::fmt().json().init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "access-vc-verifier did not start");
            ExitCode::FAILURE
        }
    }
}
