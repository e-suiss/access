//! `access-hr-connector`: one HR connector as its own process (OP-156 m.3 (q), B21). It reads
//! the HR system on its schedule, pushes the records to Access's HR batch API over Access's
//! public listener, and keeps its run history in its own database.
//!
//! Configuration (environment; secrets and keys are files the operator provides):
//! - `ACCESS_HR_LISTEN`: the address to serve `/hr-connector/v1/*` on.
//! - `ACCESS_HR_DATABASE_URL`: the connector's own PostgreSQL database.
//! - `ACCESS_HR_CONNECTOR`, `ACCESS_HR_VENDOR`, `ACCESS_HR_REALM`, `ACCESS_HR_SOURCE`: the
//!   connector's registered name, its vendor, the realm's slug and the HR source it pushes to.
//! - `ACCESS_HR_ACCESS`: Access's public origin; `ACCESS_HR_CA`: PEM roots of Access's and the
//!   HR system's certificates.
//! - `ACCESS_HR_TOKEN`: file of the DPoP-bound read token that drafts each write.
//! - `ACCESS_HR_SIGNING_KEY`: PKCS#8 file of the connector Instance's Ed25519 key;
//!   `ACCESS_HR_BASIS`: the base64url Anchor id its writes are made under.
//! - `ACCESS_HR_VENDOR_URL`, `ACCESS_HR_VENDOR_METHOD` (`GET` or `POST`),
//!   `ACCESS_HR_VENDOR_BODY` (optional JSON file), `ACCESS_HR_VENDOR_CREDENTIAL` (file of the
//!   `Authorization` header value).
//! - `ACCESS_HR_EVERY_S`: seconds between runs, at least 300 (default 3600).

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use access_hr_connector::app::Connector;
use access_hr_connector::domain::vendor::Vendor;
use access_hr_connector::https::{AccessHttps, VendorHttps, client};
use access_hr_connector::key::InstanceKey;
use access_hr_connector::ports::{Clock, Random};
use access_hr_connector::service::{Service, router};
use access_hr_connector::store::Store;
use access_kernel::json::b64url_decode;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Id;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::SoftSigner;

#[derive(Clone, Copy)]
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
    Store(#[from] access_hr_connector::store::StoreError),
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

async fn run() -> Result<(), Startup> {
    let vendor =
        Vendor::parse(&var("ACCESS_HR_VENDOR")?).ok_or(Startup::Config("ACCESS_HR_VENDOR"))?;
    let connector = Connector {
        name: var("ACCESS_HR_CONNECTOR")?,
        vendor,
        realm: var("ACCESS_HR_REALM")?,
        source: var("ACCESS_HR_SOURCE")?,
    };
    let tls = client(roots("ACCESS_HR_CA")?)?;
    let pkcs8 = std::fs::read(var("ACCESS_HR_SIGNING_KEY")?)
        .map_err(|_| Startup::Config("ACCESS_HR_SIGNING_KEY"))?;
    let signer = SoftSigner::ed25519_from_pkcs8(&Secret::new(pkcs8))
        .map_err(|_| Startup::Config("ACCESS_HR_SIGNING_KEY"))?;
    let anchor = b64url_decode(&var("ACCESS_HR_BASIS")?)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .ok_or(Startup::Config("ACCESS_HR_BASIS"))?;
    let key = Arc::new(InstanceKey::new(
        signer,
        ExerciseBasis::Anchor(Id(anchor)),
        SystemClock,
    ));
    let access = AccessHttps::new(
        tls.clone(),
        &var("ACCESS_HR_ACCESS")?,
        PathBuf::from(var("ACCESS_HR_TOKEN")?),
        Arc::clone(&key),
    );
    let method = match var("ACCESS_HR_VENDOR_METHOD").as_deref() {
        Ok("POST") => "POST",
        Ok("GET") | Err(_) => "GET",
        Ok(_) => return Err(Startup::Config("ACCESS_HR_VENDOR_METHOD")),
    };
    let body = match std::env::var("ACCESS_HR_VENDOR_BODY") {
        Ok(path) => Some(
            std::fs::read(path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .ok_or(Startup::Config("ACCESS_HR_VENDOR_BODY"))?,
        ),
        Err(_) => None,
    };
    let pull = VendorHttps {
        connector: tls,
        url: var("ACCESS_HR_VENDOR_URL")?,
        method,
        body,
        credential: PathBuf::from(var("ACCESS_HR_VENDOR_CREDENTIAL")?),
    };
    let every = std::env::var("ACCESS_HR_EVERY_S")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600)
        .max(300);
    let store = Store::connect(&var("ACCESS_HR_DATABASE_URL")?).await?;
    store.migrate().await?;
    let service = Arc::new(Service {
        connector,
        pull,
        access,
        sign: InstanceKeyRef(key),
        random: SystemRandom(Arc::new(rustls::crypto::aws_lc_rs::default_provider())),
        clock: SystemClock,
        store,
        running: tokio::sync::Mutex::new(()),
    });
    let runner = Arc::clone(&service);
    tokio::spawn(async move {
        loop {
            let _ = runner.run_once().await;
            tokio::time::sleep(Duration::from_secs(every)).await;
        }
    });
    let listener = tokio::net::TcpListener::bind(&var("ACCESS_HR_LISTEN")?).await?;
    axum::serve(listener, router(service)).await?;
    Ok(())
}

/// The shared Instance key as the signing port.
struct InstanceKeyRef(Arc<InstanceKey<SystemClock>>);

impl access_hr_connector::ports::Sign for InstanceKeyRef {
    fn ais(
        &self,
        domain: [u8; 32],
        nonce: &[u8; 16],
        intent: [u8; 32],
        pep: &str,
    ) -> Option<String> {
        self.0.ais(domain, nonce, intent, pep)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // OP-67
    tracing_subscriber::fmt().json().init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "access-hr-connector did not start");
            ExitCode::FAILURE
        }
    }
}
