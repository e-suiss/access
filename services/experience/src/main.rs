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
//! - `ACCESS_EXPERIENCE_SSF_POLL`, `ACCESS_EXPERIENCE_SSF_TOKEN`: optional, together: the SSF poll
//!   URL of this service's stream (`https://host[:port]/…/ssf/poll`) and a file holding its
//!   bearer credential; each batch of events moves the stream's signal (OP-153 m.8 (d)).
//! - `ACCESS_EXPERIENCE_DOORBELL`, with `ACCESS_EXPERIENCE_DOORBELL_SERVER_NAME`,
//!   `ACCESS_EXPERIENCE_DOORBELL_CA`, `ACCESS_EXPERIENCE_DOORBELL_CERT` and
//!   `ACCESS_EXPERIENCE_DOORBELL_KEY`: optional, Access's NATS doorbell `host:port` over mTLS (the
//!   key file readable by its owner only); each ring moves the stream's signal (OP-156 m.8 (d)).

use std::collections::BTreeMap;
use std::process::ExitCode;

use access_experience::adapters::{Beacon, router};
use access_experience::app::Experience;
use access_experience::feed;
use access_experience::https::{Endpoint, Https, SsfPoll, pep_name};
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
}

fn var(name: &'static str) -> Result<String, Startup> {
    std::env::var(name).map_err(|_| Startup::Config(name))
}

fn owner_only(path: &str) -> bool {
    std::fs::metadata(path).is_ok_and(|m| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            m.is_file() && matches!(m.permissions().mode() & 0o777, 0o400 | 0o600)
        }
        #[cfg(not(unix))]
        {
            m.is_file()
        }
    })
}

/// The doorbell client of the `ACCESS_EXPERIENCE_DOORBELL*` variables, or `None` without them.
fn doorbell(
    random: &rustls::crypto::CryptoProvider,
) -> Result<Option<suiss_ledger::doorbell::client::Config>, Startup> {
    const WHAT: &str = "ACCESS_EXPERIENCE_DOORBELL";
    let Ok(addr) = std::env::var(WHAT) else {
        return Ok(None);
    };
    let file = |name: &'static str| std::fs::read(var(name)?).map_err(|_| Startup::Config(name));
    let key = var("ACCESS_EXPERIENCE_DOORBELL_KEY")?;
    if !owner_only(&key) {
        return Err(Startup::Config("ACCESS_EXPERIENCE_DOORBELL_KEY"));
    }
    let tls = suiss_ledger::doorbell::client::tls(
        &file("ACCESS_EXPERIENCE_DOORBELL_CA")?,
        &file("ACCESS_EXPERIENCE_DOORBELL_CERT")?,
        &std::fs::read(&key).map_err(|_| Startup::Config("ACCESS_EXPERIENCE_DOORBELL_KEY"))?,
    )
    .map_err(|_| Startup::Config(WHAT))?;
    let server_name =
        rustls::pki_types::ServerName::try_from(var("ACCESS_EXPERIENCE_DOORBELL_SERVER_NAME")?)
            .map_err(|_| Startup::Config("ACCESS_EXPERIENCE_DOORBELL_SERVER_NAME"))?;
    let mut token = [0_u8; 16];
    random
        .secure_random
        .fill(&mut token)
        .map_err(|_| Startup::Config(WHAT))?;
    Ok(Some(suiss_ledger::doorbell::client::Config {
        addr,
        server_name,
        tls,
        topic: suiss_ledger::doorbell::Topic::ACCESS,
        inbox: token.iter().fold(String::new(), |mut s, b| {
            let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
            s
        }),
        name: String::from("access-experience"),
    }))
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
    let beacon = Beacon::default();
    // OP-153 m.8 (d)
    let (_keep, stopped) = tokio::sync::watch::channel(false);
    let _feed = match (
        std::env::var("ACCESS_EXPERIENCE_SSF_POLL"),
        std::env::var("ACCESS_EXPERIENCE_SSF_TOKEN"),
    ) {
        (Ok(url), Ok(file)) => {
            let token = std::fs::read_to_string(file)
                .map_err(|_| Startup::Config("ACCESS_EXPERIENCE_SSF_TOKEN"))?;
            let https = Https::new(
                roots.clone(),
                chain.clone(),
                key.clone_key(),
                default.clone(),
                BTreeMap::new(),
            )?;
            let poll = SsfPoll::new(https, &url, &token)
                .ok_or(Startup::Config("ACCESS_EXPERIENCE_SSF_POLL"))?;
            Some(tokio::spawn(feed::run(
                poll,
                beacon.clone(),
                stopped.clone(),
            )))
        }
        (Err(_), Err(_)) => None,
        _ => return Err(Startup::Config("ACCESS_EXPERIENCE_SSF_POLL")),
    };
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    // OP-156 m.8 (d)
    let _bell = doorbell(&provider)?
        .map(|cfg| tokio::spawn(feed::doorbell(cfg, beacon.clone(), stopped.clone())));
    let upstream = Https::new(roots, chain, key, default, routes)?;
    let experience = Experience::new(upstream, SystemClock, SystemRandom(provider), pep);
    let app = router(experience, beacon);
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
