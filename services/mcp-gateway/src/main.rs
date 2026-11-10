//! `access-mcp-gateway`: Access Proxy's MCP mode as its own process, behind the proxy's engine
//! (B22). It reaches Access only over Access's public listener with its client certificate and
//! keeps no state of its own.
//!
//! Configuration (environment):
//! - `ACCESS_MCP_GATEWAY_LISTEN`: the address to serve on behind the engine, e.g.
//!   `127.0.0.1:8491`; `ACCESS_MCP_GATEWAY_PATH`: the MCP endpoint's path, `/mcp` when unset.
//! - `ACCESS_MCP_GATEWAY_HOST`: the MCP server's host as agents reach it, the host the proxy is
//!   registered for; `ACCESS_MCP_GATEWAY_ORIGINS`: allowed `Origin` values, comma-separated.
//! - `ACCESS_MCP_GATEWAY_ACCESS`: Access's public origin, `https://host[:port]`.
//! - `ACCESS_MCP_GATEWAY_CA`, `ACCESS_MCP_GATEWAY_CERT`, `ACCESS_MCP_GATEWAY_KEY`: PEM files of
//!   the roots Access's certificate chains to, this gateway's client certificate chain and its
//!   key; the certificate's `x5t#S256` is the `pep` of the proxy registration.
//! - `ACCESS_MCP_GATEWAY_UPSTREAM`: the MCP server's endpoint, `https://…`;
//!   `ACCESS_MCP_GATEWAY_UPSTREAM_CA`: PEM file of the roots it chains to.
//! - `ACCESS_MCP_GATEWAY_DOMAIN`: base64url of the realm's governing domain.
//! - `ACCESS_MCP_GATEWAY_PROXY`, `ACCESS_MCP_GATEWAY_NAMESPACE`: the registration's name and
//!   resource namespace; `ACCESS_MCP_GATEWAY_ACTION`: its action as
//!   `namespace/name/major/schema` (schema base64url).

use std::process::ExitCode;
use std::sync::Arc;

use access_kernel::digest::Digest;
use access_kernel::json::b64url_decode;
use access_kernel::model::ActionRef;
use access_mcp_gateway::adapters::router;
use access_mcp_gateway::app::{Config, Gateway};
use access_mcp_gateway::domain::Profile;
use access_mcp_gateway::https::{AccessHttps, UpstreamHttps, pep_name};
use access_mcp_gateway::ports::Clock;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Option<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
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

fn roots(name: &'static str) -> Result<rustls::RootCertStore, Startup> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(var(name)?).map_err(|_| Startup::Config(name))? {
        roots
            .add(c.map_err(|_| Startup::Config(name))?)
            .map_err(|_| Startup::Config(name))?;
    }
    Ok(roots)
}

fn digest(name: &'static str, s: &str) -> Result<Digest, Startup> {
    b64url_decode(s)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(Digest)
        .ok_or(Startup::Config(name))
}

fn action() -> Result<ActionRef, Startup> {
    const NAME: &str = "ACCESS_MCP_GATEWAY_ACTION";
    let v = var(NAME)?;
    let parts: Vec<&str> = v.split('/').collect();
    let [namespace, name, major, schema] = parts.as_slice() else {
        return Err(Startup::Config(NAME));
    };
    Ok(ActionRef {
        namespace: String::from(*namespace),
        name: String::from(*name),
        major: major.parse().map_err(|_| Startup::Config(NAME))?,
        schema: digest(NAME, schema)?,
    })
}

async fn run() -> Result<(), Startup> {
    let listen = var("ACCESS_MCP_GATEWAY_LISTEN")?;
    let path = std::env::var("ACCESS_MCP_GATEWAY_PATH").unwrap_or_else(|_| String::from("/mcp"));
    if !path.starts_with('/') {
        return Err(Startup::Config("ACCESS_MCP_GATEWAY_PATH"));
    }
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(var("ACCESS_MCP_GATEWAY_CERT")?)
            .map_err(|_| Startup::Config("ACCESS_MCP_GATEWAY_CERT"))?
            .collect::<Result<_, _>>()
            .map_err(|_| Startup::Config("ACCESS_MCP_GATEWAY_CERT"))?;
    let pep = pep_name(
        chain
            .first()
            .ok_or(Startup::Config("ACCESS_MCP_GATEWAY_CERT"))?,
    );
    let key = PrivateKeyDer::from_pem_file(var("ACCESS_MCP_GATEWAY_KEY")?)
        .map_err(|_| Startup::Config("ACCESS_MCP_GATEWAY_KEY"))?;
    let access = AccessHttps::new(
        roots("ACCESS_MCP_GATEWAY_CA")?,
        chain,
        key,
        &var("ACCESS_MCP_GATEWAY_ACCESS")?,
    )?;
    let upstream_url = var("ACCESS_MCP_GATEWAY_UPSTREAM")?;
    if access_mcp_gateway::https::Target::parse(&upstream_url).is_none() {
        return Err(Startup::Config("ACCESS_MCP_GATEWAY_UPSTREAM"));
    }
    let upstream = UpstreamHttps::new(roots("ACCESS_MCP_GATEWAY_UPSTREAM_CA")?, &upstream_url)?;
    let origins = std::env::var("ACCESS_MCP_GATEWAY_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|o| !o.is_empty())
        .map(String::from)
        .collect();
    let config = Config {
        host: var("ACCESS_MCP_GATEWAY_HOST")?.to_ascii_lowercase(),
        origins,
        pep,
        domain: digest(
            "ACCESS_MCP_GATEWAY_DOMAIN",
            &var("ACCESS_MCP_GATEWAY_DOMAIN")?,
        )?,
        profile: Profile {
            proxy: var("ACCESS_MCP_GATEWAY_PROXY")?,
            namespace: var("ACCESS_MCP_GATEWAY_NAMESPACE")?,
            action: action()?,
        },
    };
    let gateway = Arc::new(Gateway::new((access, upstream, SystemClock), config));
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, router(&path, gateway)).await?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // OP-67
    tracing_subscriber::fmt().json().init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "access-mcp-gateway did not start");
            ExitCode::FAILURE
        }
    }
}
