//! The gateway's configuration, read from the environment and the files it names before the
//! lockdown (SA-22). A missing or unreadable input stops the gateway (OP-52).

use std::net::SocketAddr;
use std::path::PathBuf;

use access_edge_core::channel::ChannelConfig;
use suiss_sandbox::RunAs;

/// The LDAPS listener's default address (OP-155 m.3 (n)).
pub const DEFAULT_LISTEN: &str = "0.0.0.0:636";

/// Everything the gateway needs.
pub struct Config {
    /// The LDAPS listener.
    pub listen: SocketAddr,
    /// The cleartext listener that offers `StartTLS`; `None` keeps `StartTLS` off.
    pub starttls: Option<SocketAddr>,
    /// The gateway's TLS certificate chain for LDAP clients, PEM.
    pub tls_chain: Vec<u8>,
    /// Its private key, PEM.
    pub tls_key: Vec<u8>,
    /// The edge channel to access-server.
    pub channel: ChannelConfig,
    /// The identity to drop to when started as root.
    pub run_as: Option<RunAs>,
}

impl core::fmt::Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("starttls", &self.starttls)
            .field("channel", &self.channel)
            .finish_non_exhaustive()
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn file(name: &'static str) -> Result<Vec<u8>, String> {
    let path = PathBuf::from(var(name).ok_or_else(|| format!("{name} is required"))?);
    std::fs::read(&path).map_err(|e| format!("{name}: {e}"))
}

fn addr(name: &str, v: &str) -> Result<SocketAddr, String> {
    v.parse().map_err(|_| format!("{name}: not host:port"))
}

/// The configuration from `ACCESS_GW_LDAP_*`.
///
/// # Errors
/// A message naming the variable.
pub fn from_env() -> Result<Config, String> {
    let listen = addr(
        "ACCESS_GW_LDAP_LISTEN",
        &var("ACCESS_GW_LDAP_LISTEN").unwrap_or_else(|| String::from(DEFAULT_LISTEN)),
    )?;
    let starttls = var("ACCESS_GW_LDAP_STARTTLS_LISTEN")
        .map(|v| addr("ACCESS_GW_LDAP_STARTTLS_LISTEN", &v))
        .transpose()?;
    let run_as = var("ACCESS_GW_LDAP_RUN_AS")
        .map(|v| {
            let (u, g) = v.split_once(':').ok_or("ACCESS_GW_LDAP_RUN_AS: uid:gid")?;
            match (u.parse::<u32>(), g.parse::<u32>()) {
                (Ok(u), Ok(g)) => RunAs::new(u, g).map_err(|_| "ACCESS_GW_LDAP_RUN_AS: not root"),
                _ => Err("ACCESS_GW_LDAP_RUN_AS: uid:gid"),
            }
        })
        .transpose()?;
    Ok(Config {
        listen,
        starttls,
        tls_chain: file("ACCESS_GW_LDAP_TLS_CERT")?,
        tls_key: file("ACCESS_GW_LDAP_TLS_KEY")?,
        channel: ChannelConfig {
            addr: var("ACCESS_GW_LDAP_SERVER").ok_or("ACCESS_GW_LDAP_SERVER is required")?,
            server_name: var("ACCESS_GW_LDAP_SERVER_NAME")
                .ok_or("ACCESS_GW_LDAP_SERVER_NAME is required")?,
            roots_pem: file("ACCESS_GW_LDAP_SERVER_ROOTS")?,
            chain_pem: file("ACCESS_GW_LDAP_CHANNEL_CERT")?,
            key_pem: file("ACCESS_GW_LDAP_CHANNEL_KEY")?,
        },
        run_as,
    })
}
