//! The gateway's configuration, read from the environment and the files it names before the
//! lockdown (SA-22). A missing or unreadable input stops the gateway (OP-52).

use std::net::SocketAddr;
use std::path::PathBuf;

use access_edge_core::channel::ChannelConfig;
use suiss_sandbox::RunAs;

/// The listener's default address.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8443";

/// Where libkrb5 reads its configuration by default.
pub const DEFAULT_KRB5_CONF: &str = "/etc/krb5.conf";

/// The KDC port `S4U2Proxy` reaches by default.
pub const DEFAULT_KDC_PORT: u16 = 88;

/// The `S4U2Proxy` backend (OP-155 m.3 (o)).
pub struct Backend {
    /// The backend's service principal, `service/host@REALM`.
    pub spn: String,
    /// `host:port` of the backend's HTTPS listener.
    pub addr: String,
    /// The name its certificate is checked for.
    pub server_name: String,
    /// The roots for its certificate, PEM.
    pub roots_pem: Vec<u8>,
    /// The KDC port the gateway may reach for constrained delegation.
    pub kdc_port: u16,
}

/// Everything the gateway needs.
pub struct Config {
    /// The HTTPS listener.
    pub listen: SocketAddr,
    /// The gateway's TLS certificate chain for browsers, PEM.
    pub tls_chain: Vec<u8>,
    /// Its private key, PEM.
    pub tls_key: Vec<u8>,
    /// The one service principal accepted, `HTTP/host@REALM`.
    pub spn: String,
    /// The keytab file in the operator's secret store; read once, never written.
    pub keytab: PathBuf,
    /// The realm's normal sign-in page: every failure and every success ends there.
    pub login: String,
    /// The parser worker supervisor's socket.
    pub parser: PathBuf,
    /// The user the supervisor runs as, checked on every connection.
    pub parser_uid: Option<u32>,
    /// libkrb5's configuration file.
    pub krb5_conf: PathBuf,
    /// libkrb5's replay cache directory, on a memory file system.
    pub rcache: PathBuf,
    /// The `S4U2Proxy` backend, when one is configured.
    pub backend: Option<Backend>,
    /// The edge channel to access-server.
    pub channel: ChannelConfig,
    /// The identity to drop to when started as root.
    pub run_as: Option<RunAs>,
}

impl core::fmt::Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("spn", &self.spn)
            .field("login", &self.login)
            .field("channel", &self.channel)
            .finish_non_exhaustive()
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn required(name: &'static str) -> Result<String, String> {
    var(name).ok_or_else(|| format!("{name} is required"))
}

fn file(name: &'static str) -> Result<Vec<u8>, String> {
    let path = PathBuf::from(required(name)?);
    std::fs::read(&path).map_err(|e| format!("{name}: {e}"))
}

/// Whether `url` is an absolute `https` URL without credentials or a fragment.
#[must_use]
pub fn valid_login(url: &str) -> bool {
    url.strip_prefix("https://").is_some_and(|rest| {
        let host = rest.split(['/', '?']).next().unwrap_or_default();
        !host.is_empty()
            && !host.contains('@')
            && !url.contains('#')
            && url.len() <= 2048
            && url.bytes().all(|b| b.is_ascii_graphic())
    })
}

fn backend() -> Result<Option<Backend>, String> {
    let Some(spn) = var("ACCESS_GW_KERBEROS_BACKEND_SPN") else {
        return Ok(None);
    };
    let kdc_port = var("ACCESS_GW_KERBEROS_KDC_PORT")
        .map(|p| p.parse::<u16>())
        .transpose()
        .map_err(|_| "ACCESS_GW_KERBEROS_KDC_PORT: not a port")?
        .unwrap_or(DEFAULT_KDC_PORT);
    Ok(Some(Backend {
        spn,
        addr: required("ACCESS_GW_KERBEROS_BACKEND")?,
        server_name: required("ACCESS_GW_KERBEROS_BACKEND_NAME")?,
        roots_pem: file("ACCESS_GW_KERBEROS_BACKEND_ROOTS")?,
        kdc_port,
    }))
}

/// The configuration from `ACCESS_GW_KERBEROS_*`.
///
/// # Errors
/// A message naming the variable.
pub fn from_env() -> Result<Config, String> {
    let listen = var("ACCESS_GW_KERBEROS_LISTEN")
        .unwrap_or_else(|| String::from(DEFAULT_LISTEN))
        .parse()
        .map_err(|_| "ACCESS_GW_KERBEROS_LISTEN: not host:port")?;
    let login = required("ACCESS_GW_KERBEROS_LOGIN")?;
    if !valid_login(&login) {
        return Err(String::from("ACCESS_GW_KERBEROS_LOGIN: not an https URL"));
    }
    let run_as = var("ACCESS_GW_KERBEROS_RUN_AS")
        .map(|v| {
            let (u, g) = v
                .split_once(':')
                .ok_or("ACCESS_GW_KERBEROS_RUN_AS: uid:gid")?;
            match (u.parse::<u32>(), g.parse::<u32>()) {
                (Ok(u), Ok(g)) => {
                    RunAs::new(u, g).map_err(|_| "ACCESS_GW_KERBEROS_RUN_AS: not root")
                }
                _ => Err("ACCESS_GW_KERBEROS_RUN_AS: uid:gid"),
            }
        })
        .transpose()?;
    let parser_uid = var("ACCESS_GW_KERBEROS_PARSER_UID")
        .map(|u| u.parse::<u32>())
        .transpose()
        .map_err(|_| "ACCESS_GW_KERBEROS_PARSER_UID: not a uid")?;
    Ok(Config {
        listen,
        tls_chain: file("ACCESS_GW_KERBEROS_TLS_CERT")?,
        tls_key: file("ACCESS_GW_KERBEROS_TLS_KEY")?,
        spn: required("ACCESS_GW_KERBEROS_SPN")?,
        keytab: PathBuf::from(required("ACCESS_GW_KERBEROS_KEYTAB")?),
        login,
        parser: PathBuf::from(required("ACCESS_GW_KERBEROS_PARSER_SOCKET")?),
        parser_uid,
        krb5_conf: PathBuf::from(
            var("ACCESS_GW_KERBEROS_KRB5_CONF").unwrap_or_else(|| String::from(DEFAULT_KRB5_CONF)),
        ),
        rcache: PathBuf::from(required("ACCESS_GW_KERBEROS_RCACHE_DIR")?),
        backend: backend()?,
        channel: ChannelConfig {
            addr: required("ACCESS_GW_KERBEROS_SERVER")?,
            server_name: required("ACCESS_GW_KERBEROS_SERVER_NAME")?,
            roots_pem: file("ACCESS_GW_KERBEROS_SERVER_ROOTS")?,
            chain_pem: file("ACCESS_GW_KERBEROS_CHANNEL_CERT")?,
            key_pem: file("ACCESS_GW_KERBEROS_CHANNEL_KEY")?,
        },
        run_as,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // §10.6.4
    #[test]
    fn the_login_page_is_an_https_url() {
        assert!(valid_login("https://corp.example/realms/corp/login"));
        assert!(!valid_login("http://corp.example/login"));
        assert!(!valid_login("https://user@corp.example/login"));
        assert!(!valid_login("https://corp.example/login#x"));
        assert!(!valid_login("https:///login"));
        assert!(!valid_login("javascript:alert(1)"));
    }
}
