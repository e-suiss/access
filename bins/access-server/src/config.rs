//! Process configuration (OP-63 rule 4).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use access_http::SecurityTxt;
use access_identity_oauth::domain::issuer::{Issuer, RealmBase};
use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

/// Validated process configuration.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Listen address. Defaults to loopback (§14.3 RAUTHY-008): exposing the
    /// server beyond the host is an explicit operator decision.
    pub(crate) listen: SocketAddr,
    /// `tracing` filter directives.
    pub(crate) log: String,
    /// `security.txt` contact URIs (RFC 9116).
    pub(crate) security_contacts: Vec<String>,
    /// `security.txt` policy URI.
    pub(crate) security_policy: Option<String>,
    /// `security.txt` validity in days; RFC 9116 recommends less than a year.
    pub(crate) security_txt_valid_days: u16,
    /// TLS certificate chain and key (CR-12); there is no plain-text listener.
    pub(crate) tls: Option<Tls>,
    /// The issuer the ADP discovery document names (L1-ADP-11), without a trailing slash.
    pub(crate) issuer: Option<String>,
    /// The database (OP-141 m.18 (g)).
    pub(crate) database: Option<Database>,
    /// The PKCS#11 token (OP-94, OP-141 m.18 (h)).
    pub(crate) hsm: Option<Hsm>,
    /// The authority signer's Unix socket; without it receipts are not signed (OP-143 m.5).
    pub(crate) signer: Option<PathBuf>,
    /// The identity plane (TN-10, CMP-22b, OP-138).
    pub(crate) identity: Option<Identity>,
    pub(crate) login: Login,
}

/// The hosted login (OP-146 m.12, m.14).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Login {
    /// The built `web/login/dist`; read once before the lockdown. Without it only the login
    /// API is served.
    pub(crate) dist_dir: Option<PathBuf>,
    /// Where a completed sign-in goes: a path on the realm's origin.
    pub(crate) redirect_to: String,
    /// Session idle lifetime, seconds (TN-36; OP-146 m.14 (c): 7 days).
    pub(crate) session_idle_s: u64,
    /// Session absolute lifetime, seconds (TN-36; OP-146 m.14 (c): 30 days).
    pub(crate) session_absolute_s: u64,
    /// The calibrated Argon2id time that pads refusals until successes are measured (TN-82,
    /// OP-146 m.4 (f)).
    pub(crate) hash_mean_ms: u64,
}

impl Default for Login {
    fn default() -> Self {
        Self {
            dist_dir: None,
            redirect_to: "/".to_owned(),
            session_idle_s: 7 * 86_400,
            session_absolute_s: 30 * 86_400,
            hash_mean_ms: 0,
        }
    }
}

impl Login {
    /// The session lifetimes, if inside the TN-36 ranges.
    pub(crate) fn lifetimes(
        &self,
    ) -> Option<access_identity_session::domain::session::SessionPolicy> {
        access_identity_session::domain::session::SessionPolicy::new(
            self.session_idle_s.checked_mul(1000)?,
            self.session_absolute_s.checked_mul(1000)?,
        )
        .ok()
    }
}

/// The identity plane's realm runtime.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    /// The origin realm issuers are formed under, `https://<host>[:port]` without a path:
    /// `https://<slug>.<host>` by default (TN-10). Issuers are stored on the realm rows and
    /// never built from a request (§17.9.6).
    pub(crate) realm_base: String,
    /// The identity signer's Unix socket (CMP-22b).
    pub(crate) signer: PathBuf,
    /// PEM trust anchors for clients' own endpoints: `jwks_uri` and back-channel logout
    /// (§10.4.6, §11.3.6). Without it the system bundle is read; without either those
    /// requests fail and the server still starts.
    #[serde(default)]
    pub(crate) outbound_ca_file: Option<PathBuf>,
}

/// TLS files, read once before the lockdown.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "the _file suffix marks a path setting (OP-129 m.3)"
)]
pub(crate) struct Tls {
    /// PEM certificate chain, leaf first.
    pub(crate) cert_file: PathBuf,
    /// PEM private key; readable by the server's user only (CR-35).
    pub(crate) key_file: PathBuf,
    /// PEM bundle of the CAs that issue PEP client certificates (OP-141 m.18 (b)).
    pub(crate) client_ca_file: Option<PathBuf>,
}

/// How the deployment declares its durability (OP-24, HL-40).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Durability {
    /// Synchronous standbys.
    Replicated,
    /// The small-provider single-node declaration.
    SingleNode,
}

/// One login role and its pool.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Role {
    /// Login role, a member of the plane role.
    pub(crate) user: String,
    /// Credential file (OP-129 m.3).
    pub(crate) password_file: PathBuf,
    /// Pool size (OP-53).
    pub(crate) pool: u32,
}

/// The database and the two authority roles (OP-130 m.2).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Database {
    /// Server host name, checked against its certificate.
    pub(crate) host: String,
    /// Port.
    pub(crate) port: u16,
    /// Database name.
    pub(crate) name: String,
    /// PEM root the server certificate chains to.
    pub(crate) root_cert_file: PathBuf,
    /// Declared durability.
    pub(crate) durability: Durability,
    /// `access_sequencer` login.
    pub(crate) sequencer: Role,
    /// `access_app` login.
    pub(crate) app: Role,
    /// `access_deriver` login (OP-141 m.22 (k)).
    pub(crate) deriver: Role,
    /// `access_router` login: Host → realm resolution (OP-132 m.3).
    pub(crate) router: Role,
    /// `access_archive` login: opens the day partitions of the ephemeral protocol tables
    /// (OP-146 m.5 (f)).
    pub(crate) archive: Role,
    /// `access_outbox_reader` login: the back-channel logout courier (OP-131).
    pub(crate) outbox_reader: Role,
}

/// The PKCS#11 token holding the domains' keys.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hsm {
    /// The PKCS#11 module, loaded before the lockdown.
    pub(crate) module: PathBuf,
    /// Token label.
    pub(crate) token: String,
    /// User PIN file (OP-129 m.3).
    pub(crate) pin_file: PathBuf,
    /// Directories a file-backed token keeps its objects in, opened read-write.
    #[serde(default)]
    pub(crate) paths: Vec<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8443)),
            log: "info".to_owned(),
            security_contacts: vec![
                "https://github.com/e-suiss/access/security/advisories/new".to_owned(),
            ],
            security_policy: Some("https://github.com/e-suiss/access/security/policy".to_owned()),
            security_txt_valid_days: 180,
            tls: None,
            issuer: None,
            database: None,
            hsm: None,
            signer: None,
            identity: None,
            login: Login::default(),
        }
    }
}

/// Why the configuration was rejected.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error(transparent)]
    Parse(#[from] Box<figment::Error>),
    #[error("security_contacts must not be empty (RFC 9116 requires Contact)")]
    NoSecurityContact,
    #[error("security_txt_valid_days must be between 1 and 364")]
    SecurityTxtValidity,
    #[error("tls.cert_file and tls.key_file are required: the server speaks TLS 1.3 only (CR-12)")]
    NoTls,
    #[error("issuer is required and must be an https URL without a trailing slash (L1-ADP-11)")]
    Issuer,
    #[error("the database section is required (OP-141 m.18)")]
    NoDatabase,
    #[error("the hsm section is required (OP-94)")]
    NoHsm,
    #[error("database pools must have at least one connection each")]
    PoolSize,
    #[error("the identity section is required (TN-10, CMP-22b)")]
    NoIdentity,
    #[error("login session lifetimes are outside the TN-36 ranges")]
    SessionLifetimes,
    #[error("login.redirect_to must be a path on the realm's origin")]
    RedirectTo,
    #[error("identity.realm_base must be an https origin without a path or trailing slash (TN-10)")]
    RealmBase,
    #[error(transparent)]
    SecretEnvironment(#[from] access_crypto::secret_file::SecretFileError),
}

impl Config {
    pub(crate) fn load() -> Result<Self, ConfigError> {
        // OP-129 m.3
        access_crypto::secret_file::refuse_secret_environment(
            std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()),
        )?;
        let file = std::env::var("ACCESS_CONFIG").unwrap_or_else(|_| "access.toml".to_owned());
        let config: Self = Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file(file))
            .merge(Env::prefixed("ACCESS_").ignore(&["CONFIG"]))
            .extract()
            .map_err(Box::new)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.security_contacts.is_empty() {
            return Err(ConfigError::NoSecurityContact);
        }
        if !(1..=364).contains(&self.security_txt_valid_days) {
            return Err(ConfigError::SecurityTxtValidity);
        }
        if self.tls.is_none() {
            return Err(ConfigError::NoTls);
        }
        match &self.issuer {
            Some(i) if Issuer::parse(i).is_ok() => {}
            _ => return Err(ConfigError::Issuer),
        }
        let db = self.database.as_ref().ok_or(ConfigError::NoDatabase)?;
        if [&db.sequencer, &db.app, &db.deriver, &db.router]
            .iter()
            .any(|r| r.pool == 0)
        {
            return Err(ConfigError::PoolSize);
        }
        if self.hsm.is_none() {
            return Err(ConfigError::NoHsm);
        }
        let identity = self.identity.as_ref().ok_or(ConfigError::NoIdentity)?;
        // OP-138, §17.9.6
        RealmBase::parse(&identity.realm_base).map_err(|_| ConfigError::RealmBase)?;
        if self.login.lifetimes().is_none() {
            return Err(ConfigError::SessionLifetimes);
        }
        let to = &self.login.redirect_to;
        if !to.starts_with('/') || to.starts_with("//") || to.contains('\\') {
            return Err(ConfigError::RedirectTo);
        }
        Ok(())
    }

    pub(crate) fn security_txt(&self) -> SecurityTxt {
        SecurityTxt {
            contacts: self.security_contacts.clone(),
            expires: OffsetDateTime::now_utc()
                .saturating_add(Duration::days(i64::from(self.security_txt_valid_days))),
            policy: self.security_policy.clone(),
            preferred_languages: Some("en, tr".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RAUTHY-008, §14.3
    #[test]
    fn default_listen_address_is_loopback() {
        assert!(Config::default().listen.ip().is_loopback());
    }

    fn role(user: &str) -> Role {
        Role {
            user: user.to_owned(),
            password_file: "/run/secrets/db".into(),
            pool: 4,
        }
    }

    fn with_tls() -> Config {
        Config {
            tls: Some(Tls {
                cert_file: "/run/tls/tls.crt".into(),
                key_file: "/run/tls/tls.key".into(),
                client_ca_file: None,
            }),
            issuer: Some("https://access.example".to_owned()),
            database: Some(Database {
                host: "db.internal".to_owned(),
                port: 5432,
                name: "access".to_owned(),
                root_cert_file: "/run/tls/db-root.pem".into(),
                durability: Durability::Replicated,
                sequencer: role("access_sequencer_login"),
                app: role("access_app_login"),
                deriver: role("access_deriver_login"),
                router: role("access_router_login"),
                archive: role("access_archive_login"),
                outbox_reader: role("access_outbox_reader_login"),
            }),
            hsm: Some(Hsm {
                module: "/usr/lib/softhsm/libsofthsm2.so".into(),
                token: "access".to_owned(),
                pin_file: "/run/secrets/pin".into(),
                paths: Vec::new(),
            }),
            identity: Some(Identity {
                realm_base: "https://id.access.example".to_owned(),
                signer: "/run/access/identity-signer.sock".into(),
                outbound_ca_file: None,
            }),
            ..Config::default()
        }
    }

    #[test]
    fn defaults_with_tls_are_valid() {
        with_tls().validate().unwrap();
    }

    // TN-36, OP-146 m.14 (c): lifetimes stay in range; a completed sign-in stays on the origin
    #[test]
    fn login_settings_are_checked() {
        let long = Config {
            login: Login {
                session_absolute_s: 10 * 365 * 86_400,
                ..Login::default()
            },
            ..with_tls()
        };
        assert!(matches!(
            long.validate(),
            Err(ConfigError::SessionLifetimes)
        ));
        for to in ["https://evil.example/", "//evil.example", "/\\evil.example"] {
            let away = Config {
                login: Login {
                    redirect_to: to.to_owned(),
                    ..Login::default()
                },
                ..with_tls()
            };
            assert!(
                matches!(away.validate(), Err(ConfigError::RedirectTo)),
                "{to}"
            );
        }
    }

    // CR-12, OP-52: no TLS, no start
    #[test]
    fn tls_is_required() {
        assert!(matches!(
            Config::default().validate(),
            Err(ConfigError::NoTls)
        ));
    }

    #[test]
    fn empty_security_contact_is_rejected() {
        let config = Config {
            security_contacts: Vec::new(),
            ..with_tls()
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::NoSecurityContact)
        ));
    }

    // OP-141 m.18 (g), (h), (i)
    #[test]
    fn the_authority_plane_is_not_optional() {
        let no_db = Config {
            database: None,
            ..with_tls()
        };
        assert!(matches!(no_db.validate(), Err(ConfigError::NoDatabase)));
        let no_hsm = Config {
            hsm: None,
            ..with_tls()
        };
        assert!(matches!(no_hsm.validate(), Err(ConfigError::NoHsm)));
        for issuer in [None, Some("http://a.example"), Some("https://a.example/")] {
            let config = Config {
                issuer: issuer.map(str::to_owned),
                ..with_tls()
            };
            assert!(matches!(config.validate(), Err(ConfigError::Issuer)));
        }
    }

    // OP-138, TN-10, §17.9.6, CMP-22b: the identity plane is not optional and its realm base
    // is a bare https origin
    #[test]
    fn the_identity_plane_is_not_optional() {
        let none = Config {
            identity: None,
            ..with_tls()
        };
        assert!(matches!(none.validate(), Err(ConfigError::NoIdentity)));
        for base in [
            "http://id.example",
            "https://id.example/",
            "https://id.example/realms",
            "https://ID.example",
            "https://id.example?x",
        ] {
            let config = Config {
                identity: Some(Identity {
                    realm_base: base.to_owned(),
                    signer: "/run/s.sock".into(),
                    outbound_ca_file: None,
                }),
                ..with_tls()
            };
            assert!(
                matches!(config.validate(), Err(ConfigError::RealmBase)),
                "{base}"
            );
        }
    }

    // OP-63, TI-9
    #[test]
    fn unknown_configuration_key_is_rejected() {
        let result: Result<Config, _> = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::string("dev_mode = true"))
            .extract();
        assert!(result.is_err());
    }
}
