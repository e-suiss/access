//! Process configuration (OP-63 rule 4).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use access_http::SecurityTxt;
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
}

/// TLS files, read once before the lockdown.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Tls {
    /// PEM certificate chain, leaf first.
    pub(crate) cert_file: PathBuf,
    /// PEM private key; readable by the server's user only (CR-35).
    pub(crate) key_file: PathBuf,
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

    fn with_tls() -> Config {
        Config {
            tls: Some(Tls {
                cert_file: "/run/tls/tls.crt".into(),
                key_file: "/run/tls/tls.key".into(),
            }),
            ..Config::default()
        }
    }

    #[test]
    fn defaults_with_tls_are_valid() {
        with_tls().validate().unwrap();
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

    // OP-63, TI-9
    #[test]
    fn unknown_configuration_key_is_rejected() {
        let result: Result<Config, _> = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::string("dev_mode = true"))
            .extract();
        assert!(result.is_err());
    }
}
