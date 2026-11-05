//! Process configuration (OP-63 rule 4).

use std::path::PathBuf;

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};

/// Validated process configuration.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// `tracing` filter directives.
    pub(crate) log: String,
    /// The Unix socket the identity plane reaches the signer on (CMP-22b).
    pub(crate) socket: PathBuf,
    /// The directory of sealed realm keys; the only one the signer writes, never shared with
    /// the authority signer's.
    pub(crate) vault: PathBuf,
    /// User ids allowed to call (peer credentials).
    pub(crate) callers: Vec<u32>,
    /// Seconds between schedule rounds.
    pub(crate) tick_seconds: u64,
    /// The PKCS#11 token holding the KEK that seals realm keys (CR-21, T31).
    pub(crate) hsm: Option<Hsm>,
}

/// The PKCS#11 token.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hsm {
    /// The PKCS#11 module, loaded before the lockdown.
    pub(crate) module: PathBuf,
    /// Token label.
    pub(crate) token: String,
    /// User PIN file (OP-129 m.3).
    pub(crate) pin_file: PathBuf,
    /// Label of the KEK that seals realm keys.
    pub(crate) kek: String,
    /// Directories a file-backed token keeps its objects in, opened read-write.
    #[serde(default)]
    pub(crate) paths: Vec<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log: "info".to_owned(),
            socket: PathBuf::from("/run/access/identity-signer.sock"),
            vault: PathBuf::from("/var/lib/access/identity-signer"),
            callers: Vec::new(),
            tick_seconds: 30,
            hsm: None,
        }
    }
}

/// Why the configuration was rejected.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    /// The configuration could not be read.
    #[error(transparent)]
    Read(#[from] Box<figment::Error>),
    /// A secret was passed in the environment (OP-129 m.3).
    #[error(transparent)]
    Secret(#[from] access_crypto::secret_file::SecretFileError),
    /// Nobody may call.
    #[error("no caller user id")]
    NoCaller,
    /// No PKCS#11 token.
    #[error("no hsm section")]
    NoHsm,
    /// The schedule interval is outside 1 to 300 seconds.
    #[error("tick_seconds out of range")]
    Tick,
}

impl Config {
    /// Reads `ACCESS_IDENTITY_SIGNER_CONFIG` (default `access-identity-signer.toml`) and
    /// `ACCESS_IDENTITY_SIGNER_*`.
    ///
    /// # Errors
    /// [`ConfigError`].
    pub(crate) fn load() -> Result<Self, ConfigError> {
        // OP-129 m.3
        access_crypto::secret_file::refuse_secret_environment(
            std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()),
        )?;
        let file = std::env::var("ACCESS_IDENTITY_SIGNER_CONFIG")
            .unwrap_or_else(|_| "access-identity-signer.toml".to_owned());
        let config: Self = Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file(file))
            .merge(Env::prefixed("ACCESS_IDENTITY_SIGNER_").ignore(&["CONFIG"]))
            .extract()
            .map_err(Box::new)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.callers.is_empty() {
            return Err(ConfigError::NoCaller);
        }
        if self.hsm.is_none() {
            return Err(ConfigError::NoHsm);
        }
        if !(1..=300).contains(&self.tick_seconds) {
            return Err(ConfigError::Tick);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Config {
        Config {
            callers: vec![1000],
            hsm: Some(Hsm {
                module: "/usr/lib/softhsm/libsofthsm2.so".into(),
                token: "access".to_owned(),
                pin_file: "/run/secrets/pin".into(),
                kek: "access/identity/kek".to_owned(),
                paths: Vec::new(),
            }),
            ..Config::default()
        }
    }

    // OP-69: the local deployment's configuration is valid
    #[test]
    fn the_local_deployment_configuration_is_valid() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/compose/access/access-identity-signer.toml"
        );
        let config: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file_exact(path))
            .extract()
            .unwrap();
        config.validate().unwrap();
    }

    // CMP-22b, CR-21: callers, a token and a sane schedule are required
    #[test]
    fn incomplete_configurations_are_refused() {
        valid().validate().unwrap();
        let no_callers = Config {
            callers: Vec::new(),
            ..valid()
        };
        assert!(matches!(no_callers.validate(), Err(ConfigError::NoCaller)));
        let no_hsm = Config {
            hsm: None,
            ..valid()
        };
        assert!(matches!(no_hsm.validate(), Err(ConfigError::NoHsm)));
        let tick = Config {
            tick_seconds: 0,
            ..valid()
        };
        assert!(matches!(tick.validate(), Err(ConfigError::Tick)));
    }
}
