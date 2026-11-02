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
    /// The Unix socket callers reach the signer on (CMP-22).
    pub(crate) socket: PathBuf,
    /// The directory of sealed keys; the only one the signer writes.
    pub(crate) vault: PathBuf,
    /// User ids allowed to call (peer credentials).
    pub(crate) callers: Vec<u32>,
    /// Seconds between schedule rounds.
    pub(crate) tick_seconds: u64,
    /// The PKCS#11 token holding the binding keys and the KEK (CR-21, CR-29).
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
    /// Label of the KEK that seals operational keys.
    pub(crate) kek: String,
    /// Directories a file-backed token keeps its objects in, opened read-write.
    #[serde(default)]
    pub(crate) paths: Vec<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log: "info".to_owned(),
            socket: PathBuf::from("/run/access/signer.sock"),
            vault: PathBuf::from("/var/lib/access/signer"),
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
    /// Reads `ACCESS_SIGNER_CONFIG` (default `access-signer.toml`) and `ACCESS_SIGNER_*`.
    ///
    /// # Errors
    /// [`ConfigError`].
    pub(crate) fn load() -> Result<Self, ConfigError> {
        // OP-129 m.3
        access_crypto::secret_file::refuse_secret_environment(
            std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()),
        )?;
        let file = std::env::var("ACCESS_SIGNER_CONFIG")
            .unwrap_or_else(|_| "access-signer.toml".to_owned());
        let config: Self = Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file(file))
            .merge(Env::prefixed("ACCESS_SIGNER_").ignore(&["CONFIG"]))
            .extract()
            .map_err(Box::new)?;
        if config.callers.is_empty() {
            return Err(ConfigError::NoCaller);
        }
        if config.hsm.is_none() {
            return Err(ConfigError::NoHsm);
        }
        if !(1..=300).contains(&config.tick_seconds) {
            return Err(ConfigError::Tick);
        }
        Ok(config)
    }
}
