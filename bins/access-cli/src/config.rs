//! The configuration the command line reads: the server's own `access.toml`, of which each
//! command takes only its sections. Unknown sections are the server's and are ignored; unknown
//! keys inside a section the command reads are refused.

use std::path::{Path, PathBuf};

use figment::Figment;
use figment::providers::{Format, Toml};
use serde::Deserialize;

/// The sections the command line reads.
#[derive(Debug, Deserialize)]
pub(crate) struct File {
    /// The database (OP-141 m.18 (g)).
    pub(crate) database: Option<Database>,
}

/// How the deployment declares its durability (OP-24, HL-40).
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Durability {
    /// Synchronous standbys.
    Replicated,
    /// The small-provider single-node declaration.
    SingleNode,
}

/// One login role.
#[derive(Debug, Deserialize)]
pub(crate) struct Role {
    /// Login role.
    pub(crate) user: String,
    /// Credential file (OP-129 m.3); never the password itself.
    pub(crate) password_file: PathBuf,
}

/// The database section, as far as the command line needs it.
#[derive(Debug, Deserialize)]
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
    /// `access_migrator` login: only the migration job uses it (OP-55).
    #[serde(default)]
    pub(crate) migrator: Option<Role>,
}

/// Why the configuration cannot be used.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    /// The file does not parse.
    #[error("{0}")]
    Parse(#[from] Box<figment::Error>),
    /// The command's section is missing.
    #[error("the {0} section is required")]
    Missing(&'static str),
}

impl File {
    /// Reads `path`.
    ///
    /// # Errors
    /// [`ConfigError::Parse`].
    pub(crate) fn load(path: &Path) -> Result<Self, ConfigError> {
        Figment::from(Toml::file_exact(path))
            .extract()
            .map_err(|e| ConfigError::Parse(Box::new(e)))
    }

    /// The database section with its migration role.
    ///
    /// # Errors
    /// [`ConfigError::Missing`].
    pub(crate) fn migration(&self) -> Result<(&Database, &Role), ConfigError> {
        let db = self
            .database
            .as_ref()
            .ok_or(ConfigError::Missing("database"))?;
        let role = db
            .migrator
            .as_ref()
            .ok_or(ConfigError::Missing("database.migrator"))?;
        Ok((db, role))
    }
}
