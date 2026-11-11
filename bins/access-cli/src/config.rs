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
    /// `incident contain` (OP-157 m.3 (i)).
    pub(crate) incident: Option<Incident>,
}

/// Where `incident contain` declares a compromise and as whom (OP-157 m.3 (i)): the public
/// listener, reached with the PEP certificate the realm accepted its declarant over. Credentials
/// are files (OP-129 m.3).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Incident {
    /// The public listener, `https://host[:port]`.
    pub(crate) api: String,
    /// PEM root the listener's certificate chains to.
    pub(crate) ca_file: PathBuf,
    /// PEM certificate of the PEP the declarant's Claims arrive over.
    pub(crate) pep_cert_file: PathBuf,
    /// PEM private key of that certificate.
    pub(crate) pep_key_file: PathBuf,
    /// The realm's governing domain, base64url.
    pub(crate) domain: String,
    /// The accepted declarant Party, base64url.
    pub(crate) declarant: String,
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
#[serde(deny_unknown_fields)]
pub(crate) struct Role {
    /// Login role.
    pub(crate) user: String,
    /// Credential file (OP-129 m.3); never the password itself.
    pub(crate) password_file: PathBuf,
    /// The server's pool size; the command line opens one connection.
    #[serde(default, rename = "pool")]
    _pool: Option<u32>,
}

/// The database section, as far as the command line needs it. The server's other logins are
/// read and checked but not used, so a misspelt key is refused here as in the server (OP-63).
#[derive(Debug, Deserialize)]
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
    /// `access_migrator` login: only the migration job uses it (OP-55).
    #[serde(default)]
    pub(crate) migrator: Option<Role>,
    /// The server's logins, unused here.
    #[serde(default, rename = "sequencer")]
    _sequencer: Option<Role>,
    #[serde(default, rename = "app")]
    _app: Option<Role>,
    #[serde(default, rename = "deriver")]
    _deriver: Option<Role>,
    #[serde(default, rename = "router")]
    _router: Option<Role>,
    #[serde(default, rename = "archive")]
    _archive: Option<Role>,
    #[serde(default, rename = "outbox_reader")]
    _outbox_reader: Option<Role>,
    #[serde(default, rename = "checkpointer")]
    _checkpointer: Option<Role>,
    /// The server's read replica, unused here.
    #[serde(default, rename = "replica_host")]
    _replica_host: Option<String>,
    /// The server's management pool size (OP-158 m.3 (v)), unused here.
    #[serde(default, rename = "admin_pool")]
    _admin_pool: Option<u32>,
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn parse(text: &str) -> Result<File, Box<figment::Error>> {
        Figment::from(Toml::string(text))
            .extract()
            .map_err(Box::new)
    }

    // A-9, OP-63, TI-9
    #[test]
    fn unknown_database_keys_are_refused() {
        let server = include_str!("../../../deploy/compose/access/access.toml");
        let file = parse(server).unwrap();
        assert!(file.migration().is_ok());
        let base = "[database]\nhost = \"h\"\nport = 5432\nname = \"access\"\n\
                    root_cert_file = \"/r.pem\"\ndurability = \"replicated\"\n";
        assert!(
            parse(&format!(
                "{base}migrater = {{ user = \"m\", password_file = \"/p\" }}\n"
            ))
            .is_err()
        );
        assert!(
            parse(&format!(
                "{base}migrator = {{ user = \"m\", password_file = \"/p\", insecure = true }}\n"
            ))
            .is_err()
        );
        assert!(
            parse(&format!(
                "{base}migrator = {{ user = \"m\", password_file = \"/p\", pool = 1 }}\n"
            ))
            .is_ok()
        );
    }
}
