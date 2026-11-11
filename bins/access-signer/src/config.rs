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
    /// The binding key ceremony transcript and its pin (CR-29, OP-157 m.3 (x)).
    pub(crate) ceremony: Option<Ceremony>,
    /// CR-34: the hardening mode.
    pub(crate) hardening: Hardening,
    /// CR-34: the backend of the key memory arena.
    pub(crate) secret_memory: SecretMemoryKind,
    /// Key documents the arena holds at once (256 bytes each, counted against
    /// `RLIMIT_MEMLOCK`).
    pub(crate) secret_slots: usize,
}

/// CR-34: the hardening mode; a signer runs only `paranoid` (`PR_SET_DUMPABLE=0`,
/// `RLIMIT_CORE=0`, locked or secret key memory). There is no other mode to choose.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Hardening {
    /// The only mode of a signer process.
    #[default]
    Paranoid,
}

/// CR-34, OP-158 m.3 (y): where key documents live, named explicitly; a backend the host
/// lacks refuses the start, it never falls back to the other.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SecretMemoryKind {
    /// `memfd_secret(2)`.
    #[default]
    MemfdSecret,
    /// `mlock` + `MADV_DONTDUMP`.
    Mlock,
}

impl SecretMemoryKind {
    /// The sandbox backend.
    pub(crate) const fn backend(self) -> suiss_sandbox::SecretBackend {
        match self {
            Self::MemfdSecret => suiss_sandbox::SecretBackend::MemfdSecret,
            Self::Mlock => suiss_sandbox::SecretBackend::Mlock,
        }
    }
}

/// The binding key ceremony.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ceremony {
    /// The transcript the ceremony commands append to; the signer only reads it.
    pub(crate) transcript: PathBuf,
    /// A read-only file holding the hex digest of the transcript's first entry.
    pub(crate) genesis_file: PathBuf,
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
            ceremony: None,
            hardening: Hardening::Paranoid,
            secret_memory: SecretMemoryKind::MemfdSecret,
            secret_slots: 1024,
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
    /// No binding key ceremony (CR-29).
    #[error("no ceremony section")]
    NoCeremony,
    /// The schedule interval is outside 1 to 300 seconds.
    #[error("tick_seconds out of range")]
    Tick,
    /// The key memory arena is outside 16 to 65 536 slots (CR-34).
    #[error("secret_slots out of range")]
    SecretSlots,
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
        if config.ceremony.is_none() {
            return Err(ConfigError::NoCeremony);
        }
        if !(1..=300).contains(&config.tick_seconds) {
            return Err(ConfigError::Tick);
        }
        if !(16..=65_536).contains(&config.secret_slots) {
            return Err(ConfigError::SecretSlots);
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    /// The `name: |` block of the k8s configmap, unindented (OP-158 m.3 (y)).
    fn configmap_toml(name: &str) -> String {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/k8s/configmap.yaml"
        ))
        .unwrap();
        let head = format!("  {name}: |");
        text.lines()
            .skip_while(|l| *l != head)
            .skip(1)
            .take_while(|l| l.is_empty() || l.starts_with("    "))
            .map(|l| l.strip_prefix("    ").unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n")
    }

    // CMP-22a, CR-34, OP-158
    #[test]
    fn the_deployed_configurations_parse() {
        for text in [
            configmap_toml("signer.toml"),
            std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deploy/compose/access/access-signer.toml"
            ))
            .unwrap(),
        ] {
            let config: Config = Figment::from(Serialized::defaults(Config::default()))
                .merge(Toml::string(&text))
                .extract()
                .unwrap();
            assert!(config.hsm.is_some() && config.ceremony.is_some());
            assert_ne!(config.callers.len(), 0);
            assert_eq!(config.hardening, Hardening::Paranoid);
            assert!((16..=65_536).contains(&config.secret_slots));
        }
    }
}
