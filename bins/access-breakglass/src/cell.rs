//! One cell's break-glass directory (§17.7.3 principle 10): `/etc/access/breakglass/<cell>/`
//! holds `cell` (settings), `keys` (the key set) and `directive.key` (the directive signing
//! seed, owner-only); the state directory holds the trail, the used nonces and the spent key
//! generation.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use access_crypto::breakglass::KeySet;

use crate::Failure;

/// The `cell` file:
///
/// ```text
/// name eu-1
/// ops /var/lib/access/ops
/// alarm /usr/local/libexec/page-on-call
/// syslog unix:/dev/log
/// siem 10.0.0.5:6514
/// config /etc/access/access.toml
/// health 127.0.0.1:9090
/// state /var/lib/access/breakglass/eu-1
/// ```
#[derive(Debug)]
pub(crate) struct Cell {
    pub(crate) dir: PathBuf,
    pub(crate) name: String,
    pub(crate) ops: PathBuf,
    pub(crate) alarm: PathBuf,
    pub(crate) syslog: Option<String>,
    pub(crate) siem: Option<String>,
    pub(crate) config: Option<PathBuf>,
    pub(crate) health: Option<String>,
    pub(crate) state: PathBuf,
}

fn cell_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Cell {
    pub(crate) fn load(dir: &Path) -> Result<Self, Failure> {
        let text = fs::read_to_string(dir.join("cell")).map_err(|_| Failure::Setup("cell file"))?;
        let mut name = None;
        let mut ops = None;
        let mut alarm = None;
        let mut syslog = None;
        let mut siem = None;
        let mut config = None;
        let mut health = None;
        let mut state = None;
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once(char::is_whitespace)
                .map(|(k, v)| (k, v.trim().to_owned()))
                .ok_or(Failure::Setup("cell file line"))?;
            let slot = match key {
                "name" => &mut name,
                "ops" => &mut ops,
                "alarm" => &mut alarm,
                "syslog" => &mut syslog,
                "siem" => &mut siem,
                "config" => &mut config,
                "health" => &mut health,
                "state" => &mut state,
                _ => return Err(Failure::Setup("cell file key")),
            };
            if slot.replace(value).is_some() {
                return Err(Failure::Setup("cell file key repeated"));
            }
        }
        let name = name.ok_or(Failure::Setup("cell name"))?;
        if !cell_name(&name) {
            return Err(Failure::Setup("cell name"));
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            name,
            ops: ops
                .map(PathBuf::from)
                .ok_or(Failure::Setup("ops directory"))?,
            // §17.7.3 principle 7
            alarm: alarm
                .map(PathBuf::from)
                .ok_or(Failure::Setup("alarm hook"))?,
            syslog,
            siem,
            config: config.map(PathBuf::from),
            health,
            state: state.map_or_else(|| dir.join("state"), PathBuf::from),
        })
    }

    pub(crate) fn keys(&self) -> Result<KeySet, Failure> {
        let text = fs::read_to_string(self.dir.join("keys")).map_err(|_| Failure::Setup("keys"))?;
        KeySet::parse(&text).map_err(|e| Failure::Refused(e.code()))
    }

    pub(crate) fn directive_key(&self) -> PathBuf {
        self.dir.join("directive.key")
    }

    pub(crate) fn directives(&self) -> PathBuf {
        self.ops.join("directives")
    }

    pub(crate) fn trail(&self) -> PathBuf {
        self.state.join("trail")
    }

    fn nonces(&self) -> PathBuf {
        self.state.join("nonces")
    }

    fn spent(&self) -> PathBuf {
        self.state.join("spent")
    }

    /// Whether `nonce` was used before (§17.7.3 principle 8).
    pub(crate) fn nonce_used(&self, nonce: &str) -> Result<bool, Failure> {
        match fs::read_to_string(self.nonces()) {
            Ok(text) => Ok(text.lines().any(|l| l.trim() == nonce)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(Failure::Setup("nonce file")),
        }
    }

    /// Records `nonce` as used, durably, before anything it allows happens.
    pub(crate) fn use_nonce(&self, nonce: &str) -> Result<(), Failure> {
        append(&self.nonces(), &format!("{nonce}\n")).map_err(|_| Failure::Setup("nonce file"))
    }

    /// The key generation the last use spent; a new document needs a rotated key set.
    pub(crate) fn spent_generation(&self) -> Result<Option<u64>, Failure> {
        match fs::read_to_string(self.spent()) {
            Ok(text) => text
                .lines()
                .filter_map(|l| l.trim().parse::<u64>().ok())
                .max()
                .map_or(Ok(None), |g| Ok(Some(g))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Failure::Setup("spent file")),
        }
    }

    pub(crate) fn spend(&self, generation: u64) -> Result<(), Failure> {
        append(&self.spent(), &format!("{generation}\n")).map_err(|_| Failure::Setup("spent file"))
    }

    /// Installs a rotated key set in place of the current one.
    pub(crate) fn install_keys(&self, text: &str) -> Result<(), Failure> {
        replace(&self.dir.join("keys"), text.as_bytes()).map_err(|_| Failure::Setup("keys"))
    }

    pub(crate) fn ensure_state(&self) -> Result<(), Failure> {
        fs::create_dir_all(&self.state).map_err(|_| Failure::Setup("state directory"))
    }
}

/// Appends `line` and syncs it to disk.
pub(crate) fn append(path: &Path, line: &str) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.sync_all()
}

/// Writes `bytes` to `path` through a synced temporary file and a rename.
pub(crate) fn replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}
