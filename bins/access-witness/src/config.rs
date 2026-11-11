//! The witness's configuration file: one `key value…` per line, `#` starts a comment.
//!
//! ```text
//! name witness.example.org
//! key /etc/access-witness/key.pk8
//! state /var/lib/access-witness
//! listen 127.0.0.1:8484
//! operator Example Witness Ltd
//! log <domain, base64url> <binding public key, base64url>…
//! ```
//!
//! The key is read from the file the operator names, never from an argument or the
//! environment.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use access_kernel::digest::Digest;
use access_kernel::json::b64url_decode;
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::cose::{Algorithm, KeySet, PublicKey};

/// One log the witness serves.
#[derive(Clone, Debug)]
pub(crate) struct Log {
    /// The domain.
    pub(crate) domain: Digest,
    /// Binding keys the witness trusts for it.
    pub(crate) bindings: KeySet,
}

/// The parsed configuration.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    /// Cosigner key name.
    pub(crate) name: String,
    /// PKCS#8 Ed25519 key file.
    pub(crate) key: PathBuf,
    /// State directory.
    pub(crate) state: PathBuf,
    /// Listen address.
    pub(crate) listen: SocketAddr,
    /// The witness operator, as its independence declaration names it (SI-12).
    pub(crate) operator: String,
    /// Logs by origin.
    pub(crate) logs: BTreeMap<String, Log>,
}

/// The origin of `domain`'s checkpoints (L0-ENC-20).
pub(crate) fn origin(domain: &Digest) -> String {
    format!("sha-256:{}", access_kernel::json::b64url_encode(&domain.0))
}

fn key32(text: &str) -> Result<[u8; 32], String> {
    b64url_decode(text)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("not a 32-byte base64url value: {text}"))
}

/// Parses `text`.
pub(crate) fn parse(text: &str) -> Result<Config, String> {
    let (mut name, mut key, mut state, mut listen, mut operator) = (None, None, None, None, None);
    let mut logs = BTreeMap::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (k, v) = line
            .split_once(' ')
            .map_or((line, ""), |(k, v)| (k, v.trim()));
        let at = |e: String| format!("line {}: {e}", n.saturating_add(1));
        match k {
            "name" => {
                suiss_crypto::note::check_name(v).map_err(|_| at("bad name".into()))?;
                name = Some(v.to_owned());
            }
            "key" => key = Some(PathBuf::from(v)),
            "state" => state = Some(PathBuf::from(v)),
            "listen" => {
                listen = Some(
                    v.parse::<SocketAddr>()
                        .map_err(|_| at(format!("bad address {v}")))?,
                );
            }
            "operator" if !v.is_empty() => operator = Some(v.to_owned()),
            "log" => {
                let mut words = v.split_whitespace();
                let domain = Digest(key32(words.next().unwrap_or_default()).map_err(at)?);
                let mut bindings = KeySet::default();
                bindings.allowed.insert(Algorithm::Ed25519);
                for w in words {
                    let public = PublicKey::Ed25519(key32(w).map_err(at)?);
                    let kid = thumbprint(&public);
                    bindings
                        .insert(kid, public)
                        .map_err(|_| at(format!("bad binding key {w}")))?;
                }
                if bindings.keys.is_empty() {
                    return Err(at("a log needs at least one binding key".into()));
                }
                logs.insert(origin(&domain), Log { domain, bindings });
            }
            other => return Err(at(format!("unknown setting {other}"))),
        }
    }
    let need = |what: &str| format!("missing `{what}`");
    Ok(Config {
        name: name.ok_or_else(|| need("name"))?,
        key: key.ok_or_else(|| need("key"))?,
        state: state.ok_or_else(|| need("state"))?,
        listen: listen.ok_or_else(|| need("listen"))?,
        operator: operator.ok_or_else(|| need("operator"))?,
        logs,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn a_config_names_its_key_file_and_logs() {
        let d = access_kernel::json::b64url_encode(&[7; 32]);
        let k = access_kernel::json::b64url_encode(&[
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ]);
        let text = format!(
            "# witness\nname w.example\nkey /k\nstate /s\nlisten 127.0.0.1:0\noperator Ex Ltd\nlog {d} {k}\n"
        );
        let c = parse(&text).unwrap();
        assert_eq!(c.operator, "Ex Ltd");
        assert_eq!(c.logs.len(), 1);
        assert!(parse(&text.replace("operator Ex Ltd\n", "")).is_err());
        assert!(parse(&format!("{text}log {d}\n")).is_err());
        assert!(parse(&format!("{text}secret abc\n")).is_err());
    }
}
