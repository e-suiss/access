//! The replica's configuration file: one `key value` per line, `#` starts a comment.
//!
//! ```text
//! name acme-replica                       the name its acks carry, as the domain declares it
//! key /etc/access-replica/key.pk8         its Ed25519 PKCS#8 ack key
//! state /var/lib/access-replica           its own files
//! server http://127.0.0.1:8443            the provider's listener (a local TLS client in front)
//! domain <DomainID, base64url>
//! export <mirror run id, base64url>       the run the operator's audit export Exercise started
//! binding <Ed25519 binding key, base64url> the domain's binding keys; one line each
//! listen 127.0.0.1:8485                   the advisory read endpoint
//! ```
//!
//! Keys are read from the files the operator names, never from an argument or the environment.

use std::net::SocketAddr;
use std::path::PathBuf;

use access_kernel::digest::Digest;
use access_kernel::json::b64url_decode;
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::cose::{Algorithm, KeySet, PublicKey};

/// The parsed configuration.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    /// The replica's declared name.
    pub(crate) name: String,
    /// PKCS#8 Ed25519 ack key file.
    pub(crate) key: PathBuf,
    /// State directory.
    pub(crate) state: PathBuf,
    /// `host:port` of the provider's listener.
    pub(crate) server: String,
    /// The domain.
    pub(crate) domain: Digest,
    /// The mirror run.
    pub(crate) export: [u8; 32],
    /// The domain's binding keys.
    pub(crate) bindings: KeySet,
    /// The advisory read endpoint.
    pub(crate) listen: SocketAddr,
}

fn key32(text: &str) -> Result<[u8; 32], String> {
    b64url_decode(text)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("not a 32-byte base64url value: {text}"))
}

fn server(v: &str) -> Result<String, String> {
    let host = v
        .strip_prefix("http://")
        .ok_or("server: an http:// address of a local listener")?
        .trim_end_matches('/');
    let local = host.starts_with("127.0.0.1:") || host.starts_with("[::1]:");
    if !local || host.contains('/') {
        return Err("server: http://127.0.0.1:<port>; a remote provider is reached through a local TLS client".into());
    }
    Ok(host.to_owned())
}

/// Parses `text`.
pub(crate) fn parse(text: &str) -> Result<Config, String> {
    let (mut name, mut key, mut state, mut srv, mut domain, mut export, mut listen) =
        (None, None, None, None, None, None, None);
    let mut bindings = KeySet {
        keys: std::collections::BTreeMap::new(),
        allowed: [Algorithm::Ed25519].into_iter().collect(),
    };
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
                let ok = !v.is_empty()
                    && v.len() <= suiss_ledger::replica::mirror::MAX_NAME
                    && v.bytes().all(|b| b.is_ascii_graphic());
                if !ok {
                    return Err(at("bad name".into()));
                }
                name = Some(v.to_owned());
            }
            "key" => key = Some(PathBuf::from(v)),
            "state" => state = Some(PathBuf::from(v)),
            "server" => srv = Some(server(v).map_err(at)?),
            "domain" => domain = Some(Digest(key32(v).map_err(at)?)),
            "export" => export = Some(key32(v).map_err(at)?),
            "binding" => {
                let k = PublicKey::Ed25519(key32(v).map_err(at)?);
                bindings
                    .insert(thumbprint(&k), k)
                    .map_err(|e| at(e.to_string()))?;
            }
            "listen" => listen = Some(v.parse().map_err(|_| at("bad listen address".into()))?),
            other => return Err(at(format!("unknown key {other}"))),
        }
    }
    if bindings.keys.is_empty() {
        return Err("at least one binding key".into());
    }
    Ok(Config {
        name: name.ok_or("name is required")?,
        key: key.ok_or("key is required")?,
        state: state.ok_or("state is required")?,
        server: srv.ok_or("server is required")?,
        domain: domain.ok_or("domain is required")?,
        export: export.ok_or("export is required")?,
        bindings,
        listen: listen.ok_or("listen is required")?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn b64(n: u8) -> String {
        access_kernel::json::b64url_encode(&[n; 32])
    }

    // OP-158 m.3 (f), TI-9
    #[test]
    fn the_server_is_a_local_listener_and_every_key_is_required() {
        let key = suiss_crypto::signer::SoftSigner::generate_ed25519()
            .unwrap()
            .0;
        let PublicKey::Ed25519(binding) = suiss_crypto::signer::Signer::public_key(&key) else {
            panic!("ed25519");
        };
        let binding = access_kernel::json::b64url_encode(&binding);
        let good = format!(
            "name r\nkey /k\nstate /s\nserver http://127.0.0.1:1\ndomain {}\nexport {}\nbinding {binding}\nlisten 127.0.0.1:0\n",
            b64(1),
            b64(2)
        );
        let c = parse(&good).unwrap();
        assert_eq!(c.server, "127.0.0.1:1");
        assert_eq!(c.bindings.keys.len(), 1);
        let remote = good.replace("http://127.0.0.1:1", "http://provider.example:443");
        assert!(parse(&remote).is_err());
        let plain_remote = good.replace("http://127.0.0.1:1", "https://provider.example");
        assert!(parse(&plain_remote).is_err());
        let no_binding = good.replace(&format!("binding {binding}\n"), "");
        assert!(parse(&no_binding).is_err());
        assert!(parse(&good.replace("name r\n", "")).is_err());
        assert!(parse(&format!("{good}extra x\n")).is_err());
    }
}
