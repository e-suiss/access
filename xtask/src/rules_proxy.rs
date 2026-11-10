//! `proxy-engine` (IDP-30 (2), B22, OP-156 m.3 (m), Ek B 5369): the Access Proxy engine is never
//! written from scratch. `services/proxy` renders configuration for Envoy, Caddy and Traefik and
//! starts the engine; it depends on no HTTP server crate and opens no listening socket.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{read, rel, walk};

const RULE: &str = "proxy-engine";

const MANIFEST: &str = "services/proxy/Cargo.toml";

const SOURCES: &str = "services/proxy/src/";

/// Crates that serve HTTP or accept connections.
const SERVERS: &[&str] = &[
    "actix-server",
    "actix-web",
    "axum",
    "axum-server",
    "gotham",
    "h2",
    "h3",
    "hyper",
    "hyper-util",
    "pingora",
    "pingora-core",
    "pingora-proxy",
    "poem",
    "quinn",
    "rocket",
    "rouille",
    "salvo",
    "tide",
    "tiny_http",
    "tokio",
    "tower-http",
    "warp",
];

/// Listening sockets in source.
const LISTENERS: &[&str] = &["TcpListener", "UnixListener", "UdpSocket"];

/// The server crates `manifest` depends on, in any dependency table.
pub(crate) fn servers(manifest: &str) -> Result<Vec<String>, String> {
    let doc: toml::Table = toml::from_str(manifest).map_err(|e| format!("{MANIFEST}: {e}"))?;
    let mut out = Vec::new();
    let mut tables: Vec<&toml::Table> = Vec::new();
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = doc.get(key).and_then(toml::Value::as_table) {
            tables.push(t);
        }
    }
    if let Some(targets) = doc.get("target").and_then(toml::Value::as_table) {
        for t in targets.values().filter_map(toml::Value::as_table) {
            for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(d) = t.get(key).and_then(toml::Value::as_table) {
                    tables.push(d);
                }
            }
        }
    }
    for t in tables {
        for (name, spec) in t {
            let package = spec
                .get("package")
                .and_then(toml::Value::as_str)
                .unwrap_or(name);
            if SERVERS.contains(&package) {
                out.push(String::from(package));
            }
        }
    }
    Ok(out)
}

/// The lines of `src` that name a listening socket.
pub(crate) fn listeners(src: &str) -> Vec<usize> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| LISTENERS.iter().any(|w| l.contains(w)))
        .map(|(i, _)| i.saturating_add(1))
        .collect()
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let manifest = root.join(MANIFEST);
    if !manifest.exists() {
        return Ok(out);
    }
    for name in servers(&read(&manifest)?)? {
        out.push(Violation {
            rule: RULE,
            path: PathBuf::from(MANIFEST),
            message: format!(
                "depends on {name}; the proxy engine is Envoy or Caddy, never written here (IDP-30 (2), Ek B 5369)"
            ),
        });
    }
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if !rel_path.starts_with(SOURCES) || path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        for line in listeners(&read(&path)?) {
            out.push(Violation {
                rule: RULE,
                path: PathBuf::from(format!("{rel_path}:{line}")),
                message: "opens a listening socket; the engine serves, access-proxy only renders (IDP-30 (2), Ek B 5369)".to_owned(),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::assert_is_empty, reason = "test code")]

    use super::*;

    // IDP-30 (2), B22, Ek B 5369
    #[test]
    fn an_http_server_crate_or_a_listener_is_found() {
        let m = "[dependencies]\nserde = \"1\"\nweb = { package = \"axum\", version = \"0.8\" }\n\n[dev-dependencies]\nhyper = \"1\"\n\n[target.'cfg(unix)'.dependencies]\ntokio = \"1\"\n";
        assert_eq!(servers(m).unwrap(), vec!["axum", "hyper", "tokio"]);
        assert!(
            servers("[dependencies]\ntoml = \"1\"\n")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            listeners("use std::net::TcpListener;\nlet x = 1;\nUnixListener::bind(p)\n"),
            vec![1, 3]
        );
        assert!(listeners("let c = Command::new(\"envoy\");\n").is_empty());
    }
}
