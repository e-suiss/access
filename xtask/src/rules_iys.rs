//! `no-iys-client` (IDP-37 (4), B23, E42, OP-156 m.3 (c), Ek B 5370): Access never writes to
//! İYS; Relay alone does. No file under `crates/`, `bins/` or `services/` may name an İYS host,
//! so no client to it can be configured or built here. Comments and texts may name İYS itself.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{read, rel, walk};

const RULE: &str = "no-iys-client";

/// The İYS hosts, lower case.
const HOSTS: &[&str] = &["iys.org.tr", "iys.gov.tr"];

const ROOTS: &[&str] = &["crates/", "bins/", "services/"];

const EXTENSIONS: &[&str] = &[
    "rs", "toml", "json", "yml", "yaml", "sh", "conf", "env", "sql", "ts", "tsx",
];

/// The lines of `src` that name an İYS host.
pub(crate) fn hits(src: &str) -> Vec<usize> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| {
            let l = l.to_ascii_lowercase();
            HOSTS.iter().any(|h| l.contains(h))
        })
        .map(|(i, _)| i.saturating_add(1))
        .collect()
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if !ROOTS.iter().any(|r| rel_path.starts_with(r)) || !EXTENSIONS.contains(&ext) {
            continue;
        }
        for line in hits(&read(&path)?) {
            out.push(Violation {
                rule: RULE,
                path: PathBuf::from(format!("{rel_path}:{line}")),
                message: "names an İYS host; only Relay writes to İYS (IDP-37 (4), B23, E42)"
                    .to_owned(),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // IDP-37 (4), B23, E42
    #[test]
    fn an_iys_host_is_found_and_the_word_alone_is_not() {
        assert_eq!(hits("let u = \"https://API.iys.org.tr/sps\";\n"), vec![1]);
        assert_eq!(hits("a\nhost = \"x.iys.gov.tr\"\n"), vec![2]);
        assert_eq!(
            hits("// İYS records go through Relay\nlet iys = true;\n"),
            Vec::<usize>::new()
        );
    }
}
