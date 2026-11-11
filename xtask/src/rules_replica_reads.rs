//! `replica-reads` (OPI-2, OP-54-RL2, OP-158 m.3 (n)): no security query family is served from the read replica pool.
//!
//! The replica is reachable only through `access_store::replica_reads::ReplicaReads`, and only
//! the admin search and listing, report and audit-trail readers hold one ([`HOLDERS`]). Every
//! other source file that names it, or the configured `replica_host`, is a violation: a
//! revocation, session, lock, credential, counter, consent or membership read always goes to the
//! primary (OP-27).

use std::path::Path;

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};

const RULE: &str = "replica-reads";

/// The files that may hold the replica: where it is defined, configured, opened, and the admin
/// listing reader (§17.4.6).
const HOLDERS: [&str; 5] = [
    "crates/store/src/replica_reads.rs",
    "crates/store/src/lib.rs",
    "bins/access-server/src/main.rs",
    "bins/access-server/src/config.rs",
    "bins/access-server/src/admin/realm.rs",
];

/// The other files that may name the configuration key: the command line's mirror of it.
const KEY_MIRRORS: [&str; 1] = ["bins/access-cli/src/config.rs"];

/// What names the replica in a source line.
pub(crate) fn names_replica(line: &str) -> bool {
    line.contains("ReplicaReads")
        || line.contains("replica_reads::")
        || line.contains("replica_host")
}

/// Runs `replica-reads`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let r = rel(root, &path);
        if std::path::Path::new(&r)
            .extension()
            .is_none_or(|e| e != "rs")
            || is_test_file(&r)
            || r.starts_with("xtask/")
            || HOLDERS.contains(&r.as_str())
        {
            continue;
        }
        let src = read(&path)?;
        let test_tail = src.find("#[cfg(test)]").unwrap_or(src.len());
        for (i, line) in src.get(..test_tail).unwrap_or(&src).lines().enumerate() {
            if !names_replica(line) {
                continue;
            }
            if KEY_MIRRORS.contains(&r.as_str()) && line.contains("replica_host") {
                continue;
            }
            out.push(Violation {
                rule: RULE,
                path: r.clone().into(),
                message: format!(
                    "line {}: only the admin listing readers hold the read replica; security reads go to the primary (OPI-2, OP-54-RL2)",
                    i.saturating_add(1)
                ),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OPI-2, OP-54-RL2
    #[test]
    fn opi_2_a_replica_named_outside_the_listing_readers_is_found() {
        assert!(names_replica(
            "    reads: access_store::replica_reads::ReplicaReads,"
        ));
        assert!(names_replica("let p = reads.replica_host.clone();"));
        assert!(!names_replica("let p = &self.app;"));
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let v = check(root).unwrap();
        assert!(
            v.is_empty(),
            "{:?}",
            v.iter().map(|v| (&v.path, &v.message)).collect::<Vec<_>>()
        );
    }
}
