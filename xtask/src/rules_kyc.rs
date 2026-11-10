//! `kyc-boundary` (IDP-34, §10.3.1, OP-156 m.3 (r), Ek B 5368): Access is not a KYC
//! application. No file under `crates/`, `bins/`, `services/`, `sdks/` or `web/` may carry a
//! chip read, a face match or a liveness check: remote identity proofing happens at an
//! external provider, whose result is its `identity_proofing` Claim. The declaration of what
//! Access does not do is the one file allowed to name them.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{read, rel, walk};

const RULE: &str = "kyc-boundary";

/// What an implementation of proofing would name, lower case.
const MARKERS: &[&str] = &[
    "check_liveness",
    "liveness_check",
    "liveness_detection",
    "liveness_score",
    "passive_liveness",
    "active_liveness",
    "face_match",
    "facematch",
    "face_embedding",
    "face_template",
    "iso14443",
    "iso7816",
    "icao9303",
    "icao_9303",
    "mrz_",
    "apdu",
    "nfc_read",
    "read_chip",
];

const ROOTS: &[&str] = &["crates/", "bins/", "services/", "sdks/", "web/"];

const ALLOWED: &[&str] = &["crates/identity-signals/src/domain/boundary.rs"];

const EXTENSIONS: &[&str] = &["rs", "toml", "ts", "tsx", "js", "swift", "kt", "py"];

/// The lines of `src` that name a proofing capability.
pub(crate) fn hits(src: &str) -> Vec<usize> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| {
            let l = l.to_ascii_lowercase();
            MARKERS.iter().any(|m| l.contains(m))
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
        if !ROOTS.iter().any(|r| rel_path.starts_with(r))
            || !EXTENSIONS.contains(&ext)
            || ALLOWED.contains(&rel_path.as_str())
            || rel_path.contains("/node_modules/")
        {
            continue;
        }
        for line in hits(&read(&path)?) {
            out.push(Violation {
                rule: RULE,
                path: PathBuf::from(format!("{rel_path}:{line}")),
                message: "names a chip read, face match or liveness check; identity proofing \
                          is an external provider's Claim (IDP-34, §10.3.1)"
                    .to_owned(),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // IDP-34, §10.3.1, Ek B 5368
    #[test]
    fn a_proofing_capability_is_found_and_a_provider_claim_is_not() {
        assert_eq!(hits("fn check_liveness(frame: &[u8]) {}\n"), vec![1]);
        assert_eq!(hits("a\nlet apdu = select_aid();\n"), vec![2]);
        assert_eq!(
            hits("class = \"identity_proofing\"\nmethod = \"document_nfc\"\n"),
            Vec::<usize>::new()
        );
        assert_eq!(
            hits("/// The internal router: liveness, readiness\n"),
            Vec::<usize>::new()
        );
    }
}
