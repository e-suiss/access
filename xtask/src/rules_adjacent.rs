//! `adjacent-products` (E22, IDP-39, L28, F11, §7.6, §8.17.12, OP-156 m.3 (x), Ek B 5366): PAM
//! session brokering and recording, a general secret vault, DLP and classification, SIEM search
//! and correlation, MDM, a general risk or fraud scoring engine and IGA campaigns are separate
//! product layers. Access decides their authority part and gives them decisions, events and
//! signals; it does not implement them, and no Suiss service is written for them. No workspace
//! member is named after one, and no file under `crates/`, `bins/`, `services/`, `sdks/` or
//! `web/` carries their machinery.
//!
//! The identity plane keeps what E22 and IDP-39 assign to it: the token vault of upstream OAuth
//! tokens (`identity-vault`, E36) and its own sign-in risk signals (`identity-risk`, IDP-39 (2)).
//! Access also keeps the basic access review campaign, a view over a manager's team that is never
//! a queue (IDP-39 (3), OP-157 m.3 (w)).

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{read, rel, walk};

const RULE: &str = "adjacent-products";

/// What an implementation of an adjacent product would name, lower case.
const MARKERS: &[(&str, &str)] = &[
    ("session_recording", "PAM session recording"),
    ("record_session", "PAM session recording"),
    ("session_replay", "PAM session recording"),
    ("asciicast", "PAM session recording"),
    ("ttyrec", "PAM session recording"),
    ("session_broker", "PAM session brokering"),
    ("jump_host", "PAM session brokering"),
    ("bastion", "PAM session brokering"),
    ("secrets_engine", "a general secret vault"),
    ("secret_engine", "a general secret vault"),
    ("kv_engine", "a general secret vault"),
    ("shamir", "a general secret vault"),
    ("dlp_engine", "DLP"),
    ("data_classification", "DLP and classification"),
    ("sensitivity_label", "DLP and classification"),
    ("classify_content", "DLP and classification"),
    ("content_inspection", "DLP and classification"),
    ("siem_search", "SIEM search"),
    ("correlation_rule", "SIEM correlation"),
    ("detection_rule", "SIEM correlation"),
    ("sigma_rule", "SIEM correlation"),
    ("mdm_enroll", "MDM"),
    ("mdm_command", "MDM"),
    ("remote_wipe", "MDM"),
    ("device_wipe", "MDM"),
    ("wipe_device", "MDM"),
    ("fraud_score", "a risk or fraud scoring engine"),
    ("risk_model", "a risk or fraud scoring engine"),
    ("anomaly_model", "a risk or fraud scoring engine"),
    ("compute_risk", "a risk or fraud scoring engine"),
    ("certification_campaign", "IGA campaigns"),
    ("access_certification", "IGA campaigns"),
    ("role_mining", "IGA role mining"),
    ("sod_matrix", "IGA SoD reporting"),
    ("sod_report", "IGA SoD reporting"),
    ("campaign_engine", "IGA campaigns"),
];

/// Workspace member names that would be one of those products: a whole name or a `-suffix`.
const MEMBER_NAMES: &[&str] = &[
    "pam",
    "vault",
    "secrets",
    "secret-store",
    "dlp",
    "siem",
    "mdm",
    "fraud",
    "risk-engine",
    "iga",
];

/// Members E22 and IDP-39 assign to the identity plane, with why.
const ALLOWED_MEMBERS: &[(&str, &str)] = &[
    (
        "crates/identity-vault",
        "the identity plane's token vault of upstream OAuth tokens (E36, MD-13)",
    ),
    (
        "crates/identity-risk",
        "the identity plane's own sign-in risk signals, which only narrow (IDP-39 (2), CI-2)",
    ),
];

const ROOTS: &[&str] = &["crates/", "bins/", "services/", "sdks/", "web/"];

const MEMBER_ROOTS: &[&str] = &["crates", "bins", "services", "sdks/rust", "tools"];

const EXTENSIONS: &[&str] = &["rs", "toml", "ts", "tsx", "js", "swift", "kt", "py", "sql"];

/// The lines of `src` that name an adjacent product's machinery, with what they name.
pub(crate) fn hits(src: &str) -> Vec<(usize, &'static str)> {
    src.lines()
        .enumerate()
        .filter_map(|(i, l)| {
            let l = l.to_ascii_lowercase();
            MARKERS
                .iter()
                .find(|(m, _)| l.contains(m))
                .map(|(_, what)| (i.saturating_add(1), *what))
        })
        .collect()
}

/// Whether a workspace member's directory name is one of the adjacent products.
pub(crate) fn adjacent_member(name: &str) -> bool {
    MEMBER_NAMES
        .iter()
        .any(|m| name == *m || name.ends_with(&format!("-{m}")))
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for dir in MEMBER_ROOTS {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let member = format!("{dir}/{name}");
            if e.path().is_dir()
                && adjacent_member(&name)
                && !ALLOWED_MEMBERS.iter().any(|(m, _)| *m == member)
            {
                out.push(Violation {
                    rule: RULE,
                    path: PathBuf::from(member),
                    message: "is named after a separate product layer; Access decides its \
                              authority part and no Suiss service is written for it (E22, IDP-39)"
                        .to_owned(),
                });
            }
        }
    }
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if !ROOTS.iter().any(|r| rel_path.starts_with(r))
            || !EXTENSIONS.contains(&ext)
            || rel_path.contains("/node_modules/")
        {
            continue;
        }
        for (line, what) in hits(&read(&path)?) {
            out.push(Violation {
                rule: RULE,
                path: PathBuf::from(format!("{rel_path}:{line}")),
                message: format!(
                    "names {what}; that is a separate product layer which gets Access's \
                     decisions, events and signals (E22, IDP-39, L28)"
                ),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // E22, IDP-39, L28, Ek B 5366
    #[test]
    fn an_adjacent_products_machinery_is_found_and_its_seam_is_not() {
        assert_eq!(hits("fn start_session_recording() {}\n").len(), 1);
        assert_eq!(
            hits("a\nlet r = SodReport::new();\nsod_report(r)\n").len(),
            1
        );
        assert_eq!(
            hits("namespace = \"pam.session\"\naction = \"secret.release\"\n"),
            Vec::new()
        );
        assert_eq!(hits("class = \"posture_mdm\"\nrisk.* Claim\n"), Vec::new());
    }

    // E22, E36, IDP-39 (2)
    #[test]
    fn a_member_named_after_an_adjacent_product_is_refused() {
        for name in [
            "pam",
            "access-dlp",
            "siem",
            "suiss-mdm",
            "secret-store",
            "vault",
        ] {
            assert!(adjacent_member(name), "{name}");
        }
        for name in ["identity-signals", "proxy", "product-twin", "identity-ssh"] {
            assert!(!adjacent_member(name), "{name}");
        }
        assert!(adjacent_member("identity-vault"));
        assert!(
            ALLOWED_MEMBERS
                .iter()
                .any(|(m, _)| *m == "crates/identity-vault")
        );
    }
}
