//! Conformance profiles (§9.1 L3, P2, OP-157 m.3 (s)): `conformance/profiles/<name>.toml`, the
//! vector traces, PEP cases and CDDL files one role must pass. `--profile <name>` runs the
//! profile's PEP cases against the adapter and lists the vector traces and CDDL files the
//! implementation proves with its own vector runner. Passing a profile is conformance, not
//! endorsement.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::case::Case;

/// The eight roles (OP-157 m.3 (s)).
pub const ROLES: [&str; 8] = [
    "provider",
    "decision-pep",
    "offline-verifier",
    "approval-surface",
    "claim-issuer",
    "schema-publisher",
    "coordinator",
    "event-receiver",
];

/// One profile, in the shape of `conformance-profile.cddl`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Format version, 1.
    pub v: u8,
    /// The role.
    pub profile: String,
    /// Display title.
    pub title: String,
    /// Other Suiss products that share it.
    #[serde(default)]
    pub shared_with: Vec<String>,
    /// `track/version` under `vectors/`.
    pub vectors: Vec<String>,
    /// Case ids under `pep/cases/`.
    pub pep_cases: Vec<String>,
    /// Files under `cddl/`.
    pub cddl: Vec<String>,
    /// Domain Metadata is verified against the domain root (`access_sdk::metadata::verify`).
    #[serde(default)]
    pub metadata_signature: bool,
}

/// Why a profile does not load.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    /// The name is not one of the eight roles.
    #[error("unknown profile {0}: one of {roles}", roles = ROLES.join(", "))]
    Unknown(String),
    /// The file cannot be read.
    #[error("{0}: {1}")]
    Io(String, std::io::Error),
    /// The file is not a profile.
    #[error("{0}: {1}")]
    Parse(String, String),
    /// The profile names something that does not exist, or is not the role of its file.
    #[error("{0}: {1}")]
    Invalid(String, String),
}

fn vector_exists(root: &Path, named: &str) -> bool {
    named.split_once('/').is_some_and(|(track, version)| {
        !track.is_empty()
            && !version.is_empty()
            && version.bytes().all(|c| c.is_ascii_digit())
            && track
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-_".contains(&c))
            && std::fs::read_dir(root.join("vectors").join(track).join(version)).is_ok_and(
                |mut it| {
                    it.any(|e| e.is_ok_and(|e| e.path().extension().is_some_and(|x| x == "json")))
                },
            )
    })
}

fn plain(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-_.".contains(&c))
        && !name.contains("..")
}

/// Loads the profile `name` from `root` (the `conformance` folder) and checks that everything it
/// names exists there.
///
/// # Errors
/// [`ProfileError`].
pub fn load(root: &Path, name: &str) -> Result<Profile, ProfileError> {
    if !ROLES.contains(&name) {
        return Err(ProfileError::Unknown(name.to_owned()));
    }
    let path: PathBuf = root.join("profiles").join(format!("{name}.toml"));
    let shown = path.display().to_string();
    let text = std::fs::read_to_string(&path).map_err(|e| ProfileError::Io(shown.clone(), e))?;
    let p: Profile =
        toml::from_str(&text).map_err(|e| ProfileError::Parse(shown.clone(), e.to_string()))?;
    let invalid = |m: String| ProfileError::Invalid(shown.clone(), m);
    if p.v != 1 || p.profile != name {
        return Err(invalid(String::from(
            "not a version 1 profile of this role",
        )));
    }
    for v in &p.vectors {
        if !vector_exists(root, v) {
            return Err(invalid(format!("no vectors {v}")));
        }
    }
    for c in &p.pep_cases {
        if !plain(c) || !root.join("pep/cases").join(format!("{c}.json")).is_file() {
            return Err(invalid(format!("no PEP case {c}")));
        }
    }
    for c in &p.cddl {
        if !plain(c)
            || Path::new(c).extension().is_none_or(|x| x != "cddl")
            || !root.join("cddl").join(c).is_file()
        {
            return Err(invalid(format!("no CDDL file {c}")));
        }
    }
    Ok(p)
}

/// The cases of `all` the profile names, in case order.
#[must_use]
pub fn select(profile: &Profile, all: Vec<Case>) -> Vec<Case> {
    let wanted: BTreeSet<&str> = profile.pep_cases.iter().map(String::as_str).collect();
    all.into_iter()
        .filter(|c| wanted.contains(c.id.as_str()))
        .collect()
}

/// What the profile asks beyond its PEP cases, as text.
#[must_use]
pub fn requirements(profile: &Profile) -> String {
    let mut out = format!(
        "Conformance profile: {} ({})\n",
        profile.title, profile.profile
    );
    if !profile.shared_with.is_empty() {
        let _ = writeln!(out, "shared with: {}", profile.shared_with.join(", "));
    }
    for v in &profile.vectors {
        let _ = writeln!(out, "requires vectors  {v}");
    }
    for c in &profile.cddl {
        let _ = writeln!(out, "requires cddl     {c}");
    }
    if profile.metadata_signature {
        let _ = writeln!(
            out,
            "requires          Domain Metadata verified against the domain root"
        );
    }
    let _ = writeln!(
        out,
        "{} PEP cases; conformance, not endorsement",
        profile.pep_cases.len()
    );
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]

    use super::*;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
    }

    // P2, §9.1, OP-157 m.3 (s), Ek B 5671
    #[test]
    fn every_role_has_a_profile_that_names_existing_traces() {
        for role in ROLES {
            let p = load(&root(), role).unwrap();
            assert_eq!(p.profile, role);
            assert!(requirements(&p).contains("not endorsement"));
        }
        let pep = load(&root(), "decision-pep").unwrap();
        assert!(pep.metadata_signature);
        let verifier = load(&root(), "offline-verifier").unwrap();
        assert!(verifier.metadata_signature);
        assert_eq!(
            load(&root(), "approval-surface").unwrap().shared_with,
            ["work"]
        );
        assert!(matches!(
            load(&root(), "certified"),
            Err(ProfileError::Unknown(_))
        ));
    }

    // P2, OP-157 m.3 (s)
    #[test]
    fn a_profile_runs_only_its_own_cases() {
        let all = crate::case::load(&root().join("pep/cases")).unwrap();
        let verifier = load(&root(), "offline-verifier").unwrap();
        let picked = select(&verifier, all.clone());
        assert_eq!(picked.len(), verifier.pep_cases.len());
        assert!(picked.iter().all(|c| !c.id.starts_with("adp-")));
        assert_eq!(
            select(&load(&root(), "coordinator").unwrap(), all),
            Vec::new()
        );
    }
}
