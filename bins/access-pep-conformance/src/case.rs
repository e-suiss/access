//! Fault cases: `conformance/pep/cases/*.json`, one scenario and its expected effect each.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// What the PEP under test protects the effect with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// An ADP decision with a signed receipt (§9.8).
    Decision,
    /// An opaque access token checked by RFC 7662 introspection.
    Introspection,
    /// A JWT access token checked against the JWKS and the Token Status List.
    Jwt,
}

/// The effect the harness expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Expect {
    /// Healthy upstreams: the PEP allows and performs the effect exactly once.
    Effect,
    /// Negative evidence: the PEP answers `deny` and performs no effect.
    Deny,
    /// Unknown state: the PEP performs no effect; `deny` or `error` both pass.
    NoEffect,
}

/// How one fake upstream answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Reply {
    /// A status code with an RFC 9457 problem body.
    Status {
        /// HTTP status.
        status: u16,
    },
    /// A literal body that need not be JSON.
    Raw {
        /// HTTP status.
        status: u16,
        /// Body text.
        body: String,
    },
    /// A literal JSON body.
    Json {
        /// HTTP status.
        status: u16,
        /// Body.
        body: serde_json::Value,
    },
    /// The request is accepted and never answered.
    Hang,
    /// ADP: an `AuthZEN` evaluation answer.
    Decision {
        /// `decision`.
        decision: bool,
        /// Whether `context.receipt` carries the signed receipt.
        receipt: bool,
    },
    /// JWKS: the signing key.
    Keys,
    /// Token Status List: a signed list.
    List {
        /// The list expired before `now`.
        stale: bool,
        /// The token's bit is set.
        revoked: bool,
    },
}

/// One fault scenario.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    /// Identifier; equals the file stem.
    pub id: String,
    /// Spec rule IDs the case checks.
    pub rules: Vec<String>,
    /// What happens, in one sentence.
    pub description: String,
    /// What protects the effect.
    pub mode: Mode,
    /// The PEP's own audience when it differs from the fixture's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The intent digest (hex of its CBOR) when it differs from the fixture's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// ADP answer; healthy when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adp: Option<Reply>,
    /// Introspection answer; healthy when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection: Option<Reply>,
    /// JWKS answer; healthy when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Reply>,
    /// Status list answer; healthy when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_list: Option<Reply>,
    /// The expected effect.
    pub expect: Expect,
}

/// Why the cases cannot be loaded.
#[derive(Debug, thiserror::Error)]
pub enum CaseError {
    /// A file could not be read.
    #[error("{0}: {1}")]
    Io(String, std::io::Error),
    /// A file is not a case.
    #[error("{0}: {1}")]
    Parse(String, serde_json::Error),
    /// A case is inconsistent.
    #[error("{0}: {1}")]
    Invalid(String, &'static str),
}

impl Case {
    fn validate(&self, stem: &str) -> Result<(), &'static str> {
        if self.id != stem {
            return Err("id differs from the file name");
        }
        if self.rules.is_empty() {
            return Err("no rule IDs");
        }
        let decision_only = |r: &Option<Reply>| matches!(r, Some(Reply::Decision { .. }));
        let keys_only = |r: &Option<Reply>| matches!(r, Some(Reply::Keys));
        let list_only = |r: &Option<Reply>| matches!(r, Some(Reply::List { .. }));
        if decision_only(&self.introspection)
            || decision_only(&self.jwks)
            || decision_only(&self.status_list)
            || keys_only(&self.adp)
            || keys_only(&self.introspection)
            || keys_only(&self.status_list)
            || list_only(&self.adp)
            || list_only(&self.introspection)
            || list_only(&self.jwks)
        {
            return Err("a reply kind is used on the wrong upstream");
        }
        let used = match self.mode {
            Mode::Decision => self.introspection.is_none() && self.jwks.is_none(),
            Mode::Introspection => self.adp.is_none() && self.jwks.is_none(),
            Mode::Jwt => self.adp.is_none() && self.introspection.is_none(),
        };
        if !used || (self.mode != Mode::Jwt && self.status_list.is_some()) {
            return Err("an upstream the mode does not call is configured");
        }
        Ok(())
    }
}

/// Loads every `*.json` case in `dir`, sorted by file name.
///
/// # Errors
/// [`CaseError`].
pub fn load(dir: &Path) -> Result<Vec<Case>, CaseError> {
    let name = |p: &Path| p.display().to_string();
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| CaseError::Io(name(dir), e))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    let mut ids = BTreeSet::new();
    let mut out = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(&path).map_err(|e| CaseError::Io(name(&path), e))?;
        let case: Case =
            serde_json::from_str(&text).map_err(|e| CaseError::Parse(name(&path), e))?;
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        case.validate(stem)
            .map_err(|e| CaseError::Invalid(name(&path), e))?;
        if !ids.insert(case.id.clone()) {
            return Err(CaseError::Invalid(name(&path), "duplicate id"));
        }
        out.push(case);
    }
    if out.is_empty() {
        return Err(CaseError::Invalid(name(dir), "no cases"));
    }
    Ok(out)
}
