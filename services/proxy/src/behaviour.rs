//! The shared behaviour cases every engine runs (IDP-30 (2), OP-156 m.3 (m), Ek B 5360): one
//! request each, in the phase that sets up what it needs, with what the browser and the
//! application must see. The files are `tests/behaviour/*.toml`; the CI job `proxy-engines` runs
//! them against real Envoy, Caddy, Traefik and Nginx in front of a real Access.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

/// When a case runs; phases run in this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// No proxy session yet.
    Anonymous,
    /// Signed in through the engine on every application.
    SignedIn,
    /// The Grant was revoked and the head moved.
    Revoked,
    /// Access's listener is gone.
    AccessDown,
}

/// What the browser and the application must see.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    /// The statuses the browser may see.
    pub status: Vec<u16>,
    /// Whether the request reached the application.
    pub upstream: bool,
    /// Whether the application received a valid application token for itself.
    #[serde(default)]
    pub identity: bool,
    /// Whether the application received plain identity headers.
    #[serde(default)]
    pub plain: bool,
    /// The prefix of the browser's `Location`.
    pub location: Option<String>,
}

/// One case.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    /// The spec IDs it checks.
    pub rule: String,
    /// When it runs.
    pub phase: Phase,
    /// The `[[app]]` policy it asks.
    pub app: String,
    /// Method.
    pub method: String,
    /// Path and query.
    pub path: String,
    /// Headers the client adds.
    #[serde(default)]
    pub send: BTreeMap<String, String>,
    /// What must be seen.
    pub expect: Expect,
}

/// The cases in `dir`, by file name.
///
/// # Errors
/// A file that cannot be read or is not a case, named.
pub fn cases(dir: &Path) -> Result<Vec<(String, Case)>, String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|p| {
            let name = p
                .file_stem()
                .and_then(|s| s.to_str())
                .map(String::from)
                .unwrap_or_default();
            let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            let case: Case =
                toml::from_str(&text).map_err(|e| format!("{}: {}", p.display(), e.message()))?;
            Ok((name, case))
        })
        .collect()
}
