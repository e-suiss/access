//! Single-maintainer dependency watchlist (OP-89; §16.10 T42 item 5; RR-19).

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::Violation;
use crate::catalog::DIR;

const FILE: &str = "maintainer-watchlist.toml";
const USER_AGENT: &str = "access-xtask maintainer-watchlist (https://github.com/e-suiss/access)";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Watchlist {
    /// Months without a release or commit before a warning (PD, OP-89).
    pub(crate) threshold_months: u32,
    #[serde(rename = "crate")]
    pub(crate) crates: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Entry {
    pub(crate) name: String,
    /// `https://github.com/<owner>/<repo>`.
    pub(crate) repository: String,
    /// Spec IDs that put the crate on the list.
    pub(crate) sources: Vec<String>,
    /// Why it is watched (single maintainer, personal repository, ...).
    pub(crate) reason: String,
}

fn load(root: &Path) -> Result<Watchlist, String> {
    let path = root.join(DIR).join(FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn github_repo(url: &str) -> Option<(&str, &str)> {
    let rest = url
        .strip_prefix("https://github.com/")?
        .trim_end_matches('/');
    let (owner, repo) = rest.split_once('/')?;
    (!owner.is_empty() && !repo.is_empty() && !repo.contains('/')).then_some((owner, repo))
}

pub(crate) fn validate(list: &Watchlist) -> Vec<String> {
    let mut out = Vec::new();
    if list.threshold_months == 0 {
        out.push("threshold_months must be positive".to_owned());
    }
    let mut seen = std::collections::BTreeSet::new();
    for e in &list.crates {
        if !seen.insert(e.name.as_str()) {
            out.push(format!("{}: duplicate entry", e.name));
        }
        if e.name.is_empty()
            || !e
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            out.push(format!("{:?}: not a crate name", e.name));
        }
        if github_repo(&e.repository).is_none() {
            out.push(format!(
                "{}: repository must be https://github.com/<owner>/<repo>",
                e.name
            ));
        }
        if e.sources.is_empty() || e.reason.trim().is_empty() {
            out.push(format!("{}: needs sources and a reason", e.name));
        }
    }
    out
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "bounded calendar arithmetic on parsed dates"
)]
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses the `YYYY-MM-DD` prefix of an RFC 3339 timestamp into days since the epoch.
pub(crate) fn parse_day(ts: &str) -> Option<i64> {
    let mut parts = ts.get(..10)?.split('-');
    let y = parts.next()?.parse().ok()?;
    let m = parts.next()?.parse().ok()?;
    let d = parts.next()?.parse().ok()?;
    Some(days_from_civil(y, m, d))
}

/// Whether `then` is more than `months` (30.44-day months) before `now`.
pub(crate) fn stale(now_days: i64, then_days: i64, months: u32) -> bool {
    let limit = i64::from(months).saturating_mul(3044) / 100;
    now_days.saturating_sub(then_days) > limit
}

fn get_json(url: &str) -> Result<serde_json::Value, String> {
    let output = Command::new("curl")
        .args(["-sSfL", "--max-time", "20", "-A", USER_AGENT, url])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| format!("{url}: {e}"))
}

fn last_release(name: &str) -> Result<String, String> {
    let v = get_json(&format!(
        "https://crates.io/api/v1/crates/{name}/versions?per_page=1"
    ))?;
    v.pointer("/versions/0/created_at")
        .and_then(|x| x.as_str())
        .map(str::to_owned)
        .ok_or_else(|| format!("{name}: no versions"))
}

fn last_commit(owner: &str, repo: &str) -> Result<String, String> {
    let v = get_json(&format!(
        "https://api.github.com/repos/{owner}/{repo}/commits?per_page=1"
    ))?;
    v.pointer("/0/commit/committer/date")
        .and_then(|x| x.as_str())
        .map(str::to_owned)
        .ok_or_else(|| format!("{owner}/{repo}: no commits"))
}

fn today() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    i64::try_from(secs / 86_400).unwrap_or(0)
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let list = load(root)?;
    let path = PathBuf::from(DIR).join(FILE);
    let mut out: Vec<Violation> = validate(&list)
        .into_iter()
        .map(|message| Violation {
            rule: "OP-89",
            path: path.clone(),
            message,
        })
        .collect();
    if std::env::var("XTASK_ONLINE").as_deref() != Ok("1") {
        println!(
            "      maintainer-watchlist: {} crates; offline (set XTASK_ONLINE=1 to query crates.io and GitHub)",
            list.crates.len()
        );
        return Ok(out);
    }
    let now = today();
    for e in &list.crates {
        let release = last_release(&e.name);
        let commit = github_repo(&e.repository)
            .ok_or("bad repository".to_owned())
            .and_then(|(o, r)| last_commit(o, r));
        for (what, result) in [("release", release), ("commit", commit)] {
            match result {
                Ok(ts) => {
                    let old = parse_day(&ts).is_some_and(|d| stale(now, d, list.threshold_months));
                    let mark = if old { "WARN " } else { "     " };
                    println!(
                        "      {mark}{} last {what} {}",
                        e.name,
                        ts.get(..10).unwrap_or(&ts)
                    );
                }
                Err(err) => println!("      WARN  {}: could not read last {what}: {err}", e.name),
            }
        }
    }
    out.shrink_to_fit();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_convert_to_epoch_days() {
        assert_eq!(parse_day("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_day("2026-10-09"), Some(20_735));
        assert_eq!(parse_day("garbage"), None);
    }

    #[test]
    fn six_month_threshold_separates_fresh_from_stale() {
        let now = parse_day("2026-10-09").unwrap();
        assert!(!stale(now, parse_day("2026-05-01").unwrap(), 6));
        assert!(stale(now, parse_day("2026-03-01").unwrap(), 6));
    }

    #[test]
    fn entries_need_github_repository_sources_and_reason() {
        let list = Watchlist {
            threshold_months: 6,
            crates: vec![Entry {
                name: "spiffe".into(),
                repository: "https://gitlab.com/x/y".into(),
                sources: vec![],
                reason: String::new(),
            }],
        };
        assert_eq!(validate(&list).len(), 2);
    }
}
