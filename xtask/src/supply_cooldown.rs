//! `cooldown` (F-2, SA-34): every crates.io package in `Cargo.lock` was published
//! at least seven days ago, so a hijacked release has time to be noticed and
//! yanked before we build with it. A release that fixes a known advisory is listed in
//! `supply-chain/cooldown-exceptions.toml` and does not wait (F-15).
//!
//! The publication dates are committed in `supply-chain/publication-dates.json`, so the
//! offline check on every pull request judges every locked version; a version without a
//! recorded date fails until `XTASK_ONLINE=1 cargo xtask check cooldown` records it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::Violation;
use crate::rules::files::read;

const RULE: &str = "cooldown";

/// F-2: minimum age of a dependency version.
pub(crate) const COOLDOWN_DAYS: i64 = 7;

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
pub(crate) const DATES_FILE: &str = "supply-chain/publication-dates.json";
const EXCEPTIONS_FILE: &str = "supply-chain/cooldown-exceptions.toml";
const USER_AGENT: &str = "access-xtask cooldown check (https://github.com/e-suiss/access)";

/// A locked package: name, version, source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Locked {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) source: Option<String>,
}

/// Parses `Cargo.lock`.
pub(crate) fn parse_lock(text: &str) -> Result<Vec<Locked>, String> {
    let table: toml::Table = text.parse().map_err(|e| format!("Cargo.lock: {e}"))?;
    let packages = table
        .get("package")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(packages
        .iter()
        .map(|p| Locked {
            name: p
                .get("name")
                .and_then(toml::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            version: p
                .get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            source: p
                .get("source")
                .and_then(toml::Value::as_str)
                .map(str::to_owned),
        })
        .collect())
}

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = y.checked_div_euclid(400)?;
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let mp = m.checked_add(if m > 2 { -3 } else { 9 })?;
    let doy = mp
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(d)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

/// Parses the date and time of an RFC 3339 UTC timestamp into Unix seconds.
pub(crate) fn parse_timestamp(ts: &str) -> Option<i64> {
    let num = |range: std::ops::Range<usize>| ts.get(range)?.parse::<i64>().ok();
    let days = days_from_civil(num(0..4)?, num(5..7)?, num(8..10)?)?;
    let secs = num(11..13)?
        .checked_mul(3600)?
        .checked_add(num(14..16)?.checked_mul(60)?)?
        .checked_add(num(17..19)?)?;
    days.checked_mul(86_400)?.checked_add(secs)
}

/// The verdict for one package given its publication time. Age is counted in
/// whole UTC calendar days, so a version published on day D is usable from day
/// D + 7 regardless of the hour.
pub(crate) fn too_new(published: i64, now: i64) -> bool {
    now.div_euclid(86_400)
        .saturating_sub(published.div_euclid(86_400))
        < COOLDOWN_DAYS
}

fn load_dates(path: &Path) -> Result<BTreeMap<String, String>, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn save_dates(path: &Path, dates: &BTreeMap<String, String>) -> Result<(), String> {
    let mut json = serde_json::to_string_pretty(dates).map_err(|e| e.to_string())?;
    json.push('\n');
    std::fs::write(path, json).map_err(|e| format!("{}: {e}", path.display()))
}

/// Fetches the publication timestamp of one version from crates.io.
fn fetch(name: &str, version: &str) -> Result<String, String> {
    let url = format!("https://crates.io/api/v1/crates/{name}/{version}");
    let output = Command::new("curl")
        .args(["-sSf", "--max-time", "20", "-A", USER_AGENT, &url])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let v: Value = serde_json::from_slice(&output.stdout).map_err(|e| format!("{url}: {e}"))?;
    v.get("version")
        .and_then(|x| x.get("created_at"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{url}: no created_at"))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Exceptions {
    #[serde(default)]
    exception: Vec<Exception>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Exception {
    #[serde(rename = "crate")]
    name: String,
    version: String,
    advisory: String,
}

fn advisory_id(s: &str) -> bool {
    s.strip_prefix("RUSTSEC-").is_some_and(|rest| {
        let (year, num) = rest.split_once('-').unwrap_or_default();
        year.len() == 4
            && num.len() == 4
            && year.bytes().chain(num.bytes()).all(|b| b.is_ascii_digit())
    })
}

/// F-15: the exceptions, each naming a `RustSec` advisory and a locked crate version.
pub(crate) fn exceptions(text: &str, locked: &[Locked]) -> (Vec<String>, Vec<Violation>) {
    let violation = |message: String| Violation {
        rule: RULE,
        path: PathBuf::from(EXCEPTIONS_FILE),
        message,
    };
    let parsed: Exceptions = match toml::from_str(text) {
        Ok(p) => p,
        Err(e) => return (Vec::new(), vec![violation(e.to_string())]),
    };
    let mut keys = Vec::new();
    let mut out = Vec::new();
    for e in parsed.exception {
        let key = format!("{}@{}", e.name, e.version);
        if !advisory_id(&e.advisory) {
            out.push(violation(format!(
                "{key}: advisory must be a RUSTSEC-YYYY-NNNN id (F-15)"
            )));
        } else if !locked
            .iter()
            .any(|p| p.name == e.name && p.version == e.version)
        {
            out.push(violation(format!(
                "{key}: not in Cargo.lock; remove the stale exception"
            )));
        } else {
            keys.push(key);
        }
    }
    (keys, out)
}

pub(crate) fn online() -> bool {
    std::env::var("XTASK_ONLINE").is_ok_and(|v| v == "1")
}

/// F-2: the verdict over every crates.io package in the lock file. A version without a
/// recorded publication date is a violation: an unjudged version never passes.
pub(crate) fn judge(
    locked: &[Locked],
    dates: &BTreeMap<String, String>,
    excepted: &[String],
    now: i64,
) -> Vec<Violation> {
    let violation = |message: String| Violation {
        rule: RULE,
        path: PathBuf::from("Cargo.lock"),
        message,
    };
    let mut out = Vec::new();
    for pkg in locked
        .iter()
        .filter(|p| p.source.as_deref() == Some(CRATES_IO))
    {
        let key = format!("{}@{}", pkg.name, pkg.version);
        match dates
            .get(&key)
            .map(|ts| (ts, parse_timestamp(ts)))
        {
            Some((ts, Some(t))) if too_new(t, now) && !excepted.contains(&key) => {
                out.push(violation(format!(
                    "{key} was published {ts}, less than {COOLDOWN_DAYS} days ago (F-2)"
                )));
            }
            Some((_, Some(_))) => {}
            Some((ts, None)) => out.push(violation(format!(
                "{key}: unreadable publication date `{ts}` in {DATES_FILE}"
            ))),
            None => out.push(violation(format!(
                "{key}: publication date not recorded in {DATES_FILE}; run `XTASK_ONLINE=1 cargo xtask check cooldown` (F-2)"
            ))),
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let locked = parse_lock(&read(&root.join("Cargo.lock"))?)?;
    let exceptions_path = root.join(EXCEPTIONS_FILE);
    let (excepted, mut out) = if exceptions_path.exists() {
        exceptions(&read(&exceptions_path)?, &locked)
    } else {
        (Vec::new(), Vec::new())
    };
    let dates_path = root.join(DATES_FILE);
    let mut dates = load_dates(&dates_path)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())
        .and_then(|d| i64::try_from(d.as_secs()).map_err(|e| e.to_string()))?;
    if online() {
        let mut fetched_any = false;
        for pkg in locked
            .iter()
            .filter(|p| p.source.as_deref() == Some(CRATES_IO))
        {
            let key = format!("{}@{}", pkg.name, pkg.version);
            if dates.contains_key(&key) {
                continue;
            }
            if fetched_any {
                std::thread::sleep(Duration::from_secs(1));
            }
            fetched_any = true;
            match fetch(&pkg.name, &pkg.version) {
                Ok(ts) => {
                    dates.insert(key, ts);
                }
                Err(error) => out.push(Violation {
                    rule: RULE,
                    path: PathBuf::from("Cargo.lock"),
                    message: format!("{key}: publication date unknown: {error}"),
                }),
            }
        }
        let before = dates.len();
        dates.retain(|key, _| {
            locked.iter().any(|p| {
                p.source.as_deref() == Some(CRATES_IO)
                    && format!("{}@{}", p.name, p.version) == *key
            })
        });
        if fetched_any || dates.len() != before {
            save_dates(&dates_path, &dates)?;
        }
    }
    out.extend(judge(&locked, &dates, &excepted, now));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crates_io_timestamps_parse_to_unix_seconds() {
        assert_eq!(parse_timestamp("1970-01-02T00:00:01.5Z"), Some(86_401));
        assert_eq!(parse_timestamp("2026-10-09T00:00:00Z"), Some(1_791_504_000));
    }

    #[test]
    fn version_published_six_days_ago_is_too_new() {
        let now = 100 * 86_400 + 3_600;
        assert!(too_new(now - 6 * 86_400, now));
        assert!(!too_new(now - 7 * 86_400, now));
        assert!(!too_new(93 * 86_400 + 80_000, now));
    }

    // F-2
    #[test]
    fn unjudged_versions_fail_the_cooldown() {
        let pkg = |name: &str, version: &str| Locked {
            name: name.into(),
            version: version.into(),
            source: Some(CRATES_IO.into()),
        };
        let locked = vec![
            pkg("old", "1.0.0"),
            pkg("fresh", "2.0.0"),
            pkg("unknown", "3.0.0"),
            Locked {
                name: "ws".into(),
                version: "0.0.0".into(),
                source: None,
            },
        ];
        let now = parse_timestamp("2026-11-08T12:00:00Z").unwrap_or_default();
        let dates: BTreeMap<String, String> = [
            ("old@1.0.0", "2026-10-01T00:00:00Z"),
            ("fresh@2.0.0", "2026-11-05T00:00:00Z"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let v = judge(&locked, &dates, &[], now);
        let messages: Vec<&str> = v.iter().map(|x| x.message.as_str()).collect();
        assert_eq!(messages.len(), 2, "{messages:?}");
        assert!(
            messages
                .iter()
                .any(|m| m.starts_with("fresh@2.0.0 was published"))
        );
        assert!(
            messages
                .iter()
                .any(|m| m.starts_with("unknown@3.0.0: publication date not recorded"))
        );
        assert_eq!(
            judge(
                &locked,
                &dates,
                &["fresh@2.0.0".to_owned(), "unknown@3.0.0".to_owned()],
                now
            )
            .len(),
            1
        );
    }

    #[test]
    fn exceptions_need_an_advisory_and_a_locked_version() {
        let locked = vec![Locked {
            name: "ctutils".into(),
            version: "0.4.4".into(),
            source: Some(CRATES_IO.into()),
        }];
        let ok = "[[exception]]\ncrate = \"ctutils\"\nversion = \"0.4.4\"\nadvisory = \"RUSTSEC-2026-0385\"\n";
        let (keys, v) = exceptions(ok, &locked);
        assert_eq!((keys, v.len()), (vec!["ctutils@0.4.4".to_string()], 0));
        let bad_id = ok.replace("RUSTSEC-2026-0385", "CVE-2026-1");
        assert_eq!(exceptions(&bad_id, &locked).1.len(), 1);
        let stale = ok.replace("0.4.4", "0.4.3");
        assert_eq!(exceptions(&stale, &locked).1.len(), 1);
        let unknown = format!("{ok}reason = \"x\"\n");
        assert_eq!(exceptions(&unknown, &locked).1.len(), 1);
    }

    #[test]
    fn lockfile_packages_are_parsed_with_their_source() {
        let lock = "version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n[[package]]\nname = \"ws\"\nversion = \"0.0.0\"\n";
        let p = parse_lock(lock).unwrap_or_default();
        assert_eq!(p.len(), 2);
        assert_eq!(p.get(1).and_then(|x| x.source.clone()), None);
    }
}
