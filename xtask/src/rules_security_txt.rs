//! `security-txt` (OP-159 m.3 (jj)): security.txt carries its required fields and expires within a year.
//! The project's own `security/security.txt` and the file the server renders (RFC 9116, SA-14)
//! carry `Contact`, `Expires`, `Policy`, `Canonical` and `Preferred-Languages`; `Expires` lies
//! in the future and at most a year ahead, and the server's validity stays under a year.

use std::path::Path;

use crate::Violation;
use crate::civil;

const RULE: &str = "security-txt";
const FILE: &str = "security/security.txt";
const RENDER: &str = "crates/http/src/security_txt.rs";
const CONFIG: &str = "bins/access-server/src/config.rs";
const YEAR: i64 = 365 * 86_400;
const FIELDS: &[&str] = &[
    "Contact",
    "Expires",
    "Policy",
    "Canonical",
    "Preferred-Languages",
];
const SINGLE: &[&str] = &["Expires", "Preferred-Languages"];

fn v(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: path.into(),
        message,
    }
}

fn fields(text: &str) -> Vec<(&str, &str)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once(':'))
        .map(|(k, val)| (k.trim(), val.trim()))
        .collect()
}

/// Findings in a security.txt body at `now` (Unix seconds).
pub(crate) fn file_findings(text: &str, now: i64) -> Vec<String> {
    let mut out = Vec::new();
    let found = fields(text);
    let values = |name: &str| -> Vec<&str> {
        found
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, val)| *val)
            .collect()
    };
    for name in FIELDS {
        let n = values(name).len();
        if n == 0 {
            out.push(format!("{name} is required"));
        } else if n > 1 && SINGLE.contains(name) {
            out.push(format!("{name} appears once"));
        }
    }
    for contact in values("Contact") {
        if !(contact.starts_with("https://") || contact.starts_with("mailto:")) {
            out.push(format!("Contact {contact}: an https or mailto URI"));
        }
    }
    for name in ["Policy", "Canonical"] {
        for uri in values(name)
            .into_iter()
            .filter(|u| !u.starts_with("https://"))
        {
            out.push(format!("{name} {uri}: an https URI"));
        }
    }
    if let [expires] = values("Expires").as_slice() {
        match civil::parse_rfc3339(expires) {
            None => out.push(format!("Expires {expires}: an RFC 3339 date-time")),
            Some(t) if t <= now => {
                out.push(format!("Expires {expires} has passed; renew the file"));
            }
            Some(t) if t.saturating_sub(now) > YEAR => {
                out.push(format!(
                    "Expires {expires} is more than a year ahead (RFC 9116 §2.5.5)"
                ));
            }
            Some(_) => {}
        }
    }
    if !text.is_empty() && !text.ends_with('\n') {
        out.push(String::from("the file ends with a newline"));
    }
    out
}

/// Findings in the server's renderer and its configured validity.
pub(crate) fn server_findings(render: &str, config: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for name in FIELDS {
        if !render.contains(&format!("\"{name}: \"")) {
            out.push((RENDER, format!("the server does not render {name}")));
        }
    }
    let default_days = config
        .lines()
        .find_map(|l| l.trim().strip_prefix("security_txt_valid_days: "))
        .and_then(|d| d.trim_end_matches(',').parse::<u32>().ok());
    if !default_days.is_some_and(|d| (1..=364).contains(&d)) {
        out.push((
            CONFIG,
            String::from("the default security_txt_valid_days is 1 to 364"),
        ));
    }
    if !config.contains("(1..=364).contains(&self.security_txt_valid_days)") {
        out.push((
            CONFIG,
            String::from("the configuration refuses security_txt_valid_days over 364"),
        ));
    }
    out
}

/// The `Contact` and `Policy` values of the project's file must be the server's defaults.
pub(crate) fn default_findings(text: &str, config: &str) -> Vec<String> {
    let found = fields(text);
    let mut out = Vec::new();
    for (name, value) in found
        .iter()
        .filter(|(k, _)| matches!(*k, "Contact" | "Policy"))
    {
        if !config.contains(&format!("\"{value}\"")) {
            out.push(format!("{name} {value} is not the server's default"));
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let read =
        |rel: &str| std::fs::read_to_string(root.join(rel)).map_err(|e| format!("{rel}: {e}"));
    let text = read(FILE)?;
    let config = read(CONFIG)?;
    let mut out: Vec<Violation> = file_findings(&text, civil::now())
        .into_iter()
        .chain(default_findings(&text, &config))
        .map(|m| v(FILE, m))
        .collect();
    out.extend(
        server_findings(&read(RENDER)?, &config)
            .into_iter()
            .map(|(p, m)| v(p, m)),
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assert_is_empty, reason = "test code")]

    use super::*;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap()
    }

    fn at(s: &str) -> i64 {
        civil::parse_rfc3339(s).unwrap()
    }

    const BODY: &str = "Contact: https://github.com/e-suiss/access/security/advisories/new\nExpires: 2027-11-01T00:00:00Z\nPolicy: https://github.com/e-suiss/access/security/policy\nCanonical: https://raw.githubusercontent.com/e-suiss/access/main/security/security.txt\nPreferred-Languages: en, tr\n";

    // SA-14, OP-159 m.3 (jj)
    #[test]
    fn expires_more_than_a_year_ahead_or_in_the_past_fails() {
        assert!(file_findings(BODY, at("2026-11-12T00:00:00Z")).is_empty());
        assert_eq!(file_findings(BODY, at("2027-11-01T00:00:00Z")).len(), 1);
        assert_eq!(file_findings(BODY, at("2026-10-01T00:00:00Z")).len(), 1);
        let bad = BODY.replace("2027-11-01T00:00:00Z", "next year");
        assert_eq!(file_findings(&bad, at("2026-11-12T00:00:00Z")).len(), 1);
    }

    // SA-14
    #[test]
    fn a_missing_or_repeated_field_fails() {
        let now = at("2026-11-12T00:00:00Z");
        let no_canonical = BODY.replace("Canonical: https://raw.githubusercontent.com/e-suiss/access/main/security/security.txt\n", "");
        assert_eq!(
            file_findings(&no_canonical, now),
            vec![String::from("Canonical is required")]
        );
        let twice = format!("{BODY}Expires: 2027-01-01T00:00:00Z\n");
        assert_eq!(file_findings(&twice, now).len(), 1);
        let plain = BODY.replace("Policy: https://", "Policy: http://");
        assert_eq!(file_findings(&plain, now).len(), 1);
    }

    // SA-14, OP-159 m.3 (jj)
    #[test]
    fn the_server_renders_every_field_and_stays_under_a_year() {
        let render = std::fs::read_to_string(root().join(RENDER)).unwrap();
        let config = std::fs::read_to_string(root().join(CONFIG)).unwrap();
        assert_eq!(server_findings(&render, &config), Vec::new());
        let longer = config.replace(
            "security_txt_valid_days: 180,",
            "security_txt_valid_days: 400,",
        );
        assert_eq!(server_findings(&render, &longer).len(), 1);
        let unrendered = render.replace("\"Canonical: \"", "\"Link: \"");
        assert_eq!(server_findings(&unrendered, &config).len(), 1);
        let text = std::fs::read_to_string(root().join(FILE)).unwrap();
        assert_eq!(default_findings(&text, &config), Vec::<String>::new());
        assert_eq!(
            default_findings(&text.replace("/policy", "/other"), &config).len(),
            1
        );
    }
}
