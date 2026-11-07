//! `no-tenant-labels` (OP-47, OP-151 m.3 (p)): no metric carries a tenant, realm, domain or
//! personal identifier label. OpenTelemetry is used only behind the `crates/telemetry` facade;
//! inside it every attribute name is a [`Label`] name or a resource attribute; the label
//! allowlist names none of [`FORBIDDEN`]; alert rules and dashboards group by none of them.
//!
//! `event-names` (OP-67 m.2): every `event = "…"` field in non-test code names an entry of
//! `conformance/catalog/events.toml`, and the catalogue itself is well formed.
//!
//! `alert-runbooks` (OP-67 m.5, OP-151 m.1 (a)): every alert rule has a `severity` and a
//! `runbook` label.
//!
//! [`Label`]: ../../crates/telemetry/src/metrics.rs

use std::collections::BTreeSet;
use std::path::Path;

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{find_token, in_regions, lex, line_at, test_regions};

const LABELS_RULE: &str = "no-tenant-labels";
const EVENTS_RULE: &str = "event-names";

/// OP-47: label names never allowed on a metric.
const FORBIDDEN: &[&str] = &[
    "tenant_id",
    "realm_id",
    "domain_id",
    "client_id",
    "sub",
    "email",
    "ip",
    "instance_id",
    "account_id",
    "session_id",
    "user_id",
    "party_id",
];

/// Resource attributes the facade sets once per process.
const RESOURCE_KEYS: &[&str] = &["service.name", "service.version", "deployment.environment"];

const FACADE: &str = "crates/telemetry/";
const METRICS_FILE: &str = "crates/telemetry/src/metrics.rs";
const CATALOG: &str = "conformance/catalog/events.toml";

/// Crate paths that are the facade's business alone.
const OTEL_CRATES: &[&str] = &[
    "opentelemetry",
    "opentelemetry_sdk",
    "opentelemetry_otlp",
    "tracing_opentelemetry",
];

fn scanned(rel_path: &str) -> bool {
    (rel_path.starts_with("crates/") || rel_path.starts_with("bins/"))
        && Path::new(rel_path).extension().is_some_and(|e| e == "rs")
}

/// The string literals of `pub const fn name(self)` in the facade's metrics module: the label
/// allowlist.
pub(crate) fn allowlist(src: &str) -> Vec<String> {
    let Some(start) = src.find("pub const fn name(self)") else {
        return Vec::new();
    };
    let body = src.get(start..).unwrap_or_default();
    let end = body.find("\n    }\n").unwrap_or(body.len());
    let block = body.get(..end).unwrap_or_default();
    lex(block).strings.into_iter().map(|l| l.text).collect()
}

/// `KeyValue::new("…"` attribute names in `src`, with their lines.
pub(crate) fn attribute_names(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for at in find_token(src, "KeyValue::new(") {
        let rest = src
            .get(at.saturating_add("KeyValue::new(".len())..)
            .unwrap_or_default();
        let rest = rest.trim_start();
        if let Some(lit) = rest.strip_prefix('"')
            && let Some(end) = lit.find('"')
        {
            out.push((
                line_at(src, at),
                lit.get(..end).unwrap_or_default().to_owned(),
            ));
        }
    }
    out
}

/// Words of a YAML/JSON line that name a forbidden label in a grouping or selector.
pub(crate) fn forbidden_in_line(line: &str) -> Option<&'static str> {
    FORBIDDEN.iter().copied().find(|f| {
        find_token(line, f).into_iter().any(|at| {
            let before = line.get(..at).and_then(|s| s.chars().last());
            let after = line
                .get(at.saturating_add(f.len())..)
                .and_then(|s| s.chars().next());
            !matches!(before, Some('.' | '-' | '/')) && !matches!(after, Some('.' | '-' | '/'))
        })
    })
}

/// The two telemetry checks.
pub(crate) fn checks() -> Vec<crate::Check> {
    vec![
        crate::Check {
            name: "no-tenant-labels",
            run: check_labels,
        },
        crate::Check {
            name: "event-names",
            run: check_events,
        },
        crate::Check {
            name: "alert-runbooks",
            run: check_alerts,
        },
    ]
}

const ALERTS_RULE: &str = "alert-runbooks";
const ALERTS_DIR: &str = "deploy/observability/alerts/";

/// Alert names in a Prometheus rule file that lack a `severity` or a `runbook` label.
pub(crate) fn unlabelled_alerts(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Option<(String, bool, bool)> = None;
    let finish = |c: Option<(String, bool, bool)>, out: &mut Vec<String>| {
        if let Some((name, severity, runbook)) = c
            && !(severity && runbook)
        {
            out.push(name);
        }
    };
    for line in text.lines() {
        let t = line.trim_start();
        if let Some(name) = t.strip_prefix("- alert:") {
            finish(current.take(), &mut out);
            current = Some((name.trim().to_owned(), false, false));
        } else if let Some(c) = current.as_mut() {
            let value = |key: &str| {
                t.strip_prefix(key)
                    .map(str::trim)
                    .is_some_and(|v| !v.is_empty())
            };
            if value("severity:") {
                c.1 = true;
            }
            if value("runbook:") {
                c.2 = true;
            }
        }
    }
    finish(current, &mut out);
    out
}

/// OP-67 m.5: every alert names its severity and its runbook.
pub(crate) fn check_alerts(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let r = rel(root, &path);
        if !r.starts_with(ALERTS_DIR) {
            continue;
        }
        for name in unlabelled_alerts(&read(&path)?) {
            out.push(Violation {
                rule: ALERTS_RULE,
                path: path.clone(),
                message: format!(
                    "alert `{name}` needs `severity` and `runbook` labels (OP-67 m.5)"
                ),
            });
        }
    }
    Ok(out)
}

pub(crate) fn check_labels(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let labels = allowlist(&read(&root.join(METRICS_FILE))?);
    if labels.is_empty() {
        out.push(Violation {
            rule: LABELS_RULE,
            path: METRICS_FILE.into(),
            message: "the label allowlist (`Label::name`) was not found".into(),
        });
    }
    for l in &labels {
        if FORBIDDEN.contains(&l.as_str()) {
            out.push(Violation {
                rule: LABELS_RULE,
                path: METRICS_FILE.into(),
                message: format!("label `{l}` is forbidden on metrics (OP-47)"),
            });
        }
    }
    for path in walk(root)? {
        let r = rel(root, &path);
        if scanned(&r) {
            let src = read(&path)?;
            if r.starts_with(FACADE) {
                for (line, name) in attribute_names(&src) {
                    if !labels.contains(&name) && !RESOURCE_KEYS.contains(&name.as_str()) {
                        out.push(Violation {
                            rule: LABELS_RULE,
                            path: path.clone(),
                            message: format!(
                                "line {line}: attribute `{name}` is not a `Label` name (OP-47)"
                            ),
                        });
                    }
                }
            } else {
                let code = lex(&src).code;
                for krate in OTEL_CRATES {
                    for at in find_token(&code, krate) {
                        out.push(Violation {
                            rule: LABELS_RULE,
                            path: path.clone(),
                            message: format!(
                                "line {}: `{krate}` outside the telemetry facade; use access_telemetry (OP-47)",
                                line_at(&code, at)
                            ),
                        });
                    }
                }
            }
        } else if r.starts_with("deploy/") && (r.contains("/observability/")) {
            let text = read(&path)?;
            for (n, line) in text.lines().enumerate() {
                if let Some(f) = forbidden_in_line(line) {
                    out.push(Violation {
                        rule: LABELS_RULE,
                        path: path.clone(),
                        message: format!(
                            "line {}: `{f}` is not a metric label (OP-47)",
                            n.saturating_add(1)
                        ),
                    });
                }
            }
        }
    }
    Ok(out)
}

/// One catalogue entry.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Event {
    pub(crate) name: String,
}

fn valid_name(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    parts.len() >= 2
        && parts.iter().all(|p| {
            p.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                && p.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

fn valid_since(since: &str) -> bool {
    since == "unreleased" || {
        let parts: Vec<&str> = since.split('.').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    }
}

/// Parses and checks the catalogue; returns the entries and the problems found.
pub(crate) fn parse_catalog(text: &str) -> (Vec<Event>, Vec<String>) {
    let mut problems = Vec::new();
    let table: toml::Table = match text.parse() {
        Ok(t) => t,
        Err(e) => return (Vec::new(), vec![format!("not TOML: {e}")]),
    };
    let entries = table
        .get("event")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut seen = BTreeSet::new();
    let mut events = Vec::new();
    for e in &entries {
        let field = |k: &str| e.get(k).and_then(toml::Value::as_str).unwrap_or_default();
        let name = field("name");
        if !valid_name(name) {
            problems.push(format!("event name `{name}` is not dotted lowercase"));
        }
        if !seen.insert(name.to_owned()) {
            problems.push(format!("event `{name}` is listed twice"));
        }
        if !matches!(field("plane"), "authority" | "identity" | "signer" | "ops") {
            problems.push(format!(
                "event `{name}`: plane must be authority, identity, signer or ops"
            ));
        }
        if !matches!(field("severity"), "debug" | "info" | "warn" | "error") {
            problems.push(format!(
                "event `{name}`: severity must be debug, info, warn or error"
            ));
        }
        if !valid_since(field("since")) {
            problems.push(format!(
                "event `{name}`: since must be a release or \"unreleased\""
            ));
        }
        if e.get("fields").and_then(toml::Value::as_array).is_none() {
            problems.push(format!("event `{name}`: fields must be a list"));
        }
        if field("ocsf").is_empty() {
            problems.push(format!("event `{name}`: ocsf mapping is missing (§17.8.1)"));
        }
        events.push(Event {
            name: name.to_owned(),
        });
    }
    (events, problems)
}

/// `event = "…"` names in `src` outside test code, with their lines; `None` for a non-literal
/// value.
pub(crate) fn event_fields(src: &str) -> Vec<(usize, Option<String>)> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let raw: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (n, line) in lexed.code.lines().enumerate() {
        let number = n.saturating_add(1);
        if in_regions(&tests, number) {
            continue;
        }
        for at in find_token(line, "event") {
            let before = line.get(..at).unwrap_or_default().trim_end();
            let after = line
                .get(at.saturating_add(5)..)
                .unwrap_or_default()
                .trim_start();
            let assigns =
                after.starts_with('=') && !after.starts_with("==") && !after.starts_with("=>");
            let is_binding = before.ends_with("let") || before.ends_with("mut");
            if !assigns || is_binding {
                continue;
            }
            let Some(raw_line) = raw.get(n) else { continue };
            let value = raw_line
                .find("event")
                .and_then(|i| raw_line.get(i.saturating_add(5)..))
                .map(|s| s.trim_start().trim_start_matches('=').trim_start())
                .unwrap_or_default();
            let name = value
                .strip_prefix('"')
                .and_then(|v| v.find('"').and_then(|e| v.get(..e)))
                .map(str::to_owned);
            out.push((number, name));
        }
    }
    out
}

pub(crate) fn check_events(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let (events, problems) = parse_catalog(&read(&root.join(CATALOG))?);
    for message in problems {
        out.push(Violation {
            rule: EVENTS_RULE,
            path: CATALOG.into(),
            message,
        });
    }
    let names: BTreeSet<&str> = events.iter().map(|e| e.name.as_str()).collect();
    for path in walk(root)? {
        let r = rel(root, &path);
        if !scanned(&r) || is_test_file(&r) {
            continue;
        }
        for (line, name) in event_fields(&read(&path)?) {
            match name {
                Some(n) if names.contains(n.as_str()) => {}
                Some(n) => out.push(Violation {
                    rule: EVENTS_RULE,
                    path: path.clone(),
                    message: format!("line {line}: event `{n}` is not in {CATALOG} (OP-67 m.2)"),
                }),
                None => out.push(Violation {
                    rule: EVENTS_RULE,
                    path: path.clone(),
                    message: format!(
                        "line {line}: an event name must be a string literal (OP-67 m.2)"
                    ),
                }),
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-47: the allowlist is read from `Label::name`; a forbidden name in it is caught
    #[test]
    fn the_allowlist_is_read_from_the_facade() {
        let src = "impl Label {\n    pub const fn name(self) -> &'static str {\n        match self {\n            Self::A => \"outcome\",\n            Self::B => \"tenant_id\",\n        }\n    }\n}\n";
        let names = allowlist(src);
        assert_eq!(names, vec!["outcome".to_owned(), "tenant_id".to_owned()]);
        assert!(names.iter().any(|n| FORBIDDEN.contains(&n.as_str())));
    }

    // OP-47: attribute names inside the facade are found
    #[test]
    fn attribute_names_are_found() {
        let src = "let a = KeyValue::new(\"realm_id\", v);\nKeyValue::new( \"outcome\", x)";
        assert_eq!(
            attribute_names(src),
            vec![(1, "realm_id".to_owned()), (2, "outcome".to_owned())]
        );
    }

    // OP-47: alert and dashboard expressions may not group by a forbidden label
    #[test]
    fn alert_expressions_are_checked() {
        assert_eq!(
            forbidden_in_line("expr: sum by (tenant_id) (rate(access_x_total[5m]))"),
            Some("tenant_id")
        );
        assert_eq!(forbidden_in_line("expr: sum by (outcome) (x)"), None);
        assert_eq!(forbidden_in_line("summary: the sub-second budget"), None);
        assert_eq!(forbidden_in_line("url: http://ip.example/x"), None);
    }

    // OP-67 m.2: event names in code are literals from the catalogue; bindings are not events
    #[test]
    fn event_fields_are_found() {
        let src = "fn f() {\n    tracing::info!(event = \"login.failed\", outcome = \"deny\");\n    let event = 3;\n    tracing::warn!(event = %name);\n    if event == 3 {}\n}\n#[cfg(test)]\nmod tests {\n    fn g() { tracing::info!(event = \"x.y\"); }\n}\n";
        assert_eq!(
            event_fields(src),
            vec![(2, Some("login.failed".to_owned())), (4, None)]
        );
    }

    // OP-67 m.5: an alert without a runbook or a severity is caught
    #[test]
    fn alerts_need_runbooks() {
        let text = "groups:\n  - name: g\n    rules:\n      - alert: A\n        expr: x > 0\n        labels:\n          severity: page\n          runbook: a\n      - alert: B\n        expr: y > 0\n        labels:\n          severity: page\n";
        assert_eq!(unlabelled_alerts(text), vec!["B".to_owned()]);
    }

    // OP-67 m.2: the catalogue format is checked
    #[test]
    fn the_catalogue_is_checked() {
        let good = "[[event]]\nname = \"login.failed\"\nplane = \"identity\"\nseverity = \"info\"\nsince = \"0.3.1\"\nfields = []\nocsf = \"authentication\"\n";
        let (events, problems) = parse_catalog(good);
        assert_eq!(events.len(), 1);
        assert!(problems.is_empty(), "{problems:?}");
        let bad = format!(
            "{good}{}",
            good.replace("0.3.1", "soon").replace("identity", "web")
        );
        let (_, problems) = parse_catalog(&bad);
        assert_eq!(problems.len(), 3, "{problems:?}");
        let (_, problems) = parse_catalog(&good.replace("login.failed", "LoginFailed"));
        assert_eq!(problems.len(), 1, "{problems:?}");
    }
}
