#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::*;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "tests" && name != "target" {
                sources(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") && name != "tests.rs" {
            out.push(path);
        }
    }
}

/// Dotted string literals in `line`, e.g. `"session.created"`.
fn dotted(line: &str) -> Vec<String> {
    line.split('"')
        .skip(1)
        .step_by(2)
        .filter(|s| s.contains('.') && valid_name(s) && !s.ends_with('.'))
        .map(String::from)
        .collect()
}

/// The event names the workspace writes: the literals within the arguments of every `audit(`
/// call and every operational event, and the `format!` names expanded by their kinds.
fn written() -> BTreeSet<String> {
    let mut files = Vec::new();
    sources(&root().join("crates"), &mut files);
    sources(&root().join("bins"), &mut files);
    let mut out = BTreeSet::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let call = (line.contains("audit(") && !line.contains("fn "))
                || line.contains("OperationalEvent {")
                || line.contains("AUDIT_EVENT");
            if !call {
                continue;
            }
            for next in lines.iter().skip(i).take(5) {
                if next.contains("format!(\"login.{kind}.") {
                    for kind in ["totp", "recovery_code"] {
                        for end in ["failed", "succeeded"] {
                            out.insert(format!("login.{kind}.{end}"));
                        }
                    }
                    continue;
                }
                out.extend(dotted(next));
            }
        }
    }
    out
}

/// Events declared ahead of their lanes (OP-156 m.4): in the taxonomy, written by nothing yet. A
/// lane that writes one takes it off this list.
const UNPRODUCED: &[&str] = &[
    "linux.offline_signin",
    "linux.break_glass",
    "hr.connector_pulled",
    "signal.claim_ingested",
    "signal.refused",
    "cloud_key.destroyed",
    // OP-157 m.4 (a)
    "mapping.pinned",
    "policy.default_changed",
];

// OP-41, OP-47, §17.8.1
#[test]
fn the_taxonomy_is_compiled_in_and_well_formed() {
    let t = taxonomy().unwrap();
    assert_eq!(t.version, 1);
    assert!(t.events.len() >= 20);
    for e in &t.events {
        assert!(e.ocsf_type().unwrap() > 100_000, "{}", e.event);
        assert_eq!(e.ocsf_category(), e.ocsf_class / 1000);
        assert!(e.fields.iter().any(|f| f == "actor"), "{}", e.event);
    }
    assert_eq!(entry("nothing.like.this"), Err(TaxonomyError::Unknown));
}

// OP-41
#[test]
fn op_41_every_written_audit_event_is_in_the_taxonomy() {
    let t = taxonomy().unwrap();
    let written = written();
    assert!(written.contains("session.created"), "{written:?}");
    assert!(written.contains("audit.export"), "{written:?}");
    let known: BTreeSet<String> = t.events.iter().map(|e| e.event.clone()).collect();
    let missing: Vec<_> = written.difference(&known).collect();
    assert!(missing.is_empty(), "not in the taxonomy: {missing:?}");
    let unused: Vec<_> = known
        .difference(&written)
        .filter(|e| !e.starts_with("authority.decision."))
        .filter(|e| !UNPRODUCED.contains(&e.as_str()))
        .collect();
    assert!(unused.is_empty(), "never written: {unused:?}");
}

// OP-41, OP-156 m.4
#[test]
fn op_41_an_unproduced_event_is_declared_and_not_yet_written() {
    let t = taxonomy().unwrap();
    let known: BTreeSet<&str> = t.events.iter().map(|e| e.event.as_str()).collect();
    let written = written();
    for name in UNPRODUCED {
        assert!(known.contains(name), "{name} is not in the taxonomy");
        assert!(
            !written.contains(*name),
            "{name} is written now: take it off UNPRODUCED"
        );
    }
}

// OP-41
#[test]
fn op_41_caep_counterparts_are_the_eight_types() {
    let t = taxonomy().unwrap();
    let used: BTreeSet<&str> = t.events.iter().filter_map(Entry::caep).collect();
    assert!(used.iter().all(|c| CAEP_TYPES.contains(c)));
    assert!(used.contains("session-revoked") && used.contains("credential-change"));
    let bad = SOURCE.replacen("caep = \"session-revoked\"", "caep = \"session-ended\"", 1);
    assert_eq!(
        parse(&bad).err(),
        Some(TaxonomyError::Source("CAEP counterpart"))
    );
}

// OP-41
#[test]
fn a_malformed_taxonomy_is_refused() {
    let dup = format!(
        "{SOURCE}\n[[event]]\nevent = \"session.created\"\nplane = \"identity\"\nclass = \"session\"\noutcome = \"success\"\nfields = [\"actor\"]\nocsf_class = 3003\nocsf_activity = 99\ncaep = \"\"\nwebhook = false\n"
    );
    assert_eq!(
        parse(&dup).err(),
        Some(TaxonomyError::Source("duplicate event"))
    );
    let extra = SOURCE.replacen("webhook = true", "webhook = true\nsampled = true", 1);
    assert!(parse(&extra).is_err());
    assert!(!valid_name("Session.created") && !valid_name("") && valid_name("a.b_c"));
}

// IDP-36, IDP-37, OP-151 m.3 (i)
#[test]
fn the_webhook_feed_carries_identity_events_only() {
    let t = taxonomy().unwrap();
    let feed: Vec<&str> = t.webhook_feed().map(|e| e.event.as_str()).collect();
    assert!(feed.contains(&"account.created") && feed.contains(&"session.signed_out"));
    assert!(t.webhook_feed().all(|e| e.plane == Plane::Identity));
}
