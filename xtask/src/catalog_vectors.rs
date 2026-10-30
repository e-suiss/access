//! L0/L2 rule coverage by conformance vectors (§9.18 P34, TI-RT12).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::Violation;

const TEXT_DIRS: &[&str] = &["protocol/l0", "protocol/l2"];
const VECTOR_DIRS: &[&str] = &["conformance/vectors/core", "conformance/vectors/exchange"];
const RULE: &str = "TI-RT12";
const MARKER: &str = "<!-- no-vector:";

/// Reasons a rule may carry no vector, each with the meaning a reviewer checks it against.
pub(crate) const KINDS: &[(&str, &str)] = &[
    (
        "editorial",
        "about the text, its conventions or conformance itself",
    ),
    (
        "definition",
        "names a structure or term; the behaviour is in the rules it points to",
    ),
    (
        "property",
        "an algebraic law over all values, proved or property-tested rather than sampled",
    ),
    (
        "no-operation",
        "semantic, but no core vector operation exposes it yet",
    ),
    (
        "outside-operation",
        "a duty of the preparer, caller or enforcer that no operation output shows",
    ),
    ("unreachable", "no input of this version can trigger it"),
    (
        "undecided",
        "semantic, but the text does not fix the expected result yet",
    ),
];

/// One normative anchor and its optional no-vector marker.
#[derive(Debug)]
pub(crate) struct Anchor {
    pub(crate) id: String,
    pub(crate) file: String,
    pub(crate) exempt: Option<(String, String)>,
}

/// Normative anchors of one text file, and malformed markers as messages.
pub(crate) fn anchors(file: &str, text: &str) -> (Vec<Anchor>, Vec<String>) {
    let mut out = Vec::new();
    let mut bad = Vec::new();
    let mut rest = text;
    while let Some((_, after)) = rest.split_once("<a id=\"") {
        let Some((id, after)) = after.split_once("\"></a>") else {
            break;
        };
        rest = after;
        if !(id.starts_with("L0-") || id.starts_with("L2-")) {
            continue;
        }
        let exempt = rest.strip_prefix(MARKER).map(|m| {
            let body = m.split("-->").next().unwrap_or("").trim();
            let (kind, reason) = body.split_once(':').unwrap_or((body, ""));
            (kind.trim().to_owned(), reason.trim().to_owned())
        });
        if let Some((kind, reason)) = &exempt {
            if !KINDS.iter().any(|(k, _)| k == kind) {
                bad.push(format!("{id}: unknown no-vector kind {kind:?}"));
            } else if reason.is_empty() {
                bad.push(format!("{id}: no-vector marker needs a reason"));
            }
        }
        out.push(Anchor {
            id: id.to_owned(),
            file: file.to_owned(),
            exempt,
        });
    }
    (out, bad)
}

fn rule_list(v: Option<&Value>) -> Result<Vec<String>, String> {
    match v {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| {
                i.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "`rules` holds a non-string".to_owned())
            })
            .collect(),
        Some(_) => Err("`rules` is not an array".to_owned()),
    }
}

/// Rule citations of one vector file, by rule, as `file#case` (or `file` for the header).
pub(crate) fn citations(
    file: &str,
    doc: &Value,
) -> (BTreeMap<String, BTreeSet<String>>, Vec<String>) {
    let mut by_rule: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut bad = Vec::new();
    let header = rule_list(doc.get("rules")).unwrap_or_else(|e| {
        bad.push(e);
        Vec::new()
    });
    for r in &header {
        by_rule
            .entry(r.clone())
            .or_default()
            .insert(file.to_owned());
    }
    let cases = doc.get("cases").and_then(Value::as_array);
    if header.is_empty() && cases.is_none_or(Vec::is_empty) {
        bad.push("no file-level `rules` and no cases".to_owned());
    }
    for c in cases.into_iter().flatten() {
        let id = c.get("id").and_then(Value::as_str).unwrap_or("?");
        match rule_list(c.get("rules")) {
            Ok(list) if list.is_empty() && header.is_empty() => {
                bad.push(format!("case {id} cites no rule"));
            }
            Ok(list) => {
                for r in list {
                    by_rule.entry(r).or_default().insert(format!("{file}#{id}"));
                }
            }
            Err(e) => bad.push(format!("case {id}: {e}")),
        }
    }
    (by_rule, bad)
}

/// Pure coverage check over parsed anchors and citations, separated for tests.
pub(crate) fn violations(
    anchors: &[Anchor],
    cited: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for a in anchors {
        if !seen.insert(a.id.as_str()) {
            out.push((a.file.clone(), format!("{}: duplicate anchor", a.id)));
        }
        match (&a.exempt, cited.get(&a.id)) {
            (None, None) => out.push((
                a.file.clone(),
                format!(
                    "{}: no vector cites it; add a vector case or a `{MARKER} <kind>: <reason> -->` marker",
                    a.id
                ),
            )),
            (Some((kind, _)), Some(by)) => out.push((
                a.file.clone(),
                format!(
                    "{}: marked no-vector ({kind}) but cited by {}; drop the marker",
                    a.id,
                    by.iter().next().map_or("", String::as_str)
                ),
            )),
            _ => {}
        }
    }
    for (rule, by) in cited {
        if !seen.contains(rule.as_str()) {
            out.push((
                by.iter().next().cloned().unwrap_or_default(),
                format!("{rule}: cited by a vector but not an L0/L2 anchor"),
            ));
        }
    }
    out
}

fn md_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for dir in TEXT_DIRS {
        let d = root.join(dir);
        for e in fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))? {
            let p = e.map_err(|e| format!("{}: {e}", d.display()))?.path();
            if p.extension().is_some_and(|x| x == "md") {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn json_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for e in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let p = e.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if p.is_dir() {
            json_files(&p, out)?;
        } else if p.extension().is_some_and(|x| x == "json") {
            out.push(p);
        }
    }
    Ok(())
}

fn rel(root: &Path, p: &Path) -> String {
    crate::rules::files::rel(root, p)
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut all = Vec::new();
    let mut out = Vec::new();
    let v = |path: String, message: String| Violation {
        rule: RULE,
        path: PathBuf::from(path),
        message,
    };
    for p in md_files(root)? {
        let file = rel(root, &p);
        let text = crate::rules::files::read(&p)?;
        let (found, bad) = anchors(&file, &text);
        out.extend(bad.into_iter().map(|m| v(file.clone(), m)));
        all.extend(found);
    }
    let mut vectors = Vec::new();
    for dir in VECTOR_DIRS {
        json_files(&root.join(dir), &mut vectors)?;
    }
    vectors.sort();
    let mut cited: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for p in &vectors {
        let file = rel(root, p);
        let doc: Value = serde_json::from_str(&crate::rules::files::read(p)?)
            .map_err(|e| format!("{file}: {e}"))?;
        let (by, bad) = citations(&file, &doc);
        out.extend(bad.into_iter().map(|m| v(file.clone(), m)));
        for (r, locs) in by {
            cited.entry(r).or_default().extend(locs);
        }
    }
    out.extend(violations(&all, &cited).into_iter().map(|(f, m)| v(f, m)));
    let covered = all.iter().filter(|a| cited.contains_key(&a.id)).count();
    let marked: Vec<&str> = all
        .iter()
        .filter_map(|a| a.exempt.as_ref().map(|(k, _)| k.as_str()))
        .collect();
    let exempt: Vec<String> = KINDS
        .iter()
        .map(|(k, _)| (k, marked.iter().filter(|m| *m == k).count()))
        .filter(|(_, n)| *n > 0)
        .map(|(k, n)| format!("{k} {n}"))
        .collect();
    println!(
        "      l0-vector-coverage: {} rules, {covered} cited by vectors, {} no-vector ({})",
        all.len(),
        marked.len(),
        exempt.join(", ")
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "<a id=\"L0-ENC-1\"></a>**L0-ENC-1.** x\n\
        <a id=\"L0-GEN-1\"></a><!-- no-vector: editorial: key words -->**L0-GEN-1.**\n\
        <a id=\"open-x\"></a><a id=\"L0-EVAL-5\"></a>**L0-EVAL-5.**\n\
        <a id=\"L0-GEN-2\"></a><!-- no-vector: vibes: none -->\n\
        <a id=\"L0-GEN-3\"></a><!-- no-vector: definition -->\n";

    #[test]
    fn anchors_and_markers_parse() {
        let (a, bad) = anchors("t.md", TEXT);
        let ids: Vec<&str> = a.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(
            ids,
            ["L0-ENC-1", "L0-GEN-1", "L0-EVAL-5", "L0-GEN-2", "L0-GEN-3"]
        );
        assert_eq!(
            a[1].exempt,
            Some(("editorial".to_owned(), "key words".to_owned()))
        );
        assert!(a[0].exempt.is_none() && a[2].exempt.is_none());
        assert_eq!(bad.len(), 2, "{bad:?}");
    }

    #[test]
    fn citations_read_header_and_cases() {
        let doc: Value = serde_json::from_str(
            r#"{"rules": ["L0-ENC-1"], "cases": [{"id": "a", "rules": ["L0-EVAL-5"]}, {"id": "b"}]}"#,
        )
        .unwrap();
        let (by, bad) = citations("v.json", &doc);
        assert!(bad.is_empty(), "{bad:?}");
        assert_eq!(by["L0-ENC-1"].iter().next().unwrap(), "v.json");
        assert_eq!(by["L0-EVAL-5"].iter().next().unwrap(), "v.json#a");
        let doc: Value =
            serde_json::from_str(r#"{"cases": [{"id": "a"}, {"id": "b", "rules": "L0-X"}]}"#)
                .unwrap();
        assert_eq!(citations("v.json", &doc).1.len(), 2);
    }

    #[test]
    fn every_anchor_is_cited_or_exempt_never_both() {
        let (a, _) = anchors("t.md", TEXT);
        let mut cited: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        cited
            .entry("L0-ENC-1".into())
            .or_default()
            .insert("v#a".into());
        cited
            .entry("L0-GEN-1".into())
            .or_default()
            .insert("v#b".into());
        cited
            .entry("L0-ENC-99".into())
            .or_default()
            .insert("v#c".into());
        let got: Vec<String> = violations(&a, &cited).into_iter().map(|v| v.1).collect();
        assert_eq!(got.len(), 3, "{got:?}");
        assert!(got[0].starts_with("L0-GEN-1: marked no-vector"));
        assert!(got[1].starts_with("L0-EVAL-5: no vector cites it"));
        assert!(got[2].starts_with("L0-ENC-99: cited by a vector"));
    }
}
