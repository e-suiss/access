//! Reads rule IDs from the local, untracked spec (`docs/spec/*.md`) for `cargo xtask
//! catalog` (OP-81, OP-82).

use std::collections::BTreeMap;
use std::path::Path;

use crate::catalog::ids::{expand_range, family, ids_in, ids_outside_ranges, is_decision_family};

/// One rule definition found in the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpecRule {
    pub(crate) id: String,
    pub(crate) family: String,
    pub(crate) section: String,
    pub(crate) status: String,
    pub(crate) class: Option<String>,
    /// English lead sentence when the spec already has one (bold-bullet invariants).
    pub(crate) english_lead: Option<String>,
    pub(crate) aliases: Vec<String>,
    /// Spec text for local curation only.
    pub(crate) source: String,
}

/// One row of the §14.2 threat table, expanded to single TH IDs where numbered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpecThreat {
    /// `TH-n`, or `None` for the unnumbered identity-plane and hosting rows (SA-5).
    pub(crate) id: Option<String>,
    pub(crate) label: String,
    pub(crate) stride: Vec<String>,
    pub(crate) linddun: Vec<String>,
    pub(crate) rows: Vec<String>,
    pub(crate) refs: Vec<String>,
}

/// Everything `cargo xtask catalog` takes from the spec.
#[derive(Debug, Default)]
pub(crate) struct Spec {
    pub(crate) rules: Vec<SpecRule>,
    pub(crate) threats: Vec<SpecThreat>,
    pub(crate) abuse_cases: Vec<SpecRule>,
    /// Decision register rows (SA, CR, OP, ...), used only for IDs that tests cite.
    pub(crate) decisions: BTreeMap<String, SpecRule>,
    /// Earliest Ek B stage citing each ID outside a ticked item or a range.
    pub(crate) stages: BTreeMap<String, u8>,
}

/// One markdown line with the number of the enclosing section heading.
struct Line<'a> {
    section: String,
    text: &'a str,
}

fn lines(markdown: &str) -> Vec<Line<'_>> {
    let mut section = String::new();
    let mut out = Vec::new();
    for text in markdown.lines() {
        if let Some(heading) = text.strip_prefix('#') {
            let heading = heading.trim_start_matches('#').trim();
            let first = heading.split_whitespace().next().unwrap_or_default();
            let number = first.trim_end_matches('.');
            let numeric = number.bytes().next().is_some_and(|b| b.is_ascii_digit())
                && number
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b'.' || b.is_ascii_lowercase());
            if numeric {
                number.clone_into(&mut section);
            }
        }
        out.push(Line {
            section: section.clone(),
            text,
        });
    }
    out
}

fn in_section(line: &Line<'_>, prefix: &str) -> bool {
    line.section == prefix || line.section.starts_with(&format!("{prefix}."))
}

/// Table cells of a `| a | b |` row, trimmed; empty for non-table lines.
pub(crate) fn cells(text: &str) -> Vec<String> {
    let t = text.trim();
    if !t.starts_with('|') {
        return Vec::new();
    }
    let inner = t.trim_start_matches('|').trim_end_matches('|');
    inner.split('|').map(|c| c.trim().to_owned()).collect()
}

fn strip_bold(s: &str) -> &str {
    s.trim()
        .trim_start_matches("**")
        .trim_end_matches("**")
        .trim()
}

/// Splits `ID (aday) rest` into the ID, whether it is a candidate, and the rest.
fn split_id(s: &str) -> Option<(String, bool, &str)> {
    let s = strip_bold(s);
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .unwrap_or(s.len());
    let id = s.get(..end)?;
    family(id)?;
    let rest = s.get(end..).unwrap_or_default().trim_start();
    let candidate = rest.starts_with("(aday") || rest.starts_with("(invariant aday");
    let rest = if candidate {
        rest.find(')')
            .and_then(|p| rest.get(p.saturating_add(1)..))
            .unwrap_or_default()
    } else {
        rest
    };
    Some((id.to_owned(), candidate, rest.trim()))
}

const TURKISH_LETTERS: &str = "çğıöşüÇĞİÖŞÜ";
const TURKISH_WORDS: &[&str] = &[
    "ve", "bir", "ile", "yalnız", "için", "değil", "her", "olarak", "veya", "bu", "hiçbir",
];

/// The lead sentence when it reads as a short English title (≤ 12 words).
pub(crate) fn english_lead(text: &str) -> Option<String> {
    let text = text.trim().trim_start_matches("**").trim();
    let end = text.find(". ").map_or(text.len(), |p| p.saturating_add(1));
    let lead = text.get(..end)?.trim().trim_end_matches('.').trim();
    let words: Vec<&str> = lead.split_whitespace().collect();
    let english = !lead.is_empty()
        && words.len() <= 12
        && !lead.chars().any(|c| TURKISH_LETTERS.contains(c))
        && !words
            .iter()
            .any(|w| TURKISH_WORDS.contains(&w.to_lowercase().as_str()))
        && !lead.contains('\'');
    english.then(|| lead.replace("**", "").replace('*', ""))
}

fn rule(id: String, section: &str, status: &str, class: Option<String>, source: &str) -> SpecRule {
    let family = family(&id).unwrap_or_default().to_owned();
    SpecRule {
        id,
        family,
        section: section.to_owned(),
        status: status.to_owned(),
        class,
        english_lead: None,
        aliases: Vec::new(),
        source: source.trim().to_owned(),
    }
}

/// Normalises a guarantee class cell (`NOT GUARANTEED (→ N-16 …)`, `BS (HL-12 kadar)`).
fn class_of(cell: &str) -> Option<String> {
    let c = cell.trim();
    let upper = c.to_uppercase();
    if upper.starts_with("NOT GUARANTEED") || upper.starts_with("NG/PU") {
        return Some(
            if upper.starts_with("NG/PU") {
                "NG/PU"
            } else {
                "NG"
            }
            .to_owned(),
        );
    }
    if upper.starts_with("PHYSICALLY UNSATISFIABLE") {
        return Some("PU".to_owned());
    }
    let head: String = c
        .chars()
        .take_while(|ch| ch.is_ascii_uppercase() || *ch == '/')
        .collect();
    ["BS", "UDC", "NG", "PU", "NG/PU"]
        .contains(&head.as_str())
        .then_some(head)
}

/// Bold-bullet definitions: `- **INV-2** Text` / `- **EI-25 (aday)** Text`.
fn bold_bullets(md: &str, families: &[&str], status: &str, out: &mut Vec<SpecRule>) {
    for line in lines(md) {
        let t = line.text.trim_start();
        let Some(body) = t.strip_prefix("- **").or_else(|| t.strip_prefix("**")) else {
            continue;
        };
        let Some(close) = body.find("**") else {
            continue;
        };
        let head = body.get(..close).unwrap_or_default();
        let tail = body.get(close.saturating_add(2)..).unwrap_or_default();
        let Some((id, candidate, head_rest)) = split_id(head) else {
            continue;
        };
        if !families.contains(&family(&id).unwrap_or_default()) {
            continue;
        }
        let status = if candidate { "candidate" } else { status };
        let source = format!("{head_rest} {tail}");
        let mut r = rule(id, &line.section, status, None, &source);
        r.english_lead = english_lead(tail);
        out.push(r);
    }
}

/// Table definitions whose first cell is the ID; `class_col` names a class column.
fn table_rows(
    md: &str,
    section: &str,
    families: &[&str],
    status: &str,
    class_col: Option<usize>,
    out: &mut Vec<SpecRule>,
) {
    for line in lines(md) {
        if !in_section(&line, section) {
            continue;
        }
        let row = cells(line.text);
        let Some(first) = row.first() else { continue };
        let Some((id, candidate, _)) = split_id(first) else {
            continue;
        };
        if !strip_bold(first).starts_with(&id)
            || !families.contains(&family(&id).unwrap_or_default())
        {
            continue;
        }
        let text = row.get(1).cloned().unwrap_or_default();
        let retired = text.contains("Emekli");
        let status = if retired {
            "retired"
        } else if candidate {
            "candidate"
        } else {
            status
        };
        let class = class_col.and_then(|c| row.get(c)).and_then(|c| class_of(c));
        let mut r = rule(id, &line.section, status, class, &text);
        r.english_lead = english_lead(&text).filter(|_| text.starts_with("**"));
        out.push(r);
    }
}

fn guarantee_class(id: &str) -> Option<String> {
    match family(id)? {
        "G" => Some("BS".to_owned()),
        "U" => Some("UDC".to_owned()),
        "N" => Some("NG/PU".to_owned()),
        _ => None,
    }
}

/// §14.2 threat table: `| TH-3 / TH-4 | Malicious / compromised agent | S, E | — | rows |`.
fn threats(md: &str, out: &mut Vec<SpecThreat>) {
    for line in lines(md) {
        if !in_section(&line, "14.2") {
            continue;
        }
        let row = cells(line.text);
        let [ids, label, stride, linddun, rows_cell, ..] = row.as_slice() else {
            continue;
        };
        let numbered: Vec<String> = ids_in(ids)
            .into_iter()
            .map(|t| t.text)
            .filter(|t| family(t) == Some("TH"))
            .collect();
        let unnumbered = ids.starts_with('(');
        if numbered.is_empty() && !unnumbered {
            continue;
        }
        let split = |s: &str| -> Vec<String> {
            s.split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty() && *v != "—" && *v != "-")
                .map(str::to_owned)
                .collect()
        };
        let (rows, refs) = threat_rows(rows_cell);
        let base = SpecThreat {
            id: None,
            label: label.clone(),
            stride: split(stride),
            linddun: split(linddun),
            rows,
            refs,
        };
        if numbered.is_empty() {
            out.push(SpecThreat {
                label: format!("{} {}", ids.trim(), label),
                ..base
            });
        } else {
            for id in numbered {
                out.push(SpecThreat {
                    id: Some(id),
                    ..base.clone()
                });
            }
        }
    }
}

/// Splits a "primary §13 row" cell into catalog row IDs and other references.
fn threat_rows(cell: &str) -> (Vec<String>, Vec<String>) {
    let tokens = ids_in(cell);
    let mut rows = Vec::new();
    let mut refs = Vec::new();
    let mut k = 0;
    while let Some(t) = tokens.get(k) {
        let next = tokens.get(k.saturating_add(1));
        let between = next.map(|n| cell.get(t.end..n.start).unwrap_or_default().trim());
        let ids = if let (Some(n), Some("–" | "…")) = (next, between) {
            k = k.saturating_add(1);
            expand_range(&t.text, &n.text)
        } else {
            vec![t.text.clone()]
        };
        for id in ids {
            let fam = family(&id).unwrap_or_default();
            if fam == "AB" || is_decision_family(fam) || id.starts_with("K-") {
                refs.push(id);
            } else {
                rows.push(id);
            }
        }
        k = k.saturating_add(1);
    }
    for word in cell.split([' ', ';', ',']) {
        if word.starts_with('§') {
            refs.push(word.trim_end_matches([')', '.']).to_owned());
        }
    }
    // §13.1, §14.3
    for word in cell.split([' ', ';', ',', '(', ')']) {
        if word.starts_with("K-") && word.len() > 2 {
            refs.push(word.to_owned());
        }
    }
    (rows, refs)
}

/// §14.2 abuse cases: `AB-1 text; AB-2 text; …`.
fn abuse_cases(md: &str, out: &mut Vec<SpecRule>) {
    for line in lines(md) {
        let Some(body) = line.text.strip_prefix("**Abuse case'ler") else {
            continue;
        };
        let body = body.split_once("**").map_or(body, |(_, b)| b);
        let body = body.split(". Karşılıkları").next().unwrap_or(body);
        for part in body.split(';') {
            let part = part.trim();
            let Some((id, _, rest)) = split_id(part) else {
                continue;
            };
            out.push(rule(id, &line.section, "frozen", None, rest));
        }
    }
}

/// §2.8 must-never table (English sentences, numbered 1…19).
fn must_never(md: &str, out: &mut Vec<SpecRule>) {
    for line in lines(md) {
        if !in_section(&line, "2.8") {
            continue;
        }
        let row = cells(line.text);
        let [n, text, ..] = row.as_slice() else {
            continue;
        };
        if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        out.push(rule(
            format!("MUST-NEVER-{n}"),
            &line.section,
            "frozen",
            None,
            text,
        ));
    }
}

/// Bulleted lists under a heading, numbered in order as `<prefix><n>`.
fn numbered_bullets(md: &str, section: &str, after: &str, prefix: &str, out: &mut Vec<SpecRule>) {
    let mut started = false;
    let mut n: u32 = 0;
    for line in lines(md) {
        if !in_section(&line, section) {
            continue;
        }
        if line.text.contains(after) {
            started = true;
            continue;
        }
        if !started {
            continue;
        }
        let Some(item) = line.text.strip_prefix("- ") else {
            if n > 0 && line.text.trim().is_empty() {
                break;
            }
            continue;
        };
        n = n.saturating_add(1);
        out.push(rule(
            format!("{prefix}{n}"),
            &line.section,
            "frozen",
            None,
            item,
        ));
    }
}

/// §14.3 advisory table: the row key is the first advisory ID; the others are aliases.
fn advisories(md: &str, out: &mut Vec<SpecRule>) {
    for line in lines(md) {
        if !in_section(&line, "14.3") {
            continue;
        }
        let row = cells(line.text);
        let [key, class, response, ..] = row.as_slice() else {
            continue;
        };
        let ids: Vec<String> = ids_in(key)
            .into_iter()
            .map(|t| t.text)
            .filter(|t| family(t) == Some("ADVISORY"))
            .collect();
        let Some(first) = ids.first() else { continue };
        let mut r = rule(
            first.clone(),
            &line.section,
            "frozen",
            None,
            &format!("{class} → {response}"),
        );
        r.aliases = ids.get(1..).unwrap_or_default().to_vec();
        out.push(r);
    }
}

/// Decision register rows anywhere in the spec (`| SA-26 | text | status | …`).
fn decisions(md: &str, out: &mut BTreeMap<String, SpecRule>) {
    for line in lines(md) {
        let row = cells(line.text);
        let Some(first) = row.first() else { continue };
        let Some((id, _, _)) = split_id(first) else {
            continue;
        };
        if strip_bold(first) != id || !is_decision_family(family(&id).unwrap_or_default()) {
            continue;
        }
        let text = row.get(1).cloned().unwrap_or_default();
        out.entry(id.clone())
            .or_insert_with(|| rule(id, &line.section, "decision", None, &text));
    }
}

/// Earliest Ek B stage citing each ID; ticked (`- [x]`) items and range endpoints skipped.
fn stages(md: &str) -> BTreeMap<String, u8> {
    let mut stage: Option<u8> = None;
    let mut out = BTreeMap::new();
    for text in md.lines() {
        if let Some(h) = text.strip_prefix("## Aşama ") {
            stage = h.split_whitespace().next().and_then(|n| n.parse().ok());
            continue;
        }
        let Some(s) = stage else { continue };
        if text.trim_start().starts_with("- [x]") {
            continue;
        }
        for id in ids_outside_ranges(text) {
            out.entry(id)
                .and_modify(|v: &mut u8| *v = (*v).min(s))
                .or_insert(s);
        }
    }
    out
}

fn read(dir: &Path, name: &str) -> Result<String, String> {
    std::fs::read_to_string(dir.join(name)).map_err(|e| format!("{name}: {e}"))
}

/// Parses the spec directory.
#[allow(
    clippy::too_many_lines,
    reason = "one linear pass over the spec files; splitting would scatter the parser state"
)]
pub(crate) fn parse(dir: &Path) -> Result<Spec, String> {
    let mut spec = Spec::default();
    let rules = &mut spec.rules;

    let inv = read(dir, "06-invariants.md")?;
    bold_bullets(
        &inv,
        &["CI", "INV", "EI", "XI", "PI", "SI", "TI", "TI-RT"],
        "canonical",
        rules,
    );
    // §6.9
    for r in rules.iter_mut().filter(|r| r.section == "6.9") {
        "candidate".clone_into(&mut r.status);
    }
    bold_bullets(
        &read(dir, "07-ecosystem-boundaries.md")?,
        &["EI"],
        "candidate",
        rules,
    );
    bold_bullets(
        &read(dir, "08-product-experience.md")?,
        &["XI"],
        "candidate",
        rules,
    );
    table_rows(
        &read(dir, "10-identity-plane.md")?,
        "10.11",
        &["IDI"],
        "candidate",
        Some(2),
        rules,
    );
    table_rows(
        &read(dir, "11-mcp-and-agent-identity.md")?,
        "11.22",
        &["AGI"],
        "candidate",
        None,
        rules,
    );
    table_rows(
        &read(dir, "12-tenancy-sessions-accounts.md")?,
        "12.9",
        &["TNI"],
        "candidate",
        Some(3),
        rules,
    );
    table_rows(
        &read(dir, "17-data-operations.md")?,
        "17.13",
        &["OPI"],
        "candidate",
        None,
        rules,
    );
    let assurance = read(dir, "14-security-assurance.md")?;
    table_rows(&assurance, "14.11", &["SAI"], "candidate", None, rules);
    table_rows(
        &read(dir, "15-cryptography.md")?,
        "15.22",
        &["SAI"],
        "candidate",
        Some(3),
        rules,
    );

    let matrix = read(dir, "13-security-guarantee-matrix.md")?;
    let start = rules.len();
    table_rows(&matrix, "13.4", &["G", "U", "N"], "canonical", None, rules);
    for r in rules.get_mut(start..).unwrap_or_default() {
        r.class = guarantee_class(&r.id);
    }
    table_rows(&matrix, "13.5", &["HL"], "canonical", Some(3), rules);
    table_rows(&matrix, "13.1", &["DL"], "canonical", Some(2), rules);
    table_rows(&matrix, "13.9", &["RR"], "reference", None, rules);
    bold_bullets_in_section(&matrix, "13.10", &["SEC"], "frozen", rules);

    must_never(&read(dir, "02-product-thesis.md")?, rules);
    let data = read(dir, "17-data-operations.md")?;
    numbered_bullets(&data, "17.9.8", "Kırmızı çizgiler", "OP-54-RL", rules);
    numbered_bullets(
        &read(dir, "16-technical-architecture.md")?,
        "16.4.3",
        "CI kapıları",
        "OP-3-G",
        rules,
    );
    advisories(&assurance, rules);

    threats(&assurance, &mut spec.threats);
    abuse_cases(&assurance, &mut spec.abuse_cases);

    let mut names: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("md"))
        })
        .collect();
    names.sort();
    for name in &names {
        decisions(&read(dir, name)?, &mut spec.decisions);
    }
    spec.stages = stages(&read(dir, "appendix-b-feature-inventory.md")?);

    let mut seen = std::collections::BTreeSet::new();
    spec.rules.retain(|r| seen.insert(r.id.clone()));
    Ok(spec)
}

fn bold_bullets_in_section(
    md: &str,
    section: &str,
    families: &[&str],
    status: &str,
    out: &mut Vec<SpecRule>,
) {
    let filtered = lines(md)
        .into_iter()
        .filter(|l| in_section(l, section))
        .fold(String::new(), |mut acc, l| {
            acc.push_str(l.text);
            acc.push('\n');
            acc
        });
    let start = out.len();
    bold_bullets(&filtered, families, status, out);
    for r in out.get_mut(start..).unwrap_or_default() {
        section.clone_into(&mut r.section);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bold_bullets_yield_id_status_and_english_lead() {
        let md = "### 6.2 Semantic\n- **INV-2** Single write path (authority state). Rest of the text.\n\
                  - **EI-25 (aday)** Identity plane config changes are Exercises. Metin\n";
        let mut out = Vec::new();
        bold_bullets(md, &["INV", "EI"], "canonical", &mut out);
        assert_eq!(out.len(), 2);
        let first = out.first().unwrap();
        assert_eq!(
            (first.id.as_str(), first.section.as_str()),
            ("INV-2", "6.2")
        );
        assert_eq!(
            first.english_lead.as_deref(),
            Some("Single write path (authority state)")
        );
        assert_eq!(out.get(1).unwrap().status, "candidate");
    }

    #[test]
    fn turkish_lead_sentences_are_not_used_as_titles() {
        assert_eq!(
            english_lead("Her protocol nesnesi mevcut bir ontology sınıfına girer."),
            None
        );
        assert_eq!(
            english_lead("Batch atomik değildir; her öğe kendi Exercise'ıdır"),
            None
        );
    }

    #[test]
    fn table_rows_take_class_and_retired_status() {
        let md = "### 13.5 Known\n| HL | Sınır | Satır | Sınıf |\n|---|---|---|---|\n\
                  | HL-1 | Throughput sınırlı | N-20 | NG |\n| HL-25 | **Emekli → HL-20** | HL-20 | — |\n";
        let mut out = Vec::new();
        table_rows(md, "13.5", &["HL"], "canonical", Some(3), &mut out);
        let classes: Vec<_> = out
            .iter()
            .map(|r| (r.id.as_str(), r.class.as_deref(), r.status.as_str()))
            .collect();
        assert_eq!(
            classes,
            [
                ("HL-1", Some("NG"), "canonical"),
                ("HL-25", None, "retired")
            ]
        );
    }

    #[test]
    fn grouped_threat_rows_expand_to_single_ids() {
        let md = "### 14.2 Tehdit\n| TH | Sınıf | STRIDE | LINDDUN | Satır |\n\
                  | TH-3 / TH-4 | Malicious / compromised agent | S, E | — | DL-6; PI-11 |\n\
                  | TH-1 | Malicious user | E | — | G1–G3 (non-amplification) |\n\
                  | (identity plane) | Enumeration | I, D | Identifying | U44, §13.2 |\n";
        let mut out = Vec::new();
        threats(md, &mut out);
        let ids: Vec<_> = out.iter().map(|t| t.id.clone()).collect();
        assert_eq!(
            ids,
            [
                Some("TH-3".into()),
                Some("TH-4".into()),
                Some("TH-1".into()),
                None
            ]
        );
        assert_eq!(out.get(2).unwrap().rows, ["G1", "G2", "G3"]);
        assert_eq!(out.get(3).unwrap().refs, ["§13.2"]);
        assert_eq!(out.first().unwrap().stride, ["S", "E"]);
    }

    #[test]
    fn stages_skip_ticked_items_and_ranges() {
        let md = "## Aşama 0 — Temel\n- [x] **Done** — PI-15 note\n- [ ] **Open** — N-1…N-59; SAI-1\n\
                  ## Aşama 3 — Core\n- [ ] **Feature** — INV-2, SAI-1\n";
        let stages = stages(md);
        assert_eq!(stages.get("SAI-1"), Some(&0));
        assert_eq!(stages.get("INV-2"), Some(&3));
        assert_eq!(stages.get("PI-15"), None);
        assert_eq!(stages.get("N-1"), None);
    }

    #[test]
    fn red_lines_are_numbered_in_order() {
        let md = "#### 17.9.8 OP-54\n**Kırmızı çizgiler** (x):\n- Redis pub/sub.\n- Replica reads.\n\nAfter.\n";
        let mut out = Vec::new();
        numbered_bullets(md, "17.9.8", "Kırmızı çizgiler", "OP-54-RL", &mut out);
        let ids: Vec<_> = out.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["OP-54-RL1", "OP-54-RL2"]);
    }

    #[test]
    fn advisory_rows_key_on_the_first_advisory_id() {
        let md = "### 14.3 Saldırı\n| Advisory | Sınıf | Karşılık |\n\
                  | Kanidm GHSA-53hj-r94p-8c8f; RAUTHY-005 | ct | U45 |\n";
        let mut out = Vec::new();
        advisories(md, &mut out);
        let r = out.first().unwrap();
        assert_eq!(
            (r.id.as_str(), r.aliases.clone()),
            ("GHSA-53hj-r94p-8c8f", vec!["RAUTHY-005".to_owned()])
        );
    }
}
