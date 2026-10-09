//! Rule ID recognition shared by the spec parser and the test scanner (OP-81).

/// Families with a `PREFIX-<digits>` shape.
const DASHED: &[&str] = &[
    "CI", "INV", "EI", "XI", "PI", "SI", "TI", "SAI", "IDI", "AGI", "TNI", "OPI", "N", "HL", "DL",
    "RR", "TH", "AB",
];

/// Families with a `PREFIX<digits>` shape.
const UNDASHED: &[&str] = &["G", "U", "SEC"];

/// Decision register families. They enter the catalog only when a test cites them.
const DECISIONS: &[&str] = &["SA", "CR", "R", "OP", "MD", "F", "IDP", "AG", "TN"];

/// Families written with a fixed multi-part prefix, checked before the generic shapes.
const COMPOUND: &[(&str, &str)] = &[
    ("TI-RT", "TI-RT"),
    ("OP-54-RL", "OP-54-RL"),
    ("OP-3-G", "OP-3-G"),
    ("MUST-NEVER-", "MUST-NEVER"),
];

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_advisory(id: &str) -> bool {
    let parts: Vec<&str> = id.split('-').collect();
    match parts.as_slice() {
        ["GHSA", a, b, c] => [a, b, c]
            .iter()
            .all(|p| p.len() == 4 && p.bytes().all(|b| b.is_ascii_alphanumeric())),
        ["CVE" | "RUSTSEC", year, num] => year.len() == 4 && all_digits(year) && all_digits(num),
        ["RAUTHY", num] => all_digits(num),
        _ => false,
    }
}

/// The catalog family of `id`, or `None` when it is not a rule or decision ID.
pub(crate) fn family(id: &str) -> Option<&'static str> {
    for (prefix, name) in COMPOUND {
        if let Some(rest) = id.strip_prefix(prefix) {
            return all_digits(rest).then_some(*name);
        }
    }
    if is_advisory(id) {
        return Some("ADVISORY");
    }
    if let Some((prefix, rest)) = id.split_once('-') {
        if all_digits(rest) {
            return DASHED
                .iter()
                .chain(DECISIONS)
                .find(|f| **f == prefix)
                .copied();
        }
        return None;
    }
    let split = id.find(|c: char| c.is_ascii_digit())?;
    let (prefix, rest) = id.split_at(split);
    if all_digits(rest) {
        return UNDASHED.iter().find(|f| **f == prefix).copied();
    }
    None
}

/// Whether `family` is a decision register family (SA, CR, OP, ...).
pub(crate) fn is_decision_family(family: &str) -> bool {
    DECISIONS.contains(&family)
}

/// One ID-shaped token with its byte span in the source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    pub(crate) text: String,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

/// Every ID in `text`, in order, including `must-never #N` lists (`must-never #1, #3`).
pub(crate) fn ids_in(text: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'-';
        if !bytes.get(i).copied().is_some_and(is_word) {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        while bytes.get(i).copied().is_some_and(is_word) {
            i = i.saturating_add(1);
        }
        let raw = text.get(start..i).unwrap_or_default();
        let trimmed = raw.trim_matches('-');
        let offset = raw.len().saturating_sub(raw.trim_start_matches('-').len());
        let tstart = start.saturating_add(offset);
        let tend = tstart.saturating_add(trimmed.len());
        if trimmed.eq_ignore_ascii_case("must-never") {
            let (numbers, end) = must_never_numbers(text, i);
            for n in numbers {
                out.push(Token {
                    text: format!("MUST-NEVER-{n}"),
                    start: tstart,
                    end,
                });
            }
            i = end.max(i);
            continue;
        }
        if family(trimmed).is_some() {
            out.push(Token {
                text: trimmed.to_owned(),
                start: tstart,
                end: tend,
            });
        }
    }
    out
}

/// Parses `#1, #3 ve #5` after "must-never"; returns the numbers and the end offset.
fn must_never_numbers(text: &str, mut i: usize) -> (Vec<String>, usize) {
    let bytes = text.as_bytes();
    let mut numbers = Vec::new();
    loop {
        let mut j = i;
        while bytes.get(j).is_some_and(|b| *b == b' ' || *b == b',') {
            j = j.saturating_add(1);
        }
        if bytes.get(j) != Some(&b'#') {
            break;
        }
        j = j.saturating_add(1);
        let digits_start = j;
        while bytes.get(j).is_some_and(u8::is_ascii_digit) {
            j = j.saturating_add(1);
        }
        if j == digits_start {
            break;
        }
        numbers.push(text.get(digits_start..j).unwrap_or_default().to_owned());
        i = j;
    }
    (numbers, i)
}

/// IDs in `text` that are not the endpoint of a range such as `G1–G3` or `N-1…N-59`.
pub(crate) fn ids_outside_ranges(text: &str) -> Vec<String> {
    let tokens = ids_in(text);
    let mut skip = vec![false; tokens.len()];
    for (k, pair) in tokens.windows(2).enumerate() {
        let [a, b] = pair else { continue };
        let between = text.get(a.end..b.start).unwrap_or_default().trim();
        if matches!(between, "…" | "–" | "..." | "-" | "—") {
            if let Some(s) = skip.get_mut(k) {
                *s = true;
            }
            if let Some(s) = skip.get_mut(k.saturating_add(1)) {
                *s = true;
            }
        }
    }
    tokens
        .into_iter()
        .zip(skip)
        .filter(|(_, s)| !s)
        .map(|(t, _)| t.text)
        .collect()
}

/// Expands a range `G1–G3` into its members when both ends share a family.
pub(crate) fn expand_range(from: &str, to: &str) -> Vec<String> {
    let split = |id: &str| -> Option<(String, u32)> {
        let pos = id.rfind(|c: char| !c.is_ascii_digit())?.saturating_add(1);
        let (prefix, digits) = id.split_at(pos);
        Some((prefix.to_owned(), digits.parse().ok()?))
    };
    match (split(from), split(to)) {
        (Some((pa, a)), Some((pb, b))) if pa == pb && a <= b && b.saturating_sub(a) < 100 => {
            (a..=b).map(|n| format!("{pa}{n}")).collect()
        }
        _ => vec![from.to_owned(), to.to_owned()],
    }
}

/// The snake-case form used in test function names: `TI-RT1` → `ti_rt1`.
pub(crate) fn snake(id: &str) -> String {
    id.to_ascii_lowercase().replace('-', "_")
}

/// Whether a test function name cites `id` as a whole `_`-separated segment run.
pub(crate) fn name_cites(name: &str, id_snake: &str) -> bool {
    name == id_snake
        || name.starts_with(&format!("{id_snake}_"))
        || name.ends_with(&format!("_{id_snake}"))
        || name.contains(&format!("_{id_snake}_"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_are_recognised() {
        assert_eq!(family("INV-2"), Some("INV"));
        assert_eq!(family("TI-RT12"), Some("TI-RT"));
        assert_eq!(family("G38"), Some("G"));
        assert_eq!(family("N-41"), Some("N"));
        assert_eq!(family("SEC17"), Some("SEC"));
        assert_eq!(family("SA-26"), Some("SA"));
        assert_eq!(family("RAUTHY-008"), Some("ADVISORY"));
        assert_eq!(family("GHSA-j4gj-f54h-56j5"), Some("ADVISORY"));
        assert_eq!(family("MUST-NEVER-19"), Some("MUST-NEVER"));
        assert_eq!(family("OP-54-RL3"), Some("OP-54-RL"));
    }

    #[test]
    fn non_ids_are_rejected() {
        for word in [
            "INV",
            "G",
            "X-L1",
            "TN-H",
            "OP-S1",
            "GHSA-j4gj",
            "UTF-8",
            "sha256",
        ] {
            assert_eq!(family(word), None, "{word}");
        }
    }

    #[test]
    fn ids_are_found_in_comment_text() {
        let found: Vec<String> = ids_in("SA-21 / R-3: panics; §14.3 RAUTHY-008.")
            .into_iter()
            .map(|t| t.text)
            .collect();
        assert_eq!(found, ["SA-21", "R-3", "RAUTHY-008"]);
    }

    #[test]
    fn must_never_lists_are_normalised() {
        let found: Vec<String> = ids_in("must-never #1, #3; and must-never #12")
            .into_iter()
            .map(|t| t.text)
            .collect();
        assert_eq!(found, ["MUST-NEVER-1", "MUST-NEVER-3", "MUST-NEVER-12"]);
    }

    #[test]
    fn range_endpoints_are_not_citations() {
        assert_eq!(ids_outside_ranges("N-1…N-59 and N-41, G1–G3"), ["N-41"]);
    }

    #[test]
    fn ranges_expand_within_one_family() {
        assert_eq!(expand_range("G1", "G3"), ["G1", "G2", "G3"]);
        assert_eq!(expand_range("G1", "U3"), ["G1", "U3"]);
    }

    #[test]
    fn test_names_cite_ids_by_whole_segments() {
        assert!(name_cites("inv_2_single_write_path", "inv_2"));
        assert!(name_cites("catalog_g38_spec_wins", "g38"));
        assert!(!name_cites("inv_21_consumption", "inv_2"));
        assert!(!name_cites("sign_in", "n"));
    }
}
