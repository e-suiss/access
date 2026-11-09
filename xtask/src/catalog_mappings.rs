//! `agent-mappings` (AG-26, AG-35, §11.10.4, §11.18): the delegation invariant list and the
//! agent requirement mapping name only tests that exist.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

use super::{DIR, read_toml, violation};
use crate::Violation;

const RULE: &str = "agent-mappings";
const REQUIREMENTS: &str = "agent-requirements.toml";
const DELEGATION: &str = "delegation-invariants.toml";

/// The eight common requirements of AG-35 and the EU AI Act art. 50 row.
const REQUIREMENT_IDS: [&str; 9] = [
    "AG-35-1",
    "AG-35-2",
    "AG-35-3",
    "AG-35-4",
    "AG-35-5",
    "AG-35-6",
    "AG-35-7",
    "AG-35-8",
    "EU-AI-ACT-50",
];

const CLASSES: [&str; 2] = ["BS", "UDC"];

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Requirements {
    #[serde(default)]
    requirement: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Requirement {
    id: String,
    #[serde(rename = "requirement")]
    text: String,
    mechanism: String,
    classes: Vec<String>,
    guarantees: Vec<String>,
    #[serde(default)]
    rules: Vec<String>,
    tests: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Delegation {
    #[serde(default)]
    invariant: Vec<Invariant>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Invariant {
    number: u8,
    #[serde(rename = "invariant")]
    statement: String,
    access: String,
    rules: Vec<String>,
    tests: Vec<String>,
}

/// Whether `source` defines a function `name`.
fn defines(source: &str, name: &str) -> bool {
    source
        .split(&format!("fn {name}"))
        .skip(1)
        .any(|rest| rest.starts_with(['(', '<']))
}

/// `<file>::<fn>` entries whose file or function is missing, given a file reader.
fn missing_tests(
    file: &str,
    row: &str,
    tests: &[String],
    read: &dyn Fn(&str) -> Option<String>,
) -> Vec<Violation> {
    let mut out = Vec::new();
    if tests.is_empty() {
        out.push(violation(RULE, file, format!("{row} names no test")));
    }
    for t in tests {
        let Some((path, name)) = t.rsplit_once("::") else {
            out.push(violation(
                RULE,
                file,
                format!("{row}: `{t}` is not <file>::<fn>"),
            ));
            continue;
        };
        match read(path) {
            None => out.push(violation(RULE, file, format!("{row}: no file {path}"))),
            Some(src) if !defines(&src, name) => out.push(violation(
                RULE,
                file,
                format!("{row}: {path} has no fn {name}"),
            )),
            Some(_) => {}
        }
    }
    out
}

pub(crate) fn requirement_violations(
    r: &Requirements,
    read: &dyn Fn(&str) -> Option<String>,
) -> Vec<Violation> {
    let mut out = Vec::new();
    let ids: Vec<&str> = r.requirement.iter().map(|q| q.id.as_str()).collect();
    if ids != REQUIREMENT_IDS {
        out.push(violation(
            RULE,
            REQUIREMENTS,
            format!("rows must be exactly {REQUIREMENT_IDS:?} in order, found {ids:?}"),
        ));
    }
    for q in &r.requirement {
        if q.text.is_empty() || q.mechanism.is_empty() {
            out.push(violation(
                RULE,
                REQUIREMENTS,
                format!("{} is incomplete", q.id),
            ));
        }
        if let Some(c) = q.classes.iter().find(|c| !CLASSES.contains(&c.as_str())) {
            out.push(violation(
                RULE,
                REQUIREMENTS,
                format!("{}: unknown guarantee class {c}", q.id),
            ));
        }
        if q.guarantees.iter().chain(&q.rules).any(String::is_empty) {
            out.push(violation(
                RULE,
                REQUIREMENTS,
                format!("{}: empty reference", q.id),
            ));
        }
        out.extend(missing_tests(REQUIREMENTS, &q.id, &q.tests, read));
    }
    out
}

pub(crate) fn delegation_violations(
    d: &Delegation,
    read: &dyn Fn(&str) -> Option<String>,
) -> Vec<Violation> {
    let mut out = Vec::new();
    let numbers: Vec<u8> = d.invariant.iter().map(|i| i.number).collect();
    if numbers != [1, 2, 3, 4, 5, 6] {
        out.push(violation(
            RULE,
            DELEGATION,
            format!("the six invariants must be numbered 1 to 6 in order, found {numbers:?}"),
        ));
    }
    for i in &d.invariant {
        let row = format!("invariant {}", i.number);
        if i.statement.is_empty() || i.access.is_empty() || i.rules.is_empty() {
            out.push(violation(RULE, DELEGATION, format!("{row} is incomplete")));
        }
        let distinct: BTreeSet<&String> = i.rules.iter().collect();
        if distinct.len() != i.rules.len() {
            out.push(violation(RULE, DELEGATION, format!("{row}: a rule twice")));
        }
        out.extend(missing_tests(DELEGATION, &row, &i.tests, read));
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let dir = root.join(DIR);
    let requirements: Requirements = read_toml(&dir.join(REQUIREMENTS))?;
    let delegation: Delegation = read_toml(&dir.join(DELEGATION))?;
    let read = |p: &str| std::fs::read_to_string(root.join(p)).ok();
    let mut out = requirement_violations(&requirements, &read);
    out.extend(delegation_violations(&delegation, &read));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(path: &str) -> Option<String> {
        (path == "a.rs").then(|| String::from("#[test]\nfn proves_it() {}\nfn other_one() {}\n"))
    }

    fn requirements(tests: &[&str]) -> Requirements {
        Requirements {
            requirement: REQUIREMENT_IDS
                .iter()
                .map(|id| Requirement {
                    id: (*id).to_owned(),
                    text: String::from("r"),
                    mechanism: String::from("m"),
                    classes: vec![String::from("BS")],
                    guarantees: Vec::new(),
                    rules: Vec::new(),
                    tests: tests.iter().map(|t| (*t).to_owned()).collect(),
                })
                .collect(),
        }
    }

    // AG-35, §11.18
    #[test]
    fn every_requirement_names_a_test_that_exists() {
        assert!(requirement_violations(&requirements(&["a.rs::proves_it"]), &reader).is_empty());
        assert_eq!(
            requirement_violations(&requirements(&["a.rs::proves"]), &reader).len(),
            9
        );
        assert_eq!(
            requirement_violations(&requirements(&["b.rs::proves_it"]), &reader).len(),
            9
        );
        assert_eq!(requirement_violations(&requirements(&[]), &reader).len(), 9);
        let mut short = requirements(&["a.rs::proves_it"]);
        short.requirement.pop();
        assert_eq!(requirement_violations(&short, &reader).len(), 1);
        let mut class = requirements(&["a.rs::proves_it"]);
        class.requirement[0].classes = vec![String::from("NG")];
        assert_eq!(requirement_violations(&class, &reader).len(), 1);
    }

    // AG-26, §11.10.4
    #[test]
    fn the_six_delegation_invariants_each_name_a_test() {
        let row = |number| Invariant {
            number,
            statement: String::from("i"),
            access: String::from("a"),
            rules: vec![String::from("INV-3")],
            tests: vec![String::from("a.rs::other_one")],
        };
        let all = Delegation {
            invariant: (1..=6).map(row).collect(),
        };
        assert!(delegation_violations(&all, &reader).is_empty());
        let five = Delegation {
            invariant: (1..=5).map(row).collect(),
        };
        assert_eq!(delegation_violations(&five, &reader).len(), 1);
    }
}
