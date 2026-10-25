//! `algebra.json`: `∩` of resource selectors, subject selectors and authority sets
//! (L0-ALG-42, L0-ALG-46, L0-ALG-51, OP-126 m.2).

use alloc::format;
use alloc::vec::Vec;

use super::*;
use crate::codec::Canonical as _;

use crate::vector_rules::hex;

fn exact(path: &[&str]) -> ResourceSelector {
    ResourceSelector::Exact(rref("shop", path))
}

fn party(n: u8) -> SubjectSelector {
    SubjectSelector::Party(Id([n; 16]))
}

fn pred(classes: &[&str]) -> SubjectSelector {
    SubjectSelector::Pred(
        classes
            .iter()
            .map(|c| Conjunct {
                claim_class: s(c),
                value: None,
            })
            .collect(),
    )
}

fn resource_cases() -> Vec<(&'static str, ResourceSelector, ResourceSelector)> {
    let any = || structural("shop", &[], None, &[]);
    alloc::vec![
        ("resource-exact-equal", exact(&["o1"]), exact(&["o1"])),
        ("resource-exact-different", exact(&["o1"]), exact(&["o2"])),
        (
            "resource-exact-within-structural",
            exact(&["a", "o1"]),
            structural("shop", &["a"], None, &[])
        ),
        (
            "resource-exact-outside-structural",
            exact(&["b", "o1"]),
            structural("shop", &["a"], None, &[])
        ),
        (
            "resource-longer-prefix",
            any(),
            structural("shop", &["a", "b"], None, &[])
        ),
        (
            "resource-namespace-differs",
            any(),
            structural("shop2", &[], None, &[])
        ),
        (
            "resource-prefixes-disjoint",
            structural("shop", &["a"], None, &[]),
            structural("shop", &["b"], None, &[])
        ),
        (
            "resource-type-and-where-merge",
            structural("shop", &[], Some("order"), &[]),
            structural("shop", &[], None, &[("k", 1)])
        ),
        (
            "resource-types-differ",
            structural("shop", &[], Some("order"), &[]),
            structural("shop", &[], Some("refund"), &[])
        ),
        (
            "resource-where-conflict",
            structural("shop", &[], None, &[("k", 1)]),
            structural("shop", &[], None, &[("k", 2)])
        ),
    ]
}

fn subject_cases() -> Vec<(&'static str, SubjectSelector, SubjectSelector)> {
    let foreign = || SubjectSelector::Foreign {
        domain: d(30),
        class: s("auditor"),
    };
    alloc::vec![
        ("subject-party-same", party(1), party(1)),
        ("subject-party-different", party(1), party(2)),
        (
            "subject-public-and-party",
            SubjectSelector::Public,
            party(1)
        ),
        ("subject-pred-union", pred(&["a"]), pred(&["b"])),
        ("subject-pred-subsumed", pred(&["a", "b"]), pred(&["a"])),
        ("subject-party-and-pred", party(1), pred(&["a"])),
        ("subject-foreign-equal", foreign(), foreign()),
    ]
}

fn authority_cases() -> Vec<(&'static str, AuthoritySet, AuthoritySet)> {
    let refund = action("pay", "refund");
    let capture = action("pay", "capture");
    let with = |a: AuthoritySet, b: Bound| {
        let mut a = a;
        a.params.insert(s("p"), b);
        a
    };
    let enumb = |xs: &[&str]| Bound::Enum(xs.iter().map(|x| s(x)).collect());
    let mut recipient = set(core::slice::from_ref(&refund));
    recipient.recipient = Some(party(5));
    let mut narrow = set(core::slice::from_ref(&refund));
    narrow.resource = structural("shop", &["a"], None, &[]);
    let mut other = set(core::slice::from_ref(&refund));
    other.resource = structural("shop2", &[], None, &[]);
    alloc::vec![
        (
            "authority-common-actions",
            set(&[refund.clone(), capture.clone()]),
            set(core::slice::from_ref(&refund))
        ),
        (
            "authority-disjoint-actions",
            set(&[capture]),
            set(core::slice::from_ref(&refund))
        ),
        (
            "authority-param-one-side-kept",
            with(set(core::slice::from_ref(&refund)), enumb(&["a"])),
            set(core::slice::from_ref(&refund))
        ),
        (
            "authority-param-enum-meet",
            with(set(core::slice::from_ref(&refund)), enumb(&["a", "b"])),
            with(set(core::slice::from_ref(&refund)), enumb(&["b", "c"]))
        ),
        (
            "authority-param-bottom",
            with(set(core::slice::from_ref(&refund)), enumb(&["a"])),
            with(set(core::slice::from_ref(&refund)), enumb(&["b"]))
        ),
        (
            "authority-range-meet",
            with(
                set(core::slice::from_ref(&refund)),
                range(Some(0), Some(100), "eur")
            ),
            with(
                set(core::slice::from_ref(&refund)),
                range(Some(50), None, "eur")
            )
        ),
        (
            "authority-range-units-differ",
            with(
                set(core::slice::from_ref(&refund)),
                range(Some(0), Some(100), "eur")
            ),
            with(
                set(core::slice::from_ref(&refund)),
                range(Some(0), Some(100), "usd")
            )
        ),
        (
            "authority-recipient-one-side-kept",
            recipient,
            set(core::slice::from_ref(&refund))
        ),
        (
            "authority-resource-narrowed",
            narrow,
            set(core::slice::from_ref(&refund))
        ),
        ("authority-resource-bottom", other, set(&[refund])),
    ]
}

fn rules(id: &str) -> &'static [&'static str] {
    if id.starts_with("resource-") {
        &["L0-ALG-42"]
    } else if id.starts_with("subject-") {
        &["L0-ALG-46"]
    } else if id.contains("bottom") || id.contains("disjoint") || id.contains("differ") {
        &["L0-ALG-1", "L0-ALG-51", "L0-ALG-52"]
    } else {
        &["L0-ALG-51", "L0-ALG-52"]
    }
}

fn line(id: &str, kind: &str, a: &[u8], b: &[u8], meet: Option<Vec<u8>>) -> String {
    let expect = meet.map_or_else(
        || String::from("\"bottom\": true"),
        |m| format!("\"meet\": \"{}\"", hex(&m)),
    );
    format!(
        "  {{\"id\": \"{id}\", {}, \"kind\": \"{kind}\", \"a\": \"{}\", \"b\": \"{}\", {expect}}}",
        crate::vector_rules::field(rules(id)),
        hex(a),
        hex(b)
    )
}

// L0-ALG-42, L0-ALG-46, L0-ALG-51, OP-126 m.2
#[test]
fn meet_vectors_match() {
    let cat = Catalog::default();
    let mut lines = Vec::new();
    for (id, a, b) in resource_cases() {
        let m = resource_meet(&a, &b).map(|m| m.to_bytes().unwrap());
        lines.push(line(
            id,
            "resource",
            &a.to_bytes().unwrap(),
            &b.to_bytes().unwrap(),
            m,
        ));
    }
    for (id, a, b) in subject_cases() {
        let m = subject_meet(&a, &b).map(|m| m.to_bytes().unwrap());
        lines.push(line(
            id,
            "subject",
            &a.to_bytes().unwrap(),
            &b.to_bytes().unwrap(),
            m,
        ));
    }
    for (id, a, b) in authority_cases() {
        let m = meet(&a, &b, &cat).map(|m| m.to_bytes().unwrap());
        lines.push(line(
            id,
            "authority",
            &a.to_bytes().unwrap(),
            &b.to_bytes().unwrap(),
            m,
        ));
    }
    let json = format!(
        "{{\n \"rule\": \"OP-126\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"algebra.meet\",\n \"catalog\": \"a0\",\n \"cases\": [\n{}\n ]\n}}\n",
        lines.join(",\n")
    );
    crate::vector_rules::golden(
        "algebra.json",
        include_str!("../../../../../conformance/vectors/core/1/algebra.json"),
        &json,
    );
}
