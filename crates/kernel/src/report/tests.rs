#![allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "test fixtures"
)]

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{Limits, Value};

use super::*;
use crate::vector_rules::{field, golden, hex};

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

fn entry(n: u8, outcome: LocalOutcome, drawn: u64) -> Entry {
    Entry {
        intent: d(n),
        params: None,
        time: 1_000 + u64::from(n) * 100,
        clock_evidence: Some(d(n + 1)),
        outcome,
        drawn: (drawn > 0)
            .then_some(SliceAmount {
                budget_term: d(90),
                amount: drawn,
            })
            .into_iter()
            .collect(),
        holder_proof: Some(d(n + 2)),
    }
}

fn sealed(mut r: Report) -> Report {
    let mut head = match r.previous {
        Some(p) => p,
        None => seed(&r.exercise, &r.contract).unwrap(),
    };
    for (i, e) in r.entries.iter().enumerate() {
        head = link(&head, r.first_seq + i as u64, e).unwrap();
    }
    r.head = head;
    r
}

fn first() -> Report {
    sealed(Report {
        verifier_profile: d(20),
        verifier_instance: Some(Id([5; 16])),
        exercise: d(21),
        contract: d(22),
        period: Window {
            from: 1_000,
            until: 9_000,
        },
        previous: None,
        first_seq: 0,
        entries: vec![
            entry(10, LocalOutcome::Allow, 3),
            entry(20, LocalOutcome::Deny, 0),
            entry(30, LocalOutcome::Allow, 2),
        ],
        head: d(0),
        slice_unused: [SliceAmount {
            budget_term: d(90),
            amount: 5,
        }]
        .into_iter()
        .collect(),
        profile_version: 1,
    })
}

fn second() -> Report {
    let head = verify(&first()).unwrap().head;
    sealed(Report {
        previous: Some(head),
        first_seq: 3,
        period: Window {
            from: 9_000,
            until: 20_000,
        },
        entries: vec![Entry {
            time: 9_500,
            ..entry(40, LocalOutcome::Allow, 1)
        }],
        ..first()
    })
}

fn cases() -> Vec<(&'static str, &'static [&'static str], Vec<u8>)> {
    let bytes = |r: &Report| r.to_bytes().unwrap();
    let empty = sealed(Report {
        entries: Vec::new(),
        slice_unused: BTreeSet::new(),
        ..first()
    });
    let mut reordered = first();
    reordered.entries.swap(0, 2);
    let mut hidden = first();
    hidden.entries.remove(1);
    let late = sealed(Report {
        entries: vec![Entry {
            time: 9_001,
            ..entry(10, LocalOutcome::Allow, 3)
        }],
        ..first()
    });
    let deny_draws = sealed(Report {
        entries: vec![entry(10, LocalOutcome::Deny, 3)],
        ..first()
    });
    let previous_at_zero = sealed(Report {
        previous: Some(d(77)),
        ..first()
    });
    let no_previous = sealed(Report {
        first_seq: 3,
        ..first()
    });
    let mut unknown = first().to_value();
    if let Value::Map(m) = &mut unknown {
        m.push((Value::text("remaining"), Value::Unsigned(1)));
    }
    let overflow = sealed(Report {
        entries: vec![
            entry(10, LocalOutcome::Allow, u64::MAX),
            entry(20, LocalOutcome::Allow, 1),
        ],
        ..first()
    });
    vec![
        (
            "first-report",
            &["L2-RPT-1", "L2-RPT-2", "L2-RPT-3"],
            bytes(&first()),
        ),
        ("continuation", &["L2-RPT-2", "L2-RPT-3"], bytes(&second())),
        ("no-entries", &["L2-RPT-2"], bytes(&empty)),
        (
            "reordered-entries",
            &["L2-RPT-2", "L2-RPT-3"],
            bytes(&reordered),
        ),
        ("hidden-entry", &["L2-RPT-2", "L2-RPT-3"], bytes(&hidden)),
        ("entry-after-period", &["L2-RPT-3"], bytes(&late)),
        ("deny-draws", &["L2-RPT-3"], bytes(&deny_draws)),
        ("previous-at-zero", &["L2-RPT-3"], bytes(&previous_at_zero)),
        (
            "continuation-without-previous",
            &["L2-RPT-3"],
            bytes(&no_previous),
        ),
        ("draw-overflow", &["L2-RPT-3"], bytes(&overflow)),
        (
            "unknown-field",
            &["L2-RPT-1"],
            dcbor::encode(&unknown, Limits::CEILING).unwrap(),
        ),
    ]
}

fn result(bytes: &[u8]) -> Result<Summary, &'static str> {
    verify_bytes(bytes)
        .map(|(_, s)| s)
        .map_err(ReportError::code)
}

// L2-RPT-2, L2-RPT-3, §9.12.2
#[test]
fn reports_verify_or_name_their_failure() {
    let got: Vec<(&str, Result<Summary, &str>)> =
        cases().iter().map(|(id, _, b)| (*id, result(b))).collect();
    let s = got[0].1.clone().unwrap();
    assert_eq!(s.next_seq, 3);
    assert_eq!(s.drawn.get(&d(90)), Some(&5));
    assert_eq!(got[1].1.clone().unwrap().next_seq, 4);
    assert!(got[2].1.is_ok());
    let errors: Vec<&str> = got[3..]
        .iter()
        .map(|(_, r)| r.clone().unwrap_err())
        .collect();
    assert_eq!(
        errors,
        [
            "report-chain",
            "report-chain",
            "report-period",
            "report-entry",
            "report-start",
            "report-start",
            "report-entry",
            "report-malformed",
        ]
    );
}

// L2-RPT-2
#[test]
fn a_report_continues_only_the_last_head() {
    let s = verify(&first()).unwrap();
    assert!(continues(&s, &second()));
    let skipped = sealed(Report {
        first_seq: 4,
        ..second()
    });
    assert!(!continues(&s, &skipped));
    let forked = sealed(Report {
        previous: Some(d(66)),
        ..second()
    });
    assert!(!continues(&s, &forked));
}

// L2-RPT-3
#[test]
fn entries_at_the_period_ends_lie_in_the_period() {
    let at = |times: &[u64]| {
        verify(&sealed(Report {
            entries: times
                .iter()
                .map(|&time| Entry {
                    time,
                    ..entry(10, LocalOutcome::Allow, 1)
                })
                .collect(),
            ..first()
        }))
        .map(|s| s.next_seq)
    };
    assert_eq!(at(&[1_000, 9_000]), Ok(2));
    assert_eq!(at(&[1_000]), Ok(1));
    assert_eq!(at(&[9_000]), Ok(1));
    assert_eq!(at(&[999]), Err(ReportError::Period));
    assert_eq!(at(&[9_001]), Err(ReportError::Period));
}

// L2-RPT-1 to L2-RPT-3
#[test]
fn report_vectors_match() {
    let rows: Vec<String> = cases()
        .iter()
        .map(|(id, rules, bytes)| {
            let out = match result(bytes) {
                Ok(s) => {
                    let drawn: Vec<String> = s
                        .drawn
                        .iter()
                        .map(|(t, n)| format!("[\"{}\", {n}]", hex(&t.0)))
                        .collect();
                    format!(
                        "\"head\": \"{}\", \"next_seq\": {}, \"drawn\": [{}]",
                        hex(&s.head.0),
                        s.next_seq,
                        drawn.join(", ")
                    )
                }
                Err(e) => format!("\"error\": \"{e}\""),
            };
            format!(
                "  {{\"id\": \"{id}\", {}, \"report\": \"{}\", {out}}}",
                field(rules),
                hex(bytes)
            )
        })
        .collect();
    let json = format!(
        "{{\n \"rule\": \"L2-RPT-3\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"report.verify\",\n \"cases\": [\n{}\n ]\n}}\n",
        rows.join(",\n")
    );
    golden(
        "report.json",
        include_str!("../../../../conformance/vectors/core/1/report.json"),
        &json,
    );
}
