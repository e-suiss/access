//! `recovery/1/guard.json`: the rollback guard R* and its arms (SEC21, SEC22, §13.6,
//! OP-158 m.3 (b)).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::*;
use crate::vector_rules::{field, golden_in, hex};
use suiss_crypto::dcbor::{self, Limits, Value};

const NOW: u64 = 10_000_000;

#[allow(clippy::unnecessary_wraps, reason = "a declared witness's entry")]
fn head(size: u64, root: u8, age: u64) -> Option<WitnessHead> {
    Some(WitnessHead::new(
        size,
        [root; 32],
        NOW.checked_sub(age).unwrap(),
    ))
}

fn heads_value(heads: &[Option<WitnessHead>]) -> Value {
    Value::Array(
        heads
            .iter()
            .map(|h| match h {
                None => Value::Map(Vec::new()),
                Some(h) => Value::Map(alloc::vec![
                    (Value::text("size"), Value::Unsigned(h.size)),
                    (Value::text("root"), Value::Bytes(h.root.to_vec())),
                    (Value::text("at"), Value::Unsigned(h.at)),
                ]),
            })
            .collect(),
    )
}

fn outcome(r: Result<Guard, GuardError>) -> String {
    match r {
        Ok(Guard::Pass) => String::from("\"guard\": \"pass\""),
        Ok(Guard::Lossy { from, until }) => {
            format!("\"guard\": \"lossy\", \"from\": {from}, \"until\": {until}")
        }
        Err(e) => format!("\"error\": \"{e}\""),
    }
}

type Case = (
    &'static str,
    Vec<Option<WitnessHead>>,
    Option<u64>,
    (u64, u8),
    bool,
);

// SEC21, SEC22, U10, U24, N-14, Ek B 6117, 6132
#[test]
#[allow(clippy::too_many_lines, reason = "one table of cases")]
fn guard_vectors_match() {
    let fresh = 60_000;
    let cases: Vec<Case> = alloc::vec![
        (
            "arm-i-replica-at-the-witness-head-passes",
            alloc::vec![head(100, 1, fresh), head(100, 1, fresh)],
            Some(100),
            (100, 1),
            false,
        ),
        (
            "below-r-star-is-denied",
            alloc::vec![head(100, 1, fresh), head(100, 1, fresh)],
            Some(100),
            (90, 9),
            false,
        ),
        (
            "arm-ii-no-replica-declares-the-lost-suffix",
            alloc::vec![head(100, 1, fresh), head(80, 2, fresh)],
            None,
            (80, 2),
            false,
        ),
        (
            "arm-ii-replica-behind-the-witnesses",
            alloc::vec![head(100, 1, fresh), head(100, 1, fresh)],
            Some(70),
            (70, 7),
            false,
        ),
        (
            "a-witness-without-a-fresh-claim-asks-for-the-threshold",
            alloc::vec![head(100, 1, fresh), head(100, 1, WITNESS_FRESHNESS_MS + 1)],
            Some(100),
            (100, 1),
            false,
        ),
        (
            "a-witness-without-any-claim-asks-for-the-threshold",
            alloc::vec![head(100, 1, fresh), None],
            Some(100),
            (100, 1),
            false,
        ),
        (
            "above-every-witness-is-unwitnessed",
            alloc::vec![head(100, 1, fresh)],
            Some(100),
            (101, 1),
            false,
        ),
        (
            "a-root-no-witness-signed-is-unwitnessed",
            alloc::vec![head(100, 1, fresh)],
            Some(100),
            (100, 2),
            false,
        ),
        (
            "no-fresh-claim-at-all",
            alloc::vec![None, None],
            None,
            (10, 1),
            false
        ),
        (
            "an-undeclared-fork-is-refused",
            alloc::vec![head(100, 1, fresh), head(100, 2, fresh)],
            Some(100),
            (100, 1),
            false,
        ),
        (
            "a-declared-fork-on-the-replica-branch",
            alloc::vec![head(100, 1, fresh), head(100, 2, fresh)],
            Some(100),
            (100, 1),
            true,
        ),
        (
            "a-declared-fork-without-replica-falls-below-the-fork",
            alloc::vec![head(100, 1, fresh), head(100, 2, fresh), head(60, 6, fresh)],
            None,
            (60, 6),
            true,
        ),
        (
            "a-declared-fork-without-replica-at-the-fork-is-refused",
            alloc::vec![head(100, 1, fresh), head(100, 2, fresh)],
            None,
            (100, 1),
            true,
        ),
        (
            "a-fork-declared-where-none-is-shown",
            alloc::vec![head(100, 1, fresh)],
            Some(100),
            (100, 1),
            true,
        ),
    ];
    let mut lines = Vec::new();
    for (id, heads, replica, (n, root), fork) in cases {
        let got = rollback_guard(&heads, replica, (n, [root; 32]), fork, NOW);
        let replica_text = replica.map_or_else(|| String::from("null"), |r| format!("{r}"));
        lines.push(format!(
            "  {{\"id\": \"{id}\", {}, \"heads\": \"{}\", \"replica\": {replica_text}, \"cited\": {n}, \"cited_root\": \"{}\", \"fork\": {fork}, \"now\": {NOW}, {}}}",
            field(&["SEC21", "SEC22"]),
            hex(&dcbor::encode(&heads_value(&heads), Limits::CEILING).unwrap()),
            hex(&[root; 32]),
            outcome(got),
        ));
    }
    let json = format!(
        "{{\n \"rule\": \"OP-158\",\n \"track\": \"recovery\",\n \"version\": 1,\n \"operation\": \"recovery.guard\",\n \"freshness_ms\": {WITNESS_FRESHNESS_MS},\n \"cases\": [\n{}\n ]\n}}\n",
        lines.join(",\n")
    );
    golden_in(
        "recovery/1",
        "guard.json",
        include_str!("../../../../../conformance/vectors/recovery/1/guard.json"),
        &json,
    );
}
